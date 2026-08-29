use crate::root_protocol::ActorRoleV1;
use crate::root_protocol::AuthorizedRootCommandV1;
use crate::root_sqlite::RootSqlite;
use crate::root_sqlite::SqlValue;
use std::fs::File;
use std::fs::OpenOptions;
use std::io::ErrorKind;
use std::os::fd::AsRawFd;
use std::os::unix::fs::MetadataExt;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use std::path::PathBuf;

const ROOT_STORE_SCHEMA_VERSION: i64 = crate::root_sqlite::ROOT_STORE_SCHEMA_VERSION;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum RootStoreError {
    InvalidRoot(String),
    AlreadyOpen,
    Sqlite(String),
    Integrity(String),
    ActorStale,
    MethodMismatch,
    RevisionMismatch,
    Quiescing,
    ActiveOperations,
    InvalidTransition,
    /// COMMIT failed after the in-transaction body succeeded; the outcome is
    /// uncertain. The caller must resolve it by replaying the same idempotent
    /// operation, never by assuming either outcome.
    CommitFailed(String),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ActorAuthorityV1 {
    pub(crate) role: ActorRoleV1,
    pub(crate) component_tuple_digest: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct RootStoreBootstrapV1 {
    pub(crate) release_sequence: u64,
    pub(crate) lease_epoch: u64,
    pub(crate) actors: Vec<ActorAuthorityV1>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct RootReleaseStateV1 {
    pub(crate) release_sequence: u64,
    pub(crate) lease_epoch: u64,
    pub(crate) revision: u64,
    pub(crate) lifecycle: String,
}

pub(crate) struct RootStore {
    pub(crate) db: RootSqlite,
    _lock: File,
    _root: File,
    path: PathBuf,
}

impl RootStore {
    pub(crate) fn open(
        root: &Path,
        bootstrap: &RootStoreBootstrapV1,
    ) -> Result<Self, RootStoreError> {
        let root_file = open_private_root(root)?;
        let lock = open_named_lock(root, "guard.lock")?;
        let path = root.join("launch-guard.db");
        let created = create_or_validate_private_file(&path)?;
        let db = RootSqlite::open(&path, created)?;
        verify_private_file(&path)?;
        verify_root_identity(root, &root_file)?;
        db.configure()?;
        validate_bootstrap(bootstrap)?;
        if created {
            initialize_new_store(&db, bootstrap)?;
        } else {
            validate_existing_store(&db)?;
        }
        db.integrity_check()?;
        db.recover_uncertain_effects()?;
        Ok(Self {
            db,
            _lock: lock,
            _root: root_file,
            path,
        })
    }

    pub(crate) fn path(&self) -> &Path {
        &self.path
    }

    pub(crate) fn release_state(&self) -> Result<RootReleaseStateV1, RootStoreError> {
        let (release_sequence, lease_epoch, revision, lifecycle) = self.db.release_state_tuple()?;
        Ok(RootReleaseStateV1 {
            release_sequence: to_u64(release_sequence)?,
            lease_epoch: to_u64(lease_epoch)?,
            revision: to_u64(revision)?,
            lifecycle,
        })
    }

    #[cfg(test)]
    pub(crate) fn operation_count(&self) -> Result<u64, RootStoreError> {
        to_u64(
            self.db
                .query_i64("SELECT COUNT(*) FROM broker_operations", &[])?,
        )
    }

    #[cfg(test)]
    pub(crate) fn is_release_revoked(&self, release_sequence: u64) -> Result<bool, RootStoreError> {
        Ok(self.db.query_i64(
            "SELECT COUNT(*) FROM release_revocations WHERE release_sequence=?",
            &[SqlValue::Integer(to_i64(release_sequence)?)],
        )? == 1)
    }

    pub(crate) fn begin_quiesce(
        &mut self,
        expected_release_sequence: u64,
        expected_revision: u64,
    ) -> Result<u64, RootStoreError> {
        self.transaction(|store| {
            let changed = store.db.execute(
                "UPDATE guard_metadata SET lifecycle='quiescing', revision=revision+1 WHERE singleton=1 AND lifecycle='active' AND release_sequence=? AND revision=?",
                &[
                    SqlValue::Integer(to_i64(expected_release_sequence)?),
                    SqlValue::Integer(to_i64(expected_revision)?),
                ],
            )?;
            if changed != 1 {
                return Err(RootStoreError::RevisionMismatch);
            }
            Ok(expected_revision + 1)
        })
    }

    pub(crate) fn activate_release(
        &mut self,
        expected_release_sequence: u64,
        expected_revision: u64,
        next: &RootStoreBootstrapV1,
    ) -> Result<u64, RootStoreError> {
        validate_bootstrap(next)?;
        self.transaction(|store| {
            let state = store.release_state()?;
            if state.release_sequence != expected_release_sequence
                || state.revision != expected_revision
                || state.lifecycle != "quiescing"
            {
                return Err(RootStoreError::RevisionMismatch);
            }
            let active = store.db.query_i64(
                "SELECT COUNT(*) FROM broker_operations WHERE release_sequence=? AND state NOT IN ('cancelled-no-effect','settled-safe')",
                &[SqlValue::Integer(to_i64(expected_release_sequence)?)],
            )?;
            if active != 0 {
                return Err(RootStoreError::ActiveOperations);
            }
            let expected_next_release = state
                .release_sequence
                .checked_add(1)
                .ok_or(RootStoreError::InvalidTransition)?;
            let expected_next_epoch = state
                .lease_epoch
                .checked_add(1)
                .ok_or(RootStoreError::InvalidTransition)?;
            let next_revision = state
                .revision
                .checked_add(1)
                .ok_or(RootStoreError::InvalidTransition)?;
            if next.release_sequence != expected_next_release
                || next.lease_epoch != expected_next_epoch
            {
                return Err(RootStoreError::InvalidTransition);
            }
            store.db.execute(
                "INSERT INTO release_epochs(release_sequence,lease_epoch) VALUES(?,?)",
                &[
                    SqlValue::Integer(to_i64(next.release_sequence)?),
                    SqlValue::Integer(to_i64(next.lease_epoch)?),
                ],
            )?;
            store.db.execute(
                "INSERT INTO release_revocations(release_sequence, revoked_at_revision) VALUES(?,?)",
                &[
                    SqlValue::Integer(to_i64(expected_release_sequence)?),
                    SqlValue::Integer(to_i64(next_revision)?),
                ],
            )?;
            let changed = store.db.execute(
                "UPDATE guard_metadata SET release_sequence=?, lease_epoch=?, lifecycle='active', revision=revision+1 WHERE singleton=1 AND lifecycle='quiescing' AND release_sequence=? AND revision=?",
                &[
                    SqlValue::Integer(to_i64(next.release_sequence)?),
                    SqlValue::Integer(to_i64(next.lease_epoch)?),
                    SqlValue::Integer(to_i64(expected_release_sequence)?),
                    SqlValue::Integer(to_i64(expected_revision)?),
                ],
            )?;
            if changed != 1 {
                return Err(RootStoreError::RevisionMismatch);
            }
            store.db.exec("DELETE FROM actor_authorities")?;
            insert_actor_authorities(&store.db, next)?;
            Ok(next_revision)
        })
    }

    pub(crate) fn revalidate_actor(
        &self,
        authorized: &AuthorizedRootCommandV1,
        state: &RootReleaseStateV1,
    ) -> Result<(), RootStoreError> {
        let actor = authorized.actor();
        if actor.release_sequence() != state.release_sequence
            || actor.lease_epoch() != state.lease_epoch
        {
            return Err(RootStoreError::ActorStale);
        }
        let tuple = self.db.query_text(
            "SELECT component_tuple_digest FROM actor_authorities WHERE role=? AND release_sequence=? AND lease_epoch=?",
            &[
                SqlValue::Text(actor.role().as_str()),
                SqlValue::Integer(to_i64(state.release_sequence)?),
                SqlValue::Integer(to_i64(state.lease_epoch)?),
            ],
        )?;
        if tuple.as_deref() != Some(actor.component_tuple_digest()) {
            return Err(RootStoreError::ActorStale);
        }
        Ok(())
    }

    pub(crate) fn transaction<T>(
        &mut self,
        action: impl FnOnce(&mut Self) -> Result<T, RootStoreError>,
    ) -> Result<T, RootStoreError> {
        self.db.exec("BEGIN IMMEDIATE")?;
        match action(self) {
            Ok(value) => match self.db.exec("COMMIT") {
                Ok(()) => Ok(value),
                Err(commit_error) => {
                    let _ = self.db.exec("ROLLBACK");
                    Err(RootStoreError::CommitFailed(format!("{commit_error:?}")))
                }
            },
            Err(error) => {
                let _ = self.db.exec("ROLLBACK");
                Err(error)
            }
        }
    }
}

fn initialize_new_store(
    db: &RootSqlite,
    bootstrap: &RootStoreBootstrapV1,
) -> Result<(), RootStoreError> {
    db.exec("BEGIN EXCLUSIVE")?;
    let result = (|| {
        db.initialize_schema()?;
        db.execute(
            "INSERT INTO release_epochs(release_sequence,lease_epoch) VALUES(?,?)",
            &[
                SqlValue::Integer(to_i64(bootstrap.release_sequence)?),
                SqlValue::Integer(to_i64(bootstrap.lease_epoch)?),
            ],
        )?;
        db.execute(
            "INSERT INTO guard_metadata(singleton,schema_version,release_sequence,lease_epoch,revision,lifecycle) VALUES(1,?,?,?,?, 'active')",
            &[
                SqlValue::Integer(ROOT_STORE_SCHEMA_VERSION),
                SqlValue::Integer(to_i64(bootstrap.release_sequence)?),
                SqlValue::Integer(to_i64(bootstrap.lease_epoch)?),
                SqlValue::Integer(1),
            ],
        )?;
        insert_actor_authorities(db, bootstrap)?;
        db.validate_schema()?;
        Ok(())
    })();
    match result {
        Ok(()) => db.exec("COMMIT"),
        Err(error) => {
            let _ = db.exec("ROLLBACK");
            Err(error)
        }
    }
}

fn validate_bootstrap(bootstrap: &RootStoreBootstrapV1) -> Result<(), RootStoreError> {
    if bootstrap.release_sequence == 0 || bootstrap.lease_epoch == 0 || bootstrap.actors.len() != 7
    {
        return Err(RootStoreError::InvalidTransition);
    }
    let mut seen = [false; 7];
    for actor in &bootstrap.actors {
        let index = match actor.role {
            ActorRoleV1::Gateway => 0,
            ActorRoleV1::Main => 1,
            ActorRoleV1::Renderer => 2,
            ActorRoleV1::ModelBroker => 3,
            ActorRoleV1::NetworkBroker => 4,
            ActorRoleV1::CurrentStateBroker => 5,
            ActorRoleV1::Updater => 6,
            ActorRoleV1::Unknown => return Err(RootStoreError::InvalidTransition),
        };
        if seen[index]
            || actor.component_tuple_digest.len() != 64
            || !actor
                .component_tuple_digest
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(RootStoreError::InvalidTransition);
        }
        seen[index] = true;
    }
    if seen.into_iter().all(|present| present) {
        Ok(())
    } else {
        Err(RootStoreError::InvalidTransition)
    }
}

fn validate_existing_store(db: &RootSqlite) -> Result<(), RootStoreError> {
    db.validate_schema()?;
    let schema = db.query_i64(
        "SELECT schema_version FROM guard_metadata WHERE singleton=1",
        &[],
    )?;
    if schema != ROOT_STORE_SCHEMA_VERSION {
        return Err(RootStoreError::Integrity(format!(
            "unsupported root store schema {schema}"
        )));
    }
    Ok(())
}

fn insert_actor_authorities(
    db: &RootSqlite,
    bootstrap: &RootStoreBootstrapV1,
) -> Result<(), RootStoreError> {
    for actor in &bootstrap.actors {
        db.execute(
            "INSERT INTO actor_authorities(role,component_tuple_digest,release_sequence,lease_epoch) VALUES(?,?,?,?)",
            &[
                SqlValue::Text(actor.role.as_str()),
                SqlValue::Text(&actor.component_tuple_digest),
                SqlValue::Integer(to_i64(bootstrap.release_sequence)?),
                SqlValue::Integer(to_i64(bootstrap.lease_epoch)?),
            ],
        )?;
    }
    Ok(())
}

pub(crate) fn open_private_root(path: &Path) -> Result<File, RootStoreError> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .map_err(|error| RootStoreError::InvalidRoot(error.to_string()))?;
    verify_private_directory_metadata(&file.metadata().map_err(|error| {
        RootStoreError::InvalidRoot(format!("cannot stat root directory: {error}"))
    })?)?;
    Ok(file)
}

pub(crate) fn open_named_lock(root: &Path, name: &str) -> Result<File, RootStoreError> {
    let path = root.join(name);
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&path)
        .map_err(|error| RootStoreError::InvalidRoot(error.to_string()))?;
    verify_private_file(&path)?;
    let result = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
    if result != 0 {
        return Err(RootStoreError::AlreadyOpen);
    }
    Ok(file)
}

// Diagnostic and composition constraint: this error path must never grow
// tooling that enumerates process descriptors (/dev/fd, lsof, …), and
// spawn-heavy tests must stay mutually exclusive with lock-lifecycle tests.
// Opening /dev/fd/N duplicates the open file description, and every
// fork/posix_spawn window copies the whole descriptor table into the child
// until exec applies O_CLOEXEC; during such a window a lock fd that its
// owner just closed keeps guarding the inode, so parallel drop-then-reopen
// sequences observe spurious AlreadyOpen conflicts.
// crate::test_spawn_exclusion serializes the two groups.
#[cfg(test)]
pub(crate) use crate::test_spawn_exclusion::acquire as test_spawn_and_flock_exclusion;

pub(crate) fn create_or_validate_private_file(path: &Path) -> Result<bool, RootStoreError> {
    match OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
    {
        Ok(_) => {
            verify_private_file(path)?;
            Ok(true)
        }
        Err(error) if error.kind() == ErrorKind::AlreadyExists => {
            verify_private_file(path)?;
            Ok(false)
        }
        Err(error) => Err(RootStoreError::InvalidRoot(error.to_string())),
    }
}

pub(crate) fn verify_private_file(path: &Path) -> Result<(), RootStoreError> {
    let metadata = path
        .symlink_metadata()
        .map_err(|error| RootStoreError::InvalidRoot(error.to_string()))?;
    if !metadata.file_type().is_file()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.mode() & 0o777 != 0o600
    {
        return Err(RootStoreError::InvalidRoot(format!(
            "private file identity is invalid: {}",
            path.display()
        )));
    }
    Ok(())
}

fn verify_private_directory_metadata(metadata: &std::fs::Metadata) -> Result<(), RootStoreError> {
    if !metadata.is_dir()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.mode() & 0o777 != 0o700
    {
        return Err(RootStoreError::InvalidRoot(
            "root directory must be owned by the effective uid and mode 0700".to_string(),
        ));
    }
    Ok(())
}

pub(crate) fn verify_root_identity(path: &Path, opened: &File) -> Result<(), RootStoreError> {
    let current = path
        .symlink_metadata()
        .map_err(|error| RootStoreError::InvalidRoot(error.to_string()))?;
    let opened = opened
        .metadata()
        .map_err(|error| RootStoreError::InvalidRoot(error.to_string()))?;
    verify_private_directory_metadata(&current)?;
    if current.dev() != opened.dev() || current.ino() != opened.ino() {
        return Err(RootStoreError::InvalidRoot(
            "root directory identity changed during open".to_string(),
        ));
    }
    Ok(())
}

fn to_i64(value: u64) -> Result<i64, RootStoreError> {
    i64::try_from(value).map_err(|_| RootStoreError::InvalidTransition)
}

fn to_u64(value: i64) -> Result<u64, RootStoreError> {
    u64::try_from(value).map_err(|_| RootStoreError::Integrity("negative integer".to_string()))
}
