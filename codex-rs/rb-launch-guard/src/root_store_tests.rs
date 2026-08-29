#![allow(clippy::expect_used)]

use super::root_protocol::ActorRoleV1;
use super::root_protocol::AuthenticatedActorSnapshotV1;
use super::root_protocol::admit_root_command;
use super::root_sqlite::mutate_store_for_test;
use super::root_store::ActorAuthorityV1;
use super::root_store::RootStore;
use super::root_store::RootStoreBootstrapV1;
use super::root_store::RootStoreError;
use sha2::Digest;
use sha2::Sha256;
use std::fs;
use std::os::unix::fs::MetadataExt;
use std::os::unix::fs::symlink;

pub(super) fn digest(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

pub(super) fn bootstrap(
    release_sequence: u64,
    lease_epoch: u64,
    tuple: u8,
) -> RootStoreBootstrapV1 {
    RootStoreBootstrapV1 {
        release_sequence,
        lease_epoch,
        actors: [
            ActorRoleV1::Gateway,
            ActorRoleV1::Main,
            ActorRoleV1::Renderer,
            ActorRoleV1::ModelBroker,
            ActorRoleV1::NetworkBroker,
            ActorRoleV1::CurrentStateBroker,
            ActorRoleV1::Updater,
        ]
        .into_iter()
        .map(|role| ActorAuthorityV1 {
            role,
            component_tuple_digest: char::from(tuple).to_string().repeat(64),
        })
        .collect(),
    }
}

fn gateway_command(
    method: &str,
    operation_id: &str,
    expected_revision: u64,
    release_sequence: u64,
    lease_epoch: u64,
    tuple: u8,
) -> super::root_protocol::AuthorizedRootCommandV1 {
    admitted_command(
        ActorRoleV1::Gateway,
        method,
        operation_id,
        expected_revision,
        release_sequence,
        lease_epoch,
        tuple,
        "gateway-instance-1",
        "opaque-payload",
    )
}

#[allow(clippy::too_many_arguments)]
pub(super) fn admitted_command(
    actor_role: ActorRoleV1,
    method: &str,
    operation_id: &str,
    expected_revision: u64,
    release_sequence: u64,
    lease_epoch: u64,
    tuple: u8,
    connection_instance: &str,
    payload: &str,
) -> super::root_protocol::AuthorizedRootCommandV1 {
    admitted_command_with_subject(
        actor_role,
        method,
        operation_id,
        expected_revision,
        release_sequence,
        lease_epoch,
        tuple,
        connection_instance,
        &"a".repeat(64),
        payload,
    )
}

#[allow(clippy::too_many_arguments)]
pub(super) fn admitted_command_with_subject(
    actor_role: ActorRoleV1,
    method: &str,
    operation_id: &str,
    expected_revision: u64,
    release_sequence: u64,
    lease_epoch: u64,
    tuple: u8,
    connection_instance: &str,
    subject_digest: &str,
    payload: &str,
) -> super::root_protocol::AuthorizedRootCommandV1 {
    let bytes = format!(
        "{{\"schema\":\"rb.root-command.v1\",\"operationId\":\"{operation_id}\",\"expectedRevision\":{expected_revision},\"clientNonce\":\"nonce-1\",\"method\":\"{method}\",\"brokerRole\":\"model\",\"subjectDigest\":\"{}\",\"payload\":{payload:?},\"payloadDigest\":\"{}\"}}",
        subject_digest,
        digest(payload.as_bytes())
    )
    .into_bytes();
    let actor = AuthenticatedActorSnapshotV1::new_for_test(
        actor_role,
        char::from(tuple).to_string().repeat(64),
        release_sequence,
        lease_epoch,
        connection_instance.to_string(),
        &bytes,
    );
    admit_root_command(actor, &bytes).expect("valid Gateway store command")
}

pub(super) fn new_root() -> tempfile::TempDir {
    let root = tempfile::tempdir_in("/private/tmp").expect("private temporary root");
    let mut permissions = fs::metadata(root.path())
        .expect("temporary root metadata")
        .permissions();
    std::os::unix::fs::PermissionsExt::set_mode(&mut permissions, 0o700);
    fs::set_permissions(root.path(), permissions).expect("set private temporary root mode");
    root
}

#[test]
fn root_store_creates_private_exact_schema_and_reopens_without_repair() {
    let _spawn_exclusion = super::root_store::test_spawn_and_flock_exclusion();
    let root = new_root();
    let initial = bootstrap(3, 5, b'c');
    let store = RootStore::open(root.path(), &initial).expect("create exact root store");
    assert_eq!(store.release_state().expect("release state").revision, 1);
    assert_eq!(
        fs::metadata(store.path())
            .expect("database metadata")
            .mode()
            & 0o777,
        0o600
    );
    assert_eq!(
        RootStore::open(root.path(), &initial).err(),
        Some(RootStoreError::AlreadyOpen)
    );
    drop(store);
    let reopened = RootStore::open(root.path(), &initial).expect("healthy file DB reopen");
    assert_eq!(reopened.operation_count().expect("operation count"), 0);
}

#[test]
fn existing_store_never_repairs_missing_or_changed_schema_objects() {
    let _spawn_exclusion = super::root_store::test_spawn_and_flock_exclusion();
    let mutations = [
        "DROP TABLE broker_operations",
        "DROP TABLE release_revocations",
        "DROP TRIGGER broker_operations_no_delete",
        "DROP TRIGGER release_revocations_no_update",
        "ALTER TABLE broker_operations RENAME COLUMN payload_digest TO payload_hash",
    ];
    for mutation in mutations {
        let root = new_root();
        let initial = bootstrap(3, 5, b'c');
        let path = {
            let store = RootStore::open(root.path(), &initial).expect("create store fixture");
            store.path().to_path_buf()
        };
        mutate_store_for_test(&path, mutation).expect("mutate exact schema fixture");
        assert!(matches!(
            RootStore::open(root.path(), &initial),
            Err(RootStoreError::Integrity(_)) | Err(RootStoreError::Sqlite(_))
        ));
        assert!(matches!(
            RootStore::open(root.path(), &initial),
            Err(RootStoreError::Integrity(_)) | Err(RootStoreError::Sqlite(_))
        ));
    }
}

#[test]
fn foreign_key_violation_and_future_schema_are_terminal_on_reopen() {
    let _spawn_exclusion = super::root_store::test_spawn_and_flock_exclusion();
    let root = new_root();
    let initial = bootstrap(3, 5, b'c');
    let path = {
        let store = RootStore::open(root.path(), &initial).expect("create store fixture");
        store.path().to_path_buf()
    };
    mutate_store_for_test(
        &path,
        "PRAGMA foreign_keys=OFF; INSERT INTO broker_operations(operation_id,authorizing_gateway_tuple_digest,subject_digest,payload_digest,broker_role,release_sequence,lease_epoch,state,effect_attempt_count,owner_instance,revision) VALUES('orphan','cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc','aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa','bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb','model',999,999,'authorized',0,NULL,1)",
    )
    .expect("create real FK violation");
    assert!(matches!(
        RootStore::open(root.path(), &initial),
        Err(RootStoreError::Integrity(_))
    ));

    let root = new_root();
    let path = {
        let store = RootStore::open(root.path(), &initial).expect("create future-schema fixture");
        store.path().to_path_buf()
    };
    mutate_store_for_test(&path, "PRAGMA user_version=2").expect("advance schema version");
    assert!(matches!(
        RootStore::open(root.path(), &initial),
        Err(RootStoreError::Integrity(_))
    ));
}

#[test]
fn release_and_lease_epoch_advance_exactly_and_stale_queued_command_is_rejected() {
    let _spawn_exclusion = super::root_store::test_spawn_and_flock_exclusion();
    let root = new_root();
    let initial = bootstrap(3, 5, b'c');
    let mut store = RootStore::open(root.path(), &initial).expect("create store");
    store
        .authorize_broker(gateway_command(
            "broker-authorize",
            "operation-1",
            0,
            3,
            5,
            b'c',
        ))
        .expect("authorize operation");
    let queued_old = gateway_command("broker-authorize", "operation-2", 0, 3, 5, b'c');
    assert_eq!(store.begin_quiesce(3, 1), Ok(2));
    assert_eq!(
        store.activate_release(3, 2, &bootstrap(4, 6, b'd')),
        Err(RootStoreError::ActiveOperations)
    );
    store
        .cancel_before_claim(gateway_command(
            "broker-cancel-before-claim",
            "operation-1",
            1,
            3,
            5,
            b'c',
        ))
        .expect("cancel before claim");

    for invalid in [
        bootstrap(4, 5, b'd'),
        bootstrap(4, 4, b'd'),
        bootstrap(4, 7, b'd'),
        bootstrap(3, 6, b'd'),
        bootstrap(5, 6, b'd'),
    ] {
        assert_eq!(
            store.activate_release(3, 2, &invalid),
            Err(RootStoreError::InvalidTransition)
        );
        assert_eq!(store.release_state().expect("unchanged state").revision, 2);
        assert!(!store.is_release_revoked(3).expect("no revocation"));
    }

    assert_eq!(store.activate_release(3, 2, &bootstrap(4, 6, b'd')), Ok(3));
    assert!(store.is_release_revoked(3).expect("append-only revocation"));
    assert_eq!(
        store.authorize_broker(queued_old),
        Err(RootStoreError::ActorStale)
    );
    drop(store);
    let reopened =
        RootStore::open(root.path(), &bootstrap(4, 6, b'd')).expect("reopen exact advanced epoch");
    assert_eq!(
        reopened
            .release_state()
            .expect("advanced state")
            .lease_epoch,
        6
    );
}

#[test]
fn lock_file_descriptor_is_not_inherited_by_child_processes() {
    let _spawn_exclusion = super::root_store::test_spawn_and_flock_exclusion();
    use std::os::unix::process::CommandExt;
    use std::process::Command;
    let root = new_root();
    let initial = bootstrap(3, 5, b'c');
    // Lock exclusivity must survive concurrent child-process churn. BSD flock
    // is owned by the open file description, and fork() duplicates every
    // descriptor into the child, so a CLOEXEC-less flocked fd would survive
    // exec on platforms whose exec does not drop inherited flock state. On
    // macOS an exec severs the inherited lock and Rust's posix_spawn path
    // closes every descriptor above 2, but the no-op pre_exec below is
    // load-bearing: it forces libstd onto the fork+exec fallback, the only
    // spawn path that inherits descriptors at all, so this test keeps
    // pinning that the guard lock is dropped (CLOEXEC) and that a
    // drop-then-reopen never races against live child processes.
    let mut command = Command::new("/bin/sleep");
    command.arg("0.5");
    // SAFETY: the pre_exec closure runs in the forked child before exec and
    // only returns Ok; the call exists to force the fork+exec spawn path.
    unsafe {
        command.pre_exec(|| Ok(()));
    }
    let mut child = command
        .spawn()
        .expect("spawn fork+exec child before the store lifecycle");
    let store = RootStore::open(root.path(), &initial).expect("open store for inheritance probe");
    drop(store);
    let reopened = RootStore::open(root.path(), &initial).expect("reopen while child is alive");
    drop(reopened);
    child.wait().expect("reap child");
}

#[test]
fn symlink_and_non_private_roots_fail_before_store_authority() {
    let target = new_root();
    let parent = new_root();
    let link = parent.path().join("linked-root");
    symlink(target.path(), &link).expect("create root symlink");
    assert!(matches!(
        RootStore::open(&link, &bootstrap(3, 5, b'c')),
        Err(RootStoreError::InvalidRoot(_))
    ));

    let root = new_root();
    let mut unsafe_mode = fs::metadata(root.path()).expect("root mode").permissions();
    std::os::unix::fs::PermissionsExt::set_mode(&mut unsafe_mode, 0o755);
    fs::set_permissions(root.path(), unsafe_mode).expect("weaken fixture root");
    assert!(matches!(
        RootStore::open(root.path(), &bootstrap(3, 5, b'c')),
        Err(RootStoreError::InvalidRoot(_))
    ));
}
