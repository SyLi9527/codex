use crate::root_protocol::ActorRoleV1;
use crate::root_protocol::AuthenticatedActorSnapshotV1;
use crate::root_protocol::AuthorizedVerifiedVendorOfferV1;
use crate::root_sqlite::RootSqlite;
use crate::root_sqlite::SqlValue;
use crate::root_store::RootStoreError;
use crate::root_store::create_or_validate_private_file;
use crate::root_store::open_named_lock;
use crate::root_store::open_private_root;
use crate::root_store::verify_private_file;
use crate::root_store::verify_root_identity;
use crate::vendor_release::ACTOR_AUTHORITY_SET_DOMAIN;
use crate::vendor_release::PinnedVendorAnchorV1;
use crate::vendor_release::VendorActorRoleV1;
use crate::vendor_release::VendorReleaseError;
use crate::vendor_release::VerifiedVendorGenesisV1;
use crate::vendor_release::admit_vendor_offer_bundle;
use crate::vendor_release::verify_vendor_offer;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use libsqlite3_sys as sqlite;
use sha2::Digest;
use sha2::Sha256;
use std::fs;
use std::fs::File;
use std::path::Path;
use std::path::PathBuf;

const VENDOR_STORE_APPLICATION_ID: i64 = 1_447_129_905;
const VENDOR_STORE_SCHEMA_VERSION: i64 = 2;
/// The stage-period schema version. Kept so the migration path can validate a
/// pre-activation database against the exact manifest it shipped with before
/// rewriting it.
const LEGACY_VENDOR_STORE_SCHEMA_VERSION: i64 = 1;
const DIGEST_BYTES: usize = 32;

/// Root-local genesis lease epoch, deterministically 1 for every freshly
/// initialized store. It is not derived from vendor bytes (no vendor-signed
/// body carries an epoch). Its only writer is the activation transaction,
/// which increments it by exactly 1 together with store_revision inside one
/// transaction; the vendor_current_transition trigger rejects every other
/// lease_epoch transition, so the epoch cannot move without a full authority
/// hand-over.
pub(crate) const GENESIS_LEASE_EPOCH: u64 = 1;

// The SQL texts below are the current (activation-capable) schema contract.
// The schema validator compares sqlite_schema.sql byte for byte against these
// constants, so the documented contract text itself is schema-pinned: any
// silent rewrite fails integrity validation.
const CURRENT_SQL: &str = r#"CREATE TABLE vendor_current(
  -- Delivered activation transition contract (S2). The only permitted UPDATEs
  -- are, first, the stage-period form that increments store_revision by
  -- exactly 1 and freezes every other column, and second, the activation
  -- form: store_revision, release_sequence and lease_epoch each advance by
  -- exactly 1, singleton and schema_version stay frozen, and every remaining
  -- column except updater_tuple_digest must equal the corresponding
  -- vendor_staged_release value (trust_sequence, manifest_digest,
  -- release_digest, actor_set_digest, current_bundle=raw_bundle).
  -- updater_tuple_digest stays the first-class binding of the vendor-signed
  -- Updater component tuple; vendor_staged_release carries no such column,
  -- so the trigger cannot compare it: its correct value is cryptographically
  -- bound to the pinned NEW.actor_set_digest (domain-separated hash over the
  -- seven signed tuples), and the activation body derives it from the
  -- freshly re-verified raw_bundle and re-checks the durable actor table
  -- against the same digest before COMMIT. The
  -- vendor_current_transition trigger enforces both forms with an explicit
  -- staged-row existence guard, so an empty slot can never relax them.
  -- Delivered with the activation form: the staged-slot consume contract
  -- (vendor_staged_no_delete releases a row only after vendor_current
  -- already installed that exact release), expired-offer rejection (full
  -- re-verification from vendor_staged_release.raw_bundle with a fresh wall
  -- clock and the in-transaction current snapshot before any write; a
  -- rejected offer leaves the store byte-identical and keeps the audit row),
  -- lease_epoch owned by the activation transaction (+1 per activation, in
  -- the same transaction as store_revision), and the versioned migration path
  -- (user_version 1 -> 2; legacy v1 stores migrate in place, files carrying
  -- this application id with an unknown schema version fail closed and are
  -- never rebuilt).
  singleton INTEGER PRIMARY KEY CHECK(singleton=1),
  schema_version INTEGER NOT NULL CHECK(schema_version=1),
  store_revision INTEGER NOT NULL CHECK(store_revision>0),
  trust_sequence INTEGER NOT NULL CHECK(trust_sequence>0),
  manifest_digest BLOB NOT NULL CHECK(length(manifest_digest)=32),
  release_sequence INTEGER NOT NULL CHECK(release_sequence>0),
  release_digest BLOB NOT NULL CHECK(length(release_digest)=32),
  lease_epoch INTEGER NOT NULL CHECK(lease_epoch>0),
  actor_set_digest BLOB NOT NULL CHECK(length(actor_set_digest)=32),
  updater_tuple_digest BLOB NOT NULL CHECK(length(updater_tuple_digest)=32),
  current_bundle BLOB NOT NULL,
  UNIQUE(release_sequence,lease_epoch)
)"#;
const ACTORS_SQL: &str = r#"CREATE TABLE vendor_actor_authorities(
  -- Per-role vendor-signed tuple rows (role-keyed, extensible by adding rows
  -- and enum variants, never new columns). Immutable except inside an
  -- activation transaction: once vendor_current has moved exactly one
  -- generation ahead of a row, that row may follow once to the newly
  -- installed release tuple under the refined no-update/no-delete contracts;
  -- the activation body re-derives all seven tuples from the re-verified
  -- bundle and re-checks the recomputed actor-set digest before COMMIT.
  role TEXT PRIMARY KEY CHECK(role IN ('gateway','main','renderer','model-broker','network-broker','current-state-broker','updater')),
  tuple_digest BLOB NOT NULL CHECK(length(tuple_digest)=32),
  release_sequence INTEGER NOT NULL,
  lease_epoch INTEGER NOT NULL,
  FOREIGN KEY(release_sequence,lease_epoch) REFERENCES vendor_current(release_sequence,lease_epoch)
)"#;
const STAGED_SQL: &str = r#"CREATE TABLE vendor_staged_release(
  -- Unique pending-offer slot lifecycle: EMPTY -> OCCUPIED -> consumed by
  -- activation -> EMPTY. OCCUPIED rows are immutable (no UPDATE is ever
  -- permitted). The same operation_id with the same bundle_digest replays
  -- idempotently with zero state change; the same operation_id with
  -- different bytes is StagedOperationMismatch; a different operation_id is
  -- StagedSlotOccupied. subject_digest is an audit-only field: it records
  -- the command-declared subject and takes no part in stage decisions.
  -- Activation (delivered) fully re-verifies the offer from raw_bundle with
  -- a fresh wall clock and the in-transaction current snapshot, and consumes
  -- the slot only after vendor_current already installed that exact release;
  -- an offer rejected as expired or tampered leaves the store unchanged and
  -- keeps the slot occupied as the audit record of what was refused.
  singleton INTEGER PRIMARY KEY CHECK(singleton=1),
  operation_id TEXT NOT NULL UNIQUE,
  subject_digest TEXT NOT NULL CHECK(length(subject_digest)=64),
  payload_digest TEXT NOT NULL CHECK(length(payload_digest)=64),
  base_revision INTEGER NOT NULL CHECK(base_revision>0),
  trust_sequence INTEGER NOT NULL CHECK(trust_sequence>0),
  manifest_digest BLOB NOT NULL CHECK(length(manifest_digest)=32),
  release_sequence INTEGER NOT NULL CHECK(release_sequence>0),
  release_digest BLOB NOT NULL CHECK(length(release_digest)=32),
  bundle_digest BLOB NOT NULL CHECK(length(bundle_digest)=32),
  actor_set_digest BLOB NOT NULL CHECK(length(actor_set_digest)=32),
  raw_bundle BLOB NOT NULL
)"#;
const CURRENT_NO_DELETE_SQL: &str = "CREATE TRIGGER vendor_current_no_delete BEFORE DELETE ON vendor_current BEGIN SELECT RAISE(ABORT,'vendor current is immutable'); END";
const CURRENT_TRANSITION_SQL: &str = r#"CREATE TRIGGER vendor_current_transition BEFORE UPDATE ON vendor_current WHEN NOT (
  (
    NEW.singleton=OLD.singleton AND NEW.schema_version=OLD.schema_version AND
    NEW.store_revision=OLD.store_revision+1 AND NEW.trust_sequence=OLD.trust_sequence AND
    NEW.manifest_digest=OLD.manifest_digest AND NEW.release_sequence=OLD.release_sequence AND
    NEW.release_digest=OLD.release_digest AND NEW.lease_epoch=OLD.lease_epoch AND
    NEW.actor_set_digest=OLD.actor_set_digest AND
    NEW.updater_tuple_digest=OLD.updater_tuple_digest AND NEW.current_bundle=OLD.current_bundle
  ) OR (
    EXISTS(SELECT 1 FROM vendor_staged_release WHERE singleton=1) AND
    NEW.singleton=OLD.singleton AND NEW.schema_version=OLD.schema_version AND
    NEW.store_revision=OLD.store_revision+1 AND NEW.release_sequence=OLD.release_sequence+1 AND
    NEW.lease_epoch=OLD.lease_epoch+1 AND
    NEW.trust_sequence=(SELECT trust_sequence FROM vendor_staged_release WHERE singleton=1) AND
    NEW.manifest_digest=(SELECT manifest_digest FROM vendor_staged_release WHERE singleton=1) AND
    NEW.release_digest=(SELECT release_digest FROM vendor_staged_release WHERE singleton=1) AND
    NEW.actor_set_digest=(SELECT actor_set_digest FROM vendor_staged_release WHERE singleton=1) AND
    NEW.current_bundle=(SELECT raw_bundle FROM vendor_staged_release WHERE singleton=1)
  )
) BEGIN SELECT RAISE(ABORT,'invalid vendor current transition'); END"#;
const ACTORS_NO_UPDATE_SQL: &str = r#"CREATE TRIGGER vendor_actors_no_update BEFORE UPDATE ON vendor_actor_authorities WHEN NOT (
  NEW.release_sequence=OLD.release_sequence+1 AND NEW.lease_epoch=OLD.lease_epoch+1 AND
  EXISTS(
    SELECT 1 FROM vendor_current
    WHERE vendor_current.singleton=1 AND
      vendor_current.release_sequence=OLD.release_sequence+1 AND
      vendor_current.lease_epoch=OLD.lease_epoch+1
  )
) BEGIN SELECT RAISE(ABORT,'vendor actors are immutable'); END"#;
const ACTORS_NO_DELETE_SQL: &str = r#"CREATE TRIGGER vendor_actors_no_delete BEFORE DELETE ON vendor_actor_authorities WHEN NOT (
  EXISTS(
    SELECT 1 FROM vendor_current
    WHERE vendor_current.singleton=1 AND
      vendor_current.release_sequence=OLD.release_sequence+1 AND
      vendor_current.lease_epoch=OLD.lease_epoch+1
  )
) BEGIN SELECT RAISE(ABORT,'vendor actors are immutable'); END"#;
const STAGED_NO_UPDATE_SQL: &str = "CREATE TRIGGER vendor_staged_no_update BEFORE UPDATE ON vendor_staged_release BEGIN SELECT RAISE(ABORT,'staged release is immutable'); END";
const STAGED_NO_DELETE_SQL: &str = r#"CREATE TRIGGER vendor_staged_no_delete BEFORE DELETE ON vendor_staged_release WHEN NOT (
  EXISTS(
    SELECT 1 FROM vendor_current
    WHERE vendor_current.singleton=1 AND
      vendor_current.release_sequence=OLD.release_sequence AND
      vendor_current.trust_sequence=OLD.trust_sequence AND
      vendor_current.manifest_digest=OLD.manifest_digest AND
      vendor_current.release_digest=OLD.release_digest AND
      vendor_current.actor_set_digest=OLD.actor_set_digest AND
      vendor_current.current_bundle=OLD.raw_bundle
  )
) BEGIN SELECT RAISE(ABORT,'staged release is immutable'); END"#;

// Stage-period (pre-activation) schema texts, preserved verbatim as the
// migration contract: open_existing validates an existing user_version=1
// database against this exact manifest before rewriting it, so only the
// schema this crate actually shipped can be migrated. Nothing is created
// with these texts anymore.
const LEGACY_CURRENT_SQL: &str = r#"CREATE TABLE vendor_current(
  -- Stage-period transition contract: the only permitted UPDATE increments
  -- store_revision by exactly 1 and freezes every other column, including
  -- updater_tuple_digest (the first-class binding of the vendor-signed
  -- Updater component tuple; it is also cross-checked in the stage CAS WHERE
  -- and recomputed against the signed actor_set_digest in every stage).
  -- Activation checkpoint hard gates (contract only, no implementation in
  -- this crate state):
  -- 1. Activation must deliver a new vendor_current transition contract plus
  --    a store migration path (user_version increment plus a migrate-or-
  --    rebuild policy for pre-activation databases).
  -- 2. Activation must deliver the staged-slot consume contract: a
  --    conditional DELETE of vendor_staged_release is allowed only when
  --    vendor_current already installed that staged release
  --    (release_sequence, trust_sequence and actor_set_digest all equal);
  --    the STAGED/ACTORS immutability triggers are refined by that contract.
  -- 3. Activation must deliver expired-offer rejection: promotion re-verifies
  --    the full bundle from vendor_staged_release.raw_bundle with a fresh
  --    wall clock and the in-transaction current snapshot, and defines the
  --    slot handling for offers rejected as expired.
  -- 4. lease_epoch is root-local monotonic state owned by the activation
  --    transaction (+1 per activation); no increment path exists in this
  --    crate state.
  singleton INTEGER PRIMARY KEY CHECK(singleton=1),
  schema_version INTEGER NOT NULL CHECK(schema_version=1),
  store_revision INTEGER NOT NULL CHECK(store_revision>0),
  trust_sequence INTEGER NOT NULL CHECK(trust_sequence>0),
  manifest_digest BLOB NOT NULL CHECK(length(manifest_digest)=32),
  release_sequence INTEGER NOT NULL CHECK(release_sequence>0),
  release_digest BLOB NOT NULL CHECK(length(release_digest)=32),
  lease_epoch INTEGER NOT NULL CHECK(lease_epoch>0),
  actor_set_digest BLOB NOT NULL CHECK(length(actor_set_digest)=32),
  updater_tuple_digest BLOB NOT NULL CHECK(length(updater_tuple_digest)=32),
  current_bundle BLOB NOT NULL,
  UNIQUE(release_sequence,lease_epoch)
)"#;
const LEGACY_ACTORS_SQL: &str = r#"CREATE TABLE vendor_actor_authorities(
  -- Per-role vendor-signed tuple rows (role-keyed, extensible by adding rows
  -- and enum variants, never new columns). Immutable under stage; activation
  -- refines this immutability together with the vendor_current transition
  -- contract above.
  role TEXT PRIMARY KEY CHECK(role IN ('gateway','main','renderer','model-broker','network-broker','current-state-broker','updater')),
  tuple_digest BLOB NOT NULL CHECK(length(tuple_digest)=32),
  release_sequence INTEGER NOT NULL,
  lease_epoch INTEGER NOT NULL,
  FOREIGN KEY(release_sequence,lease_epoch) REFERENCES vendor_current(release_sequence,lease_epoch)
)"#;
const LEGACY_STAGED_SQL: &str = r#"CREATE TABLE vendor_staged_release(
  -- Unique pending-offer slot lifecycle (CP3): EMPTY -> OCCUPIED ->
  -- (activation, non-goal) -> EMPTY. OCCUPIED is terminal in this checkpoint.
  -- The same operation_id with the same bundle_digest replays idempotently
  -- with zero state change; the same operation_id with different bytes is
  -- StagedOperationMismatch; a different operation_id is StagedSlotOccupied.
  -- subject_digest is an audit-only field: it records the command-declared
  -- subject and takes no part in stage decisions; its semantic consumer is
  -- the future promote/activation checkpoint.
  -- Promotion must re-verify the full bundle from raw_bundle with a fresh
  -- wall clock and the in-transaction current snapshot; an offer valid at
  -- verify time but expired before promotion may occupy the slot, and the
  -- activation checkpoint owns the rejection and slot handling for it.
  singleton INTEGER PRIMARY KEY CHECK(singleton=1),
  operation_id TEXT NOT NULL UNIQUE,
  subject_digest TEXT NOT NULL CHECK(length(subject_digest)=64),
  payload_digest TEXT NOT NULL CHECK(length(payload_digest)=64),
  base_revision INTEGER NOT NULL CHECK(base_revision>0),
  trust_sequence INTEGER NOT NULL CHECK(trust_sequence>0),
  manifest_digest BLOB NOT NULL CHECK(length(manifest_digest)=32),
  release_sequence INTEGER NOT NULL CHECK(release_sequence>0),
  release_digest BLOB NOT NULL CHECK(length(release_digest)=32),
  bundle_digest BLOB NOT NULL CHECK(length(bundle_digest)=32),
  actor_set_digest BLOB NOT NULL CHECK(length(actor_set_digest)=32),
  raw_bundle BLOB NOT NULL
)"#;
const LEGACY_CURRENT_TRANSITION_SQL: &str = r#"CREATE TRIGGER vendor_current_transition BEFORE UPDATE ON vendor_current WHEN NOT (
  NEW.singleton=OLD.singleton AND NEW.schema_version=OLD.schema_version AND
  NEW.store_revision=OLD.store_revision+1 AND NEW.trust_sequence=OLD.trust_sequence AND
  NEW.manifest_digest=OLD.manifest_digest AND NEW.release_sequence=OLD.release_sequence AND
  NEW.release_digest=OLD.release_digest AND NEW.lease_epoch=OLD.lease_epoch AND
  NEW.actor_set_digest=OLD.actor_set_digest AND
  NEW.updater_tuple_digest=OLD.updater_tuple_digest AND NEW.current_bundle=OLD.current_bundle
) BEGIN SELECT RAISE(ABORT,'invalid vendor current transition'); END"#;
const LEGACY_ACTORS_NO_UPDATE_SQL: &str = "CREATE TRIGGER vendor_actors_no_update BEFORE UPDATE ON vendor_actor_authorities BEGIN SELECT RAISE(ABORT,'vendor actors are immutable'); END";
const LEGACY_ACTORS_NO_DELETE_SQL: &str = "CREATE TRIGGER vendor_actors_no_delete BEFORE DELETE ON vendor_actor_authorities BEGIN SELECT RAISE(ABORT,'vendor actors are immutable'); END";
const LEGACY_STAGED_NO_DELETE_SQL: &str = "CREATE TRIGGER vendor_staged_no_delete BEFORE DELETE ON vendor_staged_release BEGIN SELECT RAISE(ABORT,'staged release is immutable'); END";

const SCHEMA_OBJECTS: &[(&str, &str, &str, &str)] = &[
    ("table", "vendor_current", "vendor_current", CURRENT_SQL),
    (
        "table",
        "vendor_actor_authorities",
        "vendor_actor_authorities",
        ACTORS_SQL,
    ),
    (
        "table",
        "vendor_staged_release",
        "vendor_staged_release",
        STAGED_SQL,
    ),
    (
        "trigger",
        "vendor_current_no_delete",
        "vendor_current",
        CURRENT_NO_DELETE_SQL,
    ),
    (
        "trigger",
        "vendor_current_transition",
        "vendor_current",
        CURRENT_TRANSITION_SQL,
    ),
    (
        "trigger",
        "vendor_actors_no_update",
        "vendor_actor_authorities",
        ACTORS_NO_UPDATE_SQL,
    ),
    (
        "trigger",
        "vendor_actors_no_delete",
        "vendor_actor_authorities",
        ACTORS_NO_DELETE_SQL,
    ),
    (
        "trigger",
        "vendor_staged_no_update",
        "vendor_staged_release",
        STAGED_NO_UPDATE_SQL,
    ),
    (
        "trigger",
        "vendor_staged_no_delete",
        "vendor_staged_release",
        STAGED_NO_DELETE_SQL,
    ),
];

/// The exact stage-period manifest, used only to validate a legacy v1
/// database before migrating it. The two triggers that never changed are
/// shared with the current manifest.
const LEGACY_SCHEMA_OBJECTS: &[(&str, &str, &str, &str)] = &[
    (
        "table",
        "vendor_current",
        "vendor_current",
        LEGACY_CURRENT_SQL,
    ),
    (
        "table",
        "vendor_actor_authorities",
        "vendor_actor_authorities",
        LEGACY_ACTORS_SQL,
    ),
    (
        "table",
        "vendor_staged_release",
        "vendor_staged_release",
        LEGACY_STAGED_SQL,
    ),
    (
        "trigger",
        "vendor_current_no_delete",
        "vendor_current",
        CURRENT_NO_DELETE_SQL,
    ),
    (
        "trigger",
        "vendor_current_transition",
        "vendor_current",
        LEGACY_CURRENT_TRANSITION_SQL,
    ),
    (
        "trigger",
        "vendor_actors_no_update",
        "vendor_actor_authorities",
        LEGACY_ACTORS_NO_UPDATE_SQL,
    ),
    (
        "trigger",
        "vendor_actors_no_delete",
        "vendor_actor_authorities",
        LEGACY_ACTORS_NO_DELETE_SQL,
    ),
    (
        "trigger",
        "vendor_staged_no_update",
        "vendor_staged_release",
        STAGED_NO_UPDATE_SQL,
    ),
    (
        "trigger",
        "vendor_staged_no_delete",
        "vendor_staged_release",
        LEGACY_STAGED_NO_DELETE_SQL,
    ),
];

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum VendorStoreError {
    Backend(RootStoreError),
    AlreadyExists,
    InvalidGenesis,
    StaleCurrent,
    /// The actor's live tuple digest is not 64 lowercase hex characters: an
    /// identity-seam defect. Strictly distinct from the policy denial below;
    /// both outcomes fail closed.
    ActorIdentityMalformed,
    /// Role, release, epoch, or tuple mismatch against the durable current
    /// rows: a policy denial, fail closed.
    ActorDenied,
    RevisionMismatch,
    /// The unique pending-offer slot is occupied by a different operation.
    StagedSlotOccupied,
    /// The same operation_id was reused for different bundle bytes.
    StagedOperationMismatch,
    /// Activation found the unique pending-offer slot empty: nothing to
    /// promote (a double activation, or activation without a prior stage).
    /// The lease epoch can only advance together with a consumed slot.
    StagedSlotEmpty,
    /// The staged offer failed full re-verification from its raw_bundle with
    /// the activation wall clock: expired, tampered, or no longer chained to
    /// the in-transaction current snapshot. Activation is refused with zero
    /// state change and the slot keeps the rejected row as the audit record.
    StagedOfferRejected(VendorReleaseError),
    /// The staged row's metadata columns are incoherent with its own
    /// re-verified bundle bytes: a directly tampered slot. Strictly distinct
    /// from `StagedOfferRejected`, which covers the cryptographic
    /// verification itself; both outcomes fail closed with zero state change.
    StaleStage,
    /// COMMIT failed after the in-transaction body succeeded; the outcome is
    /// uncertain. The authoritative recovery is to re-verify and re-stage the
    /// same operation_id with the same bundle bytes: a committed transaction
    /// resolves as an idempotent replay, a rolled-back one as a fresh stage.
    /// For activation the authoritative recovery is the same transaction
    /// retried with a fresh snapshot: a committed run resolves as
    /// StagedSlotEmpty, a rolled-back one as a fresh activation.
    CommitFailed(String),
    Integrity,
    InjectedFault,
}

impl From<RootStoreError> for VendorStoreError {
    fn from(value: RootStoreError) -> Self {
        Self::Backend(value)
    }
}

/// A non-transferable read snapshot created only from this store's durable
/// current row (updater_tuple_digest is a first-class column of that row).
/// The test constructor cannot enter a non-test feature build.
pub(crate) struct VendorCurrentSnapshotV1 {
    store_revision: u64,
    trust_sequence: u64,
    manifest_digest: [u8; DIGEST_BYTES],
    release_sequence: u64,
    release_digest: [u8; DIGEST_BYTES],
    lease_epoch: u64,
    actor_set_digest: [u8; DIGEST_BYTES],
    updater_tuple_digest: [u8; DIGEST_BYTES],
}

impl VendorCurrentSnapshotV1 {
    fn from_current(current: &CurrentRow) -> Self {
        Self {
            store_revision: current.store_revision,
            trust_sequence: current.trust_sequence,
            manifest_digest: current.manifest_digest,
            release_sequence: current.release_sequence,
            release_digest: current.release_digest,
            lease_epoch: current.lease_epoch,
            actor_set_digest: current.actor_set_digest,
            updater_tuple_digest: current.updater_tuple_digest,
        }
    }

    #[expect(
        clippy::too_many_arguments,
        reason = "the test constructor mirrors the snapshot fields one to one so that field additions must touch this signature explicitly"
    )]
    #[cfg(test)]
    pub(crate) fn new_for_test(
        store_revision: u64,
        trust_sequence: u64,
        manifest_digest: [u8; DIGEST_BYTES],
        release_sequence: u64,
        release_digest: [u8; DIGEST_BYTES],
        lease_epoch: u64,
        actor_set_digest: [u8; DIGEST_BYTES],
        updater_tuple_digest: [u8; DIGEST_BYTES],
    ) -> Self {
        Self {
            store_revision,
            trust_sequence,
            manifest_digest,
            release_sequence,
            release_digest,
            lease_epoch,
            actor_set_digest,
            updater_tuple_digest,
        }
    }

    pub(crate) fn store_revision(&self) -> u64 {
        self.store_revision
    }
    pub(crate) fn trust_sequence(&self) -> u64 {
        self.trust_sequence
    }
    pub(crate) fn manifest_digest(&self) -> &[u8; DIGEST_BYTES] {
        &self.manifest_digest
    }
    pub(crate) fn release_sequence(&self) -> u64 {
        self.release_sequence
    }
    pub(crate) fn release_digest(&self) -> &[u8; DIGEST_BYTES] {
        &self.release_digest
    }
    pub(crate) fn lease_epoch(&self) -> u64 {
        self.lease_epoch
    }
    pub(crate) fn actor_set_digest(&self) -> &[u8; DIGEST_BYTES] {
        &self.actor_set_digest
    }
    pub(crate) fn updater_tuple_digest(&self) -> &[u8; DIGEST_BYTES] {
        &self.updater_tuple_digest
    }

    fn matches(&self, current: &CurrentRow) -> bool {
        self.store_revision == current.store_revision
            && self.trust_sequence == current.trust_sequence
            && self.manifest_digest == current.manifest_digest
            && self.release_sequence == current.release_sequence
            && self.release_digest == current.release_digest
            && self.lease_epoch == current.lease_epoch
            && self.actor_set_digest == current.actor_set_digest
            && self.updater_tuple_digest == current.updater_tuple_digest
    }
}

/// The caller-supplied preconditions of one activation: the last observed
/// durable snapshot (CAS'd field-for-field against the in-transaction
/// re-read, exactly like stage) and the live Updater identity authorizing the
/// transition (re-checked inside the transaction with the same four checks as
/// stage: role, release sequence, lease epoch, component tuple digest).
/// Neither field is optional and neither is taken from the staged row; the
/// staged row only supplies the bytes that are re-verified.
pub(crate) struct ActivationExpectationV1 {
    current: VendorCurrentSnapshotV1,
    actor: AuthenticatedActorSnapshotV1,
}

impl ActivationExpectationV1 {
    pub(crate) fn new(
        current: VendorCurrentSnapshotV1,
        actor: AuthenticatedActorSnapshotV1,
    ) -> Self {
        Self { current, actor }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ActivationResultV1 {
    revision: u64,
    release_sequence: u64,
    lease_epoch: u64,
}

impl ActivationResultV1 {
    pub(crate) fn revision(&self) -> u64 {
        self.revision
    }
    pub(crate) fn release_sequence(&self) -> u64 {
        self.release_sequence
    }
    pub(crate) fn lease_epoch(&self) -> u64 {
        self.lease_epoch
    }
}

pub(crate) struct VendorAuthorityRootStore {
    db: RootSqlite,
    _lock: File,
    _root: File,
    path: PathBuf,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct VendorStageResultV1 {
    pub(crate) revision: u64,
}

#[cfg(test)]
#[derive(Clone, Copy)]
pub(crate) enum StageFaultPoint {
    None,
    BeforeInsert,
    AfterInsert,
    AfterRevision,
    /// Skips the COMMIT call and feeds a synthetic error through the real
    /// commit-failure handler, exercising the best-effort ROLLBACK and the
    /// CommitFailed contract.
    Commit,
}

struct CurrentRow {
    store_revision: u64,
    trust_sequence: u64,
    manifest_digest: [u8; DIGEST_BYTES],
    release_sequence: u64,
    release_digest: [u8; DIGEST_BYTES],
    lease_epoch: u64,
    actor_set_digest: [u8; DIGEST_BYTES],
    updater_tuple_digest: [u8; DIGEST_BYTES],
}

enum ExistingFileDisposition {
    /// A genesis corpse: an empty file, a non-SQLite garbage file, or a
    /// database whose store identity pragmas never committed. Safe to remove
    /// and rebuild exactly once.
    Corpse,
    /// Store identity pragmas are present but the schema does not validate:
    /// real corruption, never deleted, fail closed.
    Corrupt,
    /// A complete, validated store at the current schema version.
    Complete,
    /// A complete, validated store at the legacy stage-period schema version:
    /// migrated in place by `open_existing`; `create_new` must never touch it.
    Legacy,
}

impl VendorAuthorityRootStore {
    pub(crate) fn create_new(
        root: &Path,
        genesis: VerifiedVendorGenesisV1,
    ) -> Result<Self, VendorStoreError> {
        if genesis.release_sequence() != 1 || genesis.trust_sequence() != 1 {
            return Err(VendorStoreError::InvalidGenesis);
        }
        let root_file = open_private_root(root)?;
        let lock = open_named_lock(root, "vendor-authority.lock")?;
        let path = root.join("vendor-authority.db");
        if create_or_validate_private_file(&path)? {
            return Self::initialize(root, root_file, lock, path, genesis);
        }
        match classify_existing_file(&path)? {
            ExistingFileDisposition::Complete | ExistingFileDisposition::Legacy => {
                // A legacy store is a live store: opening/migrating it is
                // open_existing's job, and create_new must never delete it.
                Err(VendorStoreError::AlreadyExists)
            }
            ExistingFileDisposition::Corrupt => Err(VendorStoreError::Integrity),
            ExistingFileDisposition::Corpse => {
                // Genesis corpse recovery: remove the corpse together with its
                // rollback journal, then rebuild exactly once. The private
                // file must be recreated through create_or_validate_private_
                // file so it reappears with mode 0600 (SQLite's own CREATE
                // would use the umask default instead). A rebuild failure
                // returns immediately; there is no retry loop and the
                // deletion scope never grows beyond these two files.
                remove_corpse_files(&path)?;
                if !create_or_validate_private_file(&path)? {
                    return Err(VendorStoreError::AlreadyExists);
                }
                Self::initialize(root, root_file, lock, path, genesis)
            }
        }
    }

    /// Opens an existing store in place; this is the store's migration entry
    /// point. A complete current-version store is opened as-is. A legacy v1
    /// store is validated against the exact stage-period manifest and then
    /// migrated in place inside one exclusive transaction. Corpses and real
    /// corruption fail closed: open never deletes anything.
    pub(crate) fn open_existing(root: &Path) -> Result<Self, VendorStoreError> {
        let root_file = open_private_root(root)?;
        let lock = open_named_lock(root, "vendor-authority.lock")?;
        let path = root.join("vendor-authority.db");
        if create_or_validate_private_file(&path)? {
            // The file did not exist and was just created empty: there is no
            // store to open. Leave the corpse for create_new's documented
            // single-shot corpse recovery and fail closed here.
            return Err(VendorStoreError::Backend(RootStoreError::InvalidRoot(
                "vendor authority store does not exist".to_string(),
            )));
        }
        let disposition = classify_existing_file(&path)?;
        if !matches!(
            disposition,
            ExistingFileDisposition::Complete | ExistingFileDisposition::Legacy
        ) {
            return Err(VendorStoreError::Integrity);
        }
        let db = RootSqlite::open(&path, false)?;
        verify_private_file(&path)?;
        verify_root_identity(root, &root_file)?;
        db.configure()?;
        if matches!(disposition, ExistingFileDisposition::Legacy) {
            migrate_legacy_v1_store(&db)?;
        }
        db.integrity_check()?;
        Ok(Self {
            db,
            _lock: lock,
            _root: root_file,
            path,
        })
    }

    fn initialize(
        root: &Path,
        root_file: File,
        lock: File,
        path: PathBuf,
        genesis: VerifiedVendorGenesisV1,
    ) -> Result<Self, VendorStoreError> {
        let db = RootSqlite::open(&path, true)?;
        verify_private_file(&path)?;
        verify_root_identity(root, &root_file)?;
        db.configure()?;
        initialize_new_store(&db, &genesis)?;
        db.integrity_check()?;
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

    pub(crate) fn snapshot(&self) -> Result<VendorCurrentSnapshotV1, VendorStoreError> {
        Ok(VendorCurrentSnapshotV1::from_current(&read_current(
            &self.db,
        )?))
    }

    pub(crate) fn stage(
        &mut self,
        authorized: AuthorizedVerifiedVendorOfferV1,
    ) -> Result<VendorStageResultV1, VendorStoreError> {
        self.stage_inner(authorized, StageFaultPoint::None)
    }

    #[cfg(test)]
    pub(crate) fn stage_with_fault(
        &mut self,
        authorized: AuthorizedVerifiedVendorOfferV1,
        fault: StageFaultPoint,
    ) -> Result<VendorStageResultV1, VendorStoreError> {
        self.stage_inner(authorized, fault)
    }

    fn stage_inner(
        &mut self,
        authorized: AuthorizedVerifiedVendorOfferV1,
        fault: StageFaultPoint,
    ) -> Result<VendorStageResultV1, VendorStoreError> {
        self.db.exec("BEGIN IMMEDIATE")?;
        let result = (|| {
            let current = read_current(&self.db)?;
            // Mandatory in-transaction recomputation of the signed actor-set
            // digest over the seven durable role rows, placed before the actor
            // checks: tampering with any role row (including non-Updater rows)
            // must map to Integrity instead of being silently ignored or
            // disguised as a policy denial.
            if recompute_actor_set_digest(&self.db)? != current.actor_set_digest {
                return Err(VendorStoreError::Integrity);
            }
            let actor = authorized.actor();
            if actor.role() != ActorRoleV1::Updater
                || actor.release_sequence() != current.release_sequence
                || actor.lease_epoch() != current.lease_epoch
            {
                return Err(VendorStoreError::ActorDenied);
            }
            if decode_hex_digest(actor.component_tuple_digest())? != current.updater_tuple_digest {
                return Err(VendorStoreError::ActorDenied);
            }
            // ACK-loss idempotency probe, before matches/expected_revision so
            // that a lazy retry carrying a stale snapshot still resolves: the
            // same operation_id with the same bundle bytes succeeds with zero
            // state change and returns the durable revision; the same
            // operation_id with different bytes is a caller bug; any other
            // operation finds the unique slot occupied.
            if let Some(staged) = read_staged_slot(&self.db)? {
                if staged.operation_id == authorized.operation_id() {
                    if staged.bundle_digest == *authorized.verified().bundle_digest() {
                        return Ok(VendorStageResultV1 {
                            revision: current.store_revision,
                        });
                    }
                    return Err(VendorStoreError::StagedOperationMismatch);
                }
                return Err(VendorStoreError::StagedSlotOccupied);
            }
            if !authorized.current().matches(&current) {
                return Err(VendorStoreError::StaleCurrent);
            }
            if authorized.expected_revision() != current.store_revision {
                return Err(VendorStoreError::RevisionMismatch);
            }
            if matches!(fault, StageFaultPoint::BeforeInsert) {
                return Err(VendorStoreError::InjectedFault);
            }
            let verified = authorized.verified();
            self.db.execute(
                "INSERT INTO vendor_staged_release(singleton,operation_id,subject_digest,payload_digest,base_revision,trust_sequence,manifest_digest,release_sequence,release_digest,bundle_digest,actor_set_digest,raw_bundle) VALUES(1,?,?,?,?,?,?,?,?,?,?,?)",
                &[
                    SqlValue::Text(authorized.operation_id()),
                    SqlValue::Text(authorized.subject_digest()),
                    SqlValue::Text(authorized.payload_digest()),
                    SqlValue::Integer(to_i64(current.store_revision)?),
                    SqlValue::Integer(to_i64(verified.trust_sequence())?),
                    SqlValue::Blob(verified.manifest_digest()),
                    SqlValue::Integer(to_i64(verified.release_sequence())?),
                    SqlValue::Blob(verified.release_object_digest()),
                    SqlValue::Blob(verified.bundle_digest()),
                    SqlValue::Blob(verified.actor_authorities().digest()),
                    SqlValue::Blob(verified.bundle_raw()),
                ],
            )?;
            if matches!(fault, StageFaultPoint::AfterInsert) {
                return Err(VendorStoreError::InjectedFault);
            }
            let next_revision = current
                .store_revision
                .checked_add(1)
                .ok_or(VendorStoreError::Integrity)?;
            if self.db.execute(
                "UPDATE vendor_current SET store_revision=store_revision+1 WHERE singleton=1 AND store_revision=? AND trust_sequence=? AND manifest_digest=? AND release_sequence=? AND release_digest=? AND lease_epoch=? AND actor_set_digest=? AND updater_tuple_digest=?",
                &[
                    SqlValue::Integer(to_i64(current.store_revision)?),
                    SqlValue::Integer(to_i64(current.trust_sequence)?),
                    SqlValue::Blob(&current.manifest_digest),
                    SqlValue::Integer(to_i64(current.release_sequence)?),
                    SqlValue::Blob(&current.release_digest),
                    SqlValue::Integer(to_i64(current.lease_epoch)?),
                    SqlValue::Blob(&current.actor_set_digest),
                    SqlValue::Blob(&current.updater_tuple_digest),
                ],
            )? != 1 {
                return Err(VendorStoreError::StaleCurrent);
            }
            if matches!(fault, StageFaultPoint::AfterRevision) {
                return Err(VendorStoreError::InjectedFault);
            }
            Ok(VendorStageResultV1 {
                revision: next_revision,
            })
        })();
        match result {
            Ok(value) => {
                let commit = if matches!(fault, StageFaultPoint::Commit) {
                    Err(RootStoreError::Sqlite("injected commit fault".to_string()))
                } else {
                    self.db.exec("COMMIT")
                };
                match commit {
                    Ok(()) => Ok(value),
                    Err(commit_error) => {
                        let _ = self.db.exec("ROLLBACK");
                        Err(VendorStoreError::CommitFailed(format!("{commit_error:?}")))
                    }
                }
            }
            Err(error) => {
                let _ = self.db.exec("ROLLBACK");
                Err(error)
            }
        }
    }

    /// Controlled staged-release activation: consumes the staged slot and
    /// installs it as the new current release inside one fail-closed
    /// transaction from the same family as stage (BEGIN IMMEDIATE,
    /// in-transaction re-read, full-snapshot CAS, best-effort rollback). The
    /// four activation hard gates are enforced here and, independently, by
    /// the schema triggers:
    /// 1. consume: the slot is deleted only after vendor_current already
    ///    holds the staged release (re-checked by vendor_staged_no_delete);
    /// 2. transition: the current row moves only in the exact activation
    ///    form (re-checked by vendor_current_transition);
    /// 3. epoch: lease_epoch advances by exactly 1 in the same transaction as
    ///    store_revision, and the seven actor rows follow to the newly
    ///    installed release tuple (only the refined actor triggers allow
    ///    that, and only because current just moved one generation ahead);
    /// 4. expiry: the full offer is re-verified from
    ///    vendor_staged_release.raw_bundle with the fresh activation wall
    ///    clock and the in-transaction current snapshot before any write;
    ///    staged metadata is never trusted on its own.
    pub(crate) fn activate(
        &mut self,
        expected: &ActivationExpectationV1,
        anchor: &PinnedVendorAnchorV1,
        observed_wall: &str,
    ) -> Result<ActivationResultV1, VendorStoreError> {
        self.db.exec("BEGIN IMMEDIATE")?;
        let result = (|| {
            // The activation UPDATE moves the vendor_current parent key while
            // the actor child rows still reference the previous generation;
            // the seven-row refresh follows within this same transaction.
            // Deferring foreign-key checking to COMMIT covers exactly this
            // window (the pragma reverts to its default when the transaction
            // ends), so every other path keeps immediate enforcement and any
            // leaked violation fails the COMMIT into the CommitFailed family.
            self.db.exec("PRAGMA defer_foreign_keys=ON")?;
            self.activate_body(expected, anchor, observed_wall)
        })();
        match result {
            Ok(value) => match self.db.exec("COMMIT") {
                Ok(()) => Ok(value),
                Err(commit_error) => {
                    let _ = self.db.exec("ROLLBACK");
                    Err(VendorStoreError::CommitFailed(format!("{commit_error:?}")))
                }
            },
            Err(error) => {
                let _ = self.db.exec("ROLLBACK");
                Err(error)
            }
        }
    }

    fn activate_body(
        &self,
        expected: &ActivationExpectationV1,
        anchor: &PinnedVendorAnchorV1,
        observed_wall: &str,
    ) -> Result<ActivationResultV1, VendorStoreError> {
        let current = read_current(&self.db)?;
        // Mandatory in-transaction recomputation of the signed actor-set
        // digest over the seven durable role rows, placed before the actor
        // checks: tampering with any role row must map to Integrity instead
        // of being silently ignored or disguised as a policy denial.
        if recompute_actor_set_digest(&self.db)? != current.actor_set_digest {
            return Err(VendorStoreError::Integrity);
        }
        // The same four actor checks as stage, against the pre-activation
        // generation: the live Updater authority is who authorizes the
        // hand-over.
        let actor = &expected.actor;
        if actor.role() != ActorRoleV1::Updater
            || actor.release_sequence() != current.release_sequence
            || actor.lease_epoch() != current.lease_epoch
        {
            return Err(VendorStoreError::ActorDenied);
        }
        if decode_hex_digest(actor.component_tuple_digest())? != current.updater_tuple_digest {
            return Err(VendorStoreError::ActorDenied);
        }
        // Full-snapshot CAS, exactly like stage: the caller must have
        // observed this exact durable row.
        if !expected.current.matches(&current) {
            return Err(VendorStoreError::StaleCurrent);
        }
        let staged = read_staged_offer(&self.db)?.ok_or(VendorStoreError::StagedSlotEmpty)?;
        // Hard gate 4: full re-verification from the staged raw bytes with
        // the fresh activation wall clock and the in-transaction current
        // snapshot. The raw bytes re-enter through the same carrier admission
        // gate as any offer (the base64 round trip is exact, so the store
        // verifies byte-for-byte what stage persisted).
        let carrier = URL_SAFE_NO_PAD.encode(&staged.raw_bundle);
        let owned =
            admit_vendor_offer_bundle(&carrier).map_err(VendorStoreError::StagedOfferRejected)?;
        let verified = verify_vendor_offer(
            owned,
            anchor,
            &VendorCurrentSnapshotV1::from_current(&current),
            observed_wall,
        )
        .map_err(VendorStoreError::StagedOfferRejected)?;
        // Coherence: the re-verified offer must be exactly the offer the
        // staged row claims to hold, and exactly the next generation. A
        // mismatch means the slot's metadata columns were tampered with
        // directly; the bytes win, the metadata loses, nothing changes.
        if staged.release_sequence
            != current
                .release_sequence
                .checked_add(1)
                .ok_or(VendorStoreError::Integrity)?
            || verified.release_sequence() != staged.release_sequence
            || verified.trust_sequence() != staged.trust_sequence
            || verified.manifest_digest() != &staged.manifest_digest
            || verified.release_object_digest() != &staged.release_digest
            || verified.bundle_digest() != &staged.bundle_digest
            || verified.actor_authorities().digest() != &staged.actor_set_digest
        {
            return Err(VendorStoreError::StaleStage);
        }
        let next_revision = current
            .store_revision
            .checked_add(1)
            .ok_or(VendorStoreError::Integrity)?;
        let next_epoch = current
            .lease_epoch
            .checked_add(1)
            .ok_or(VendorStoreError::Integrity)?;
        // Hard gate 2: the activation-form transition. The full old-value CAS
        // WHERE is the stage-family guard; vendor_current_transition
        // independently re-checks the whole staged-equality form.
        if self.db.execute(
            "UPDATE vendor_current SET store_revision=store_revision+1, trust_sequence=?, manifest_digest=?, release_sequence=release_sequence+1, release_digest=?, lease_epoch=lease_epoch+1, actor_set_digest=?, updater_tuple_digest=?, current_bundle=? WHERE singleton=1 AND store_revision=? AND trust_sequence=? AND manifest_digest=? AND release_sequence=? AND release_digest=? AND lease_epoch=? AND actor_set_digest=? AND updater_tuple_digest=?",
            &[
                SqlValue::Integer(to_i64(verified.trust_sequence())?),
                SqlValue::Blob(verified.manifest_digest()),
                SqlValue::Blob(verified.release_object_digest()),
                SqlValue::Blob(verified.actor_authorities().digest()),
                SqlValue::Blob(
                    verified
                        .actor_authorities()
                        .tuple(VendorActorRoleV1::Updater),
                ),
                SqlValue::Blob(&staged.raw_bundle),
                SqlValue::Integer(to_i64(current.store_revision)?),
                SqlValue::Integer(to_i64(current.trust_sequence)?),
                SqlValue::Blob(&current.manifest_digest),
                SqlValue::Integer(to_i64(current.release_sequence)?),
                SqlValue::Blob(&current.release_digest),
                SqlValue::Integer(to_i64(current.lease_epoch)?),
                SqlValue::Blob(&current.actor_set_digest),
                SqlValue::Blob(&current.updater_tuple_digest),
            ],
        )? != 1
        {
            return Err(VendorStoreError::StaleCurrent);
        }
        // Hard gate 3: authority hand-over. The seven role rows follow to the
        // newly installed generation; the refined actor triggers allow this
        // only because vendor_current just moved exactly one generation ahead
        // of them, i.e. only inside an activation transaction.
        for role in VendorActorRoleV1::ALL {
            if self.db.execute(
                "UPDATE vendor_actor_authorities SET tuple_digest=?, release_sequence=?, lease_epoch=? WHERE role=? AND release_sequence=? AND lease_epoch=?",
                &[
                    SqlValue::Blob(verified.actor_authorities().tuple(role)),
                    SqlValue::Integer(to_i64(verified.release_sequence())?),
                    SqlValue::Integer(to_i64(next_epoch)?),
                    SqlValue::Text(actor_role(role).as_str()),
                    SqlValue::Integer(to_i64(current.release_sequence)?),
                    SqlValue::Integer(to_i64(current.lease_epoch)?),
                ],
            )? != 1
            {
                return Err(VendorStoreError::Integrity);
            }
        }
        // Hard gate 1: consume the staged slot. vendor_staged_no_delete
        // independently re-checks that vendor_current now holds this exact
        // release before the row may go away.
        if self
            .db
            .execute("DELETE FROM vendor_staged_release WHERE singleton=1", &[])?
            != 1
        {
            return Err(VendorStoreError::Integrity);
        }
        // Post-refresh recompute: the durable actor table must now hash to
        // the newly installed actor-set digest before this transaction may
        // commit.
        if recompute_actor_set_digest(&self.db)? != *verified.actor_authorities().digest() {
            return Err(VendorStoreError::Integrity);
        }
        Ok(ActivationResultV1 {
            revision: next_revision,
            release_sequence: verified.release_sequence(),
            lease_epoch: next_epoch,
        })
    }

    #[cfg(test)]
    pub(crate) fn staged_count(&self) -> Result<u64, VendorStoreError> {
        staged_count(&self.db)
    }

    #[cfg(test)]
    pub(crate) fn actor_tuple(
        &self,
        role: VendorActorRoleV1,
    ) -> Result<[u8; 32], VendorStoreError> {
        read_actor_tuple(&self.db, role)
    }

    /// Test-only raw SQL channel over the store's own configured connection
    /// (recursive_triggers, foreign_keys, defensive mode all enabled). The
    /// REPLACE-bypass regression must run here: the recursive_triggers
    /// defense is connection-scoped, so a fresh unconfigured connection would
    /// not exercise it.
    #[cfg(test)]
    pub(crate) fn exec_raw_for_test(&self, sql: &str) -> Result<(), VendorStoreError> {
        self.db.exec(sql).map_err(VendorStoreError::Backend)
    }

    /// Test-only: rewrites a complete current store down to the exact legacy
    /// v1 schema (table texts, trigger texts, user_version=1), preserving
    /// every row, so migration tests exercise a faithful stage-era database
    /// instead of a hand-waved one.
    #[cfg(test)]
    pub(crate) fn downgrade_store_to_v1_for_test(path: &Path) -> Result<(), VendorStoreError> {
        let db = RootSqlite::open(path, false)?;
        db.exec("BEGIN EXCLUSIVE")?;
        let result = (|| {
            for (kind, name, _, _) in SCHEMA_OBJECTS {
                if *kind == "trigger" {
                    db.exec(&format!("DROP TRIGGER {name}"))?;
                }
            }
            recreate_tables_with_sql(
                &db,
                &[
                    ("vendor_current", LEGACY_CURRENT_SQL),
                    ("vendor_actor_authorities", LEGACY_ACTORS_SQL),
                    ("vendor_staged_release", LEGACY_STAGED_SQL),
                ],
            )?;
            for (kind, _, _, sql) in LEGACY_SCHEMA_OBJECTS {
                if *kind == "trigger" {
                    db.exec(sql)?;
                }
            }
            db.exec(&format!(
                "PRAGMA application_id={VENDOR_STORE_APPLICATION_ID}; PRAGMA user_version={LEGACY_VENDOR_STORE_SCHEMA_VERSION}"
            ))?;
            validate_schema_at(&db, LEGACY_VENDOR_STORE_SCHEMA_VERSION)?;
            Ok(())
        })();
        match result {
            Ok(()) => db.exec("COMMIT").map_err(Into::into),
            Err(error) => {
                let _ = db.exec("ROLLBACK");
                Err(error)
            }
        }
    }

    /// Test-only read-back of the persisted schema version.
    #[cfg(test)]
    pub(crate) fn stored_user_version_for_test(path: &Path) -> Result<i64, VendorStoreError> {
        let db = RootSqlite::open(path, false)?;
        db.query_i64("PRAGMA user_version", &[])
            .map_err(VendorStoreError::Backend)
    }
}

fn initialize_new_store(
    db: &RootSqlite,
    genesis: &VerifiedVendorGenesisV1,
) -> Result<(), VendorStoreError> {
    db.exec("BEGIN EXCLUSIVE")?;
    let result = (|| {
        db.exec(&format!("PRAGMA application_id={VENDOR_STORE_APPLICATION_ID}; PRAGMA user_version={VENDOR_STORE_SCHEMA_VERSION}"))?;
        for (_, _, _, sql) in SCHEMA_OBJECTS {
            db.exec(sql)?;
        }
        db.execute(
            "INSERT INTO vendor_current(singleton,schema_version,store_revision,trust_sequence,manifest_digest,release_sequence,release_digest,lease_epoch,actor_set_digest,updater_tuple_digest,current_bundle) VALUES(1,1,1,?,?,?,?,?,?,?,?)",
            &[
                SqlValue::Integer(to_i64(genesis.trust_sequence())?),
                SqlValue::Blob(genesis.manifest_digest()),
                SqlValue::Integer(to_i64(genesis.release_sequence())?),
                SqlValue::Blob(genesis.release_object_digest()),
                SqlValue::Integer(to_i64(GENESIS_LEASE_EPOCH)?),
                SqlValue::Blob(genesis.actor_authorities().digest()),
                SqlValue::Blob(genesis.actor_authorities().tuple(VendorActorRoleV1::Updater)),
                SqlValue::Blob(genesis.bundle_raw()),
            ],
        )?;
        for role in VendorActorRoleV1::ALL {
            db.execute(
                "INSERT INTO vendor_actor_authorities(role,tuple_digest,release_sequence,lease_epoch) VALUES(?,?,?,?)",
                &[
                    SqlValue::Text(actor_role(role).as_str()),
                    SqlValue::Blob(genesis.actor_authorities().tuple(role)),
                    SqlValue::Integer(to_i64(genesis.release_sequence())?),
                    SqlValue::Integer(to_i64(GENESIS_LEASE_EPOCH)?),
                ],
            )?;
        }
        validate_schema(db)?;
        Ok(())
    })();
    match result {
        Ok(()) => db.exec("COMMIT").map_err(Into::into),
        Err(error) => {
            let _ = db.exec("ROLLBACK");
            Err(error)
        }
    }
}

/// In-place migration of an already validated legacy v1 store to the current
/// schema: rebuild the three tables with the current DDL texts (every row is
/// carried over verbatim), replace the stage-period trigger bodies with the
/// refined activation-era contracts, bump user_version, and revalidate the
/// full v2 manifest. Everything happens inside one exclusive transaction, so
/// any failure rolls the legacy store back untouched.
fn migrate_legacy_v1_store(db: &RootSqlite) -> Result<(), VendorStoreError> {
    db.exec("BEGIN EXCLUSIVE")?;
    let result = (|| {
        for (kind, name, _, _) in SCHEMA_OBJECTS {
            if *kind == "trigger" {
                db.exec(&format!("DROP TRIGGER {name}"))?;
            }
        }
        recreate_tables_with_sql(
            db,
            &[
                ("vendor_current", CURRENT_SQL),
                ("vendor_actor_authorities", ACTORS_SQL),
                ("vendor_staged_release", STAGED_SQL),
            ],
        )?;
        for (kind, _, _, sql) in SCHEMA_OBJECTS {
            if *kind == "trigger" {
                db.exec(sql)?;
            }
        }
        db.exec(&format!("PRAGMA application_id={VENDOR_STORE_APPLICATION_ID}; PRAGMA user_version={VENDOR_STORE_SCHEMA_VERSION}"))?;
        validate_schema(db)?;
        Ok(())
    })();
    match result {
        Ok(()) => db.exec("COMMIT").map_err(Into::into),
        Err(error) => {
            let _ = db.exec("ROLLBACK");
            Err(error)
        }
    }
}

/// Rebuilds the three vendor tables with the given DDL texts, carrying every
/// row over verbatim through AS-SELECT backup tables. Drops run child-first
/// (actor rows reference vendor_current under an immediate foreign key, so
/// the parent may only be dropped once unreferenced), creates run
/// parent-first, and the backups are removed before the caller revalidates
/// the schema manifest.
fn recreate_tables_with_sql(
    db: &RootSqlite,
    tables: &[(&str, &str)],
) -> Result<(), VendorStoreError> {
    for (name, _) in tables.iter().rev() {
        db.exec(&format!(
            "CREATE TABLE schema_migration_backup_{name} AS SELECT * FROM {name}"
        ))?;
    }
    for (name, _) in tables.iter().rev() {
        db.exec(&format!("DROP TABLE {name}"))?;
    }
    for (name, sql) in tables {
        db.exec(sql)?;
        db.exec(&format!(
            "INSERT INTO {name} SELECT * FROM schema_migration_backup_{name}"
        ))?;
    }
    for (name, _) in tables {
        db.exec(&format!("DROP TABLE schema_migration_backup_{name}"))?;
    }
    Ok(())
}

fn validate_schema(db: &RootSqlite) -> Result<(), VendorStoreError> {
    validate_schema_at(db, VENDOR_STORE_SCHEMA_VERSION)
}

fn validate_schema_at(db: &RootSqlite, version: i64) -> Result<(), VendorStoreError> {
    if db.query_i64("PRAGMA application_id", &[])? != VENDOR_STORE_APPLICATION_ID
        || db.query_i64("PRAGMA user_version", &[])? != version
    {
        return Err(VendorStoreError::Integrity);
    }
    let expected_objects: &[(&str, &str, &str, &str)] = match version {
        VENDOR_STORE_SCHEMA_VERSION => SCHEMA_OBJECTS,
        LEGACY_VENDOR_STORE_SCHEMA_VERSION => LEGACY_SCHEMA_OBJECTS,
        _ => return Err(VendorStoreError::Integrity),
    };
    let mut statement = db.prepare("SELECT type,name,tbl_name,sql FROM sqlite_schema WHERE name NOT LIKE 'sqlite_%' ORDER BY type,name")?;
    let mut actual = Vec::new();
    loop {
        match statement.step()? {
            sqlite::SQLITE_ROW => actual.push((
                statement.column_text(0)?,
                statement.column_text(1)?,
                statement.column_text(2)?,
                statement.column_text(3)?,
            )),
            sqlite::SQLITE_DONE => break,
            _ => unreachable!("SQLite statement step is bounded to ROW or DONE"),
        }
    }
    let mut expected = expected_objects
        .iter()
        .map(|(kind, name, table, sql)| {
            (
                (*kind).to_string(),
                (*name).to_string(),
                (*table).to_string(),
                (*sql).to_string(),
            )
        })
        .collect::<Vec<_>>();
    expected.sort();
    if actual != expected {
        return Err(VendorStoreError::Integrity);
    }
    Ok(())
}

fn read_current(db: &RootSqlite) -> Result<CurrentRow, VendorStoreError> {
    let mut statement = db.prepare("SELECT store_revision,trust_sequence,manifest_digest,release_sequence,release_digest,lease_epoch,actor_set_digest,updater_tuple_digest FROM vendor_current WHERE singleton=1")?;
    if statement.step()? != sqlite::SQLITE_ROW {
        return Err(VendorStoreError::Integrity);
    }
    Ok(CurrentRow {
        store_revision: to_u64(statement.column_i64(0))?,
        trust_sequence: to_u64(statement.column_i64(1))?,
        manifest_digest: digest(statement.column_blob(2)?)?,
        release_sequence: to_u64(statement.column_i64(3))?,
        release_digest: digest(statement.column_blob(4)?)?,
        lease_epoch: to_u64(statement.column_i64(5))?,
        actor_set_digest: digest(statement.column_blob(6)?)?,
        updater_tuple_digest: digest(statement.column_blob(7)?)?,
    })
}

fn read_actor_tuple(
    db: &RootSqlite,
    role: VendorActorRoleV1,
) -> Result<[u8; 32], VendorStoreError> {
    let mut statement =
        db.prepare("SELECT tuple_digest FROM vendor_actor_authorities WHERE role=?")?;
    statement.bind(&[SqlValue::Text(actor_role(role).as_str())])?;
    if statement.step()? != sqlite::SQLITE_ROW {
        return Err(VendorStoreError::Integrity);
    }
    digest(statement.column_blob(0)?)
}

/// Recomputes the domain-separated actor-set digest over the seven durable
/// role rows, isomorphic to parse_actor_authorities in vendor_release.
fn recompute_actor_set_digest(db: &RootSqlite) -> Result<[u8; DIGEST_BYTES], VendorStoreError> {
    let mut hasher = Sha256::new();
    hasher.update(ACTOR_AUTHORITY_SET_DOMAIN);
    hasher.update([VendorActorRoleV1::ALL.len() as u8]);
    for role in VendorActorRoleV1::ALL {
        let tuple = read_actor_tuple(db, role)?;
        hasher.update([role as u8]);
        hasher.update(tuple);
    }
    Ok(hasher.finalize().into())
}

struct StagedSlotRow {
    operation_id: String,
    bundle_digest: [u8; DIGEST_BYTES],
}

fn read_staged_slot(db: &RootSqlite) -> Result<Option<StagedSlotRow>, VendorStoreError> {
    let mut statement = db.prepare(
        "SELECT operation_id,bundle_digest FROM vendor_staged_release WHERE singleton=1",
    )?;
    match statement.step()? {
        sqlite::SQLITE_ROW => Ok(Some(StagedSlotRow {
            operation_id: statement.column_text(0)?,
            bundle_digest: digest(statement.column_blob(1)?)?,
        })),
        sqlite::SQLITE_DONE => Ok(None),
        _ => unreachable!("SQLite statement step is bounded to ROW or DONE"),
    }
}

/// The full pending-offer row as seen by the activation transaction: the
/// metadata columns it claims, plus the raw bundle bytes that alone decide
/// whether those claims are true.
struct StagedOfferRow {
    trust_sequence: u64,
    manifest_digest: [u8; DIGEST_BYTES],
    release_sequence: u64,
    release_digest: [u8; DIGEST_BYTES],
    bundle_digest: [u8; DIGEST_BYTES],
    actor_set_digest: [u8; DIGEST_BYTES],
    raw_bundle: Vec<u8>,
}

fn read_staged_offer(db: &RootSqlite) -> Result<Option<StagedOfferRow>, VendorStoreError> {
    let mut statement = db.prepare(
        "SELECT trust_sequence,manifest_digest,release_sequence,release_digest,bundle_digest,actor_set_digest,raw_bundle FROM vendor_staged_release WHERE singleton=1",
    )?;
    match statement.step()? {
        sqlite::SQLITE_ROW => Ok(Some(StagedOfferRow {
            trust_sequence: to_u64(statement.column_i64(0))?,
            manifest_digest: digest(statement.column_blob(1)?)?,
            release_sequence: to_u64(statement.column_i64(2))?,
            release_digest: digest(statement.column_blob(3)?)?,
            bundle_digest: digest(statement.column_blob(4)?)?,
            actor_set_digest: digest(statement.column_blob(5)?)?,
            raw_bundle: statement.column_blob(6)?,
        })),
        sqlite::SQLITE_DONE => Ok(None),
        _ => unreachable!("SQLite statement step is bounded to ROW or DONE"),
    }
}

fn staged_count(db: &RootSqlite) -> Result<u64, VendorStoreError> {
    to_u64(db.query_i64("SELECT COUNT(*) FROM vendor_staged_release", &[])?)
}

fn actor_role(role: VendorActorRoleV1) -> ActorRoleV1 {
    match role {
        VendorActorRoleV1::Gateway => ActorRoleV1::Gateway,
        VendorActorRoleV1::Main => ActorRoleV1::Main,
        VendorActorRoleV1::Renderer => ActorRoleV1::Renderer,
        VendorActorRoleV1::ModelBroker => ActorRoleV1::ModelBroker,
        VendorActorRoleV1::NetworkBroker => ActorRoleV1::NetworkBroker,
        VendorActorRoleV1::CurrentStateBroker => ActorRoleV1::CurrentStateBroker,
        VendorActorRoleV1::Updater => ActorRoleV1::Updater,
    }
}

fn decode_hex_digest(value: &str) -> Result<[u8; DIGEST_BYTES], VendorStoreError> {
    if value.len() != DIGEST_BYTES * 2 {
        return Err(VendorStoreError::ActorIdentityMalformed);
    }
    let mut decoded = [0_u8; DIGEST_BYTES];
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        decoded[index] = (hex_nibble(pair[0])? << 4) | hex_nibble(pair[1])?;
    }
    Ok(decoded)
}

fn hex_nibble(value: u8) -> Result<u8, VendorStoreError> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        _ => Err(VendorStoreError::ActorIdentityMalformed),
    }
}

fn digest(value: Vec<u8>) -> Result<[u8; DIGEST_BYTES], VendorStoreError> {
    value.try_into().map_err(|_| VendorStoreError::Integrity)
}

fn to_i64(value: u64) -> Result<i64, VendorStoreError> {
    i64::try_from(value).map_err(|_| VendorStoreError::Integrity)
}

fn to_u64(value: i64) -> Result<u64, VendorStoreError> {
    u64::try_from(value).map_err(|_| VendorStoreError::Integrity)
}

/// Upper bound for how long the classification probe waits out a transient
/// SQLITE_BUSY (hot journal replay, a concurrent writer) before giving up.
/// Same magnitude as the durable store's configure() busy timeout.
const VENDOR_PROBE_BUSY_TIMEOUT_MS: i32 = 2_000;

fn classify_existing_file(path: &Path) -> Result<ExistingFileDisposition, VendorStoreError> {
    let (disposition, probe_failed) = classify_existing_file_once(path)?;
    if !probe_failed {
        return Ok(disposition);
    }
    // A transient SQLITE_BUSY between open and the first PRAGMA can make a
    // healthy file look unreadable. The probe connection already waits out
    // short holders (VENDOR_PROBE_BUSY_TIMEOUT_MS); one bounded re-probe
    // covers the residual window. Genuinely corrupt files keep failing the
    // probe and land in exactly the same branches again, so fail-closed
    // semantics and all dispositions are unchanged.
    let (retried, _) = classify_existing_file_once(path)?;
    Ok(retried)
}

fn classify_existing_file_once(
    path: &Path,
) -> Result<(ExistingFileDisposition, bool), VendorStoreError> {
    let db = RootSqlite::open(path, false)?;
    // RootSqlite::open is lazy: without this, the probe connection has the
    // SQLite default busy timeout of zero, so any transient holder turns a
    // healthy store into a spurious Corrupt (magic present) or Corpse
    // (magic absent) classification.
    db.set_busy_timeout_ms(VENDOR_PROBE_BUSY_TIMEOUT_MS);
    let probe: Result<(i64, i64), RootStoreError> = (|| {
        let application_id = db.query_i64("PRAGMA application_id", &[])?;
        let user_version = db.query_i64("PRAGMA user_version", &[])?;
        Ok((application_id, user_version))
    })();
    let probe_failed = probe.is_err();
    let disposition = match probe {
        // A first-PRAGMA failure on a file that does not even carry the
        // SQLite magic is a garbage file, not a store: safe to treat as a
        // genesis corpse. A probe failure on a real SQLite file is unknown
        // territory (locked, I/O error, ...) and fails closed instead.
        Err(_) if !has_sqlite_file_magic(path) => ExistingFileDisposition::Corpse,
        Err(_) => ExistingFileDisposition::Corrupt,
        // A foreign application id means this was never one of our stores:
        // safe to treat as a corpse.
        Ok((application_id, _)) if application_id != VENDOR_STORE_APPLICATION_ID => {
            ExistingFileDisposition::Corpse
        }
        Ok((_, user_version)) if user_version == VENDOR_STORE_SCHEMA_VERSION => {
            if validate_schema_at(&db, VENDOR_STORE_SCHEMA_VERSION).is_ok() {
                ExistingFileDisposition::Complete
            } else {
                ExistingFileDisposition::Corrupt
            }
        }
        Ok((_, user_version)) if user_version == LEGACY_VENDOR_STORE_SCHEMA_VERSION => {
            if validate_schema_at(&db, LEGACY_VENDOR_STORE_SCHEMA_VERSION).is_ok() {
                ExistingFileDisposition::Legacy
            } else {
                ExistingFileDisposition::Corrupt
            }
        }
        // A file that carries our application id but an unknown schema
        // version belongs to our store family and is never rebuilt: fail
        // closed (migrate-or-rebuild policy: rebuild applies only to files
        // whose store identity never committed).
        Ok(_) => ExistingFileDisposition::Corrupt,
    };
    drop(db);
    Ok((disposition, probe_failed))
}

fn has_sqlite_file_magic(path: &Path) -> bool {
    use std::io::Read;
    let mut magic = [0_u8; 16];
    fs::File::open(path)
        .and_then(|mut file| file.read_exact(&mut magic))
        .is_ok()
        && magic == *b"SQLite format 3\0"
}

/// Removes a genesis corpse database together with its rollback journal. Any
/// removal failure other than a missing file fails closed.
fn remove_corpse_files(db_path: &Path) -> Result<(), VendorStoreError> {
    let mut journal_name = db_path.as_os_str().to_os_string();
    journal_name.push("-journal");
    for path in [db_path.to_path_buf(), PathBuf::from(journal_name)] {
        match fs::remove_file(&path) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(RootStoreError::InvalidRoot(format!(
                    "cannot remove genesis corpse file {}: {error}",
                    path.display()
                ))
                .into());
            }
        }
    }
    Ok(())
}
