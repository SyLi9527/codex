// Test assertions express failure by panicking by design, while the workspace
// denies unwrap/expect globally; this module carries a scoped allowance.
#![allow(clippy::expect_used, clippy::unwrap_used)]

use super::root_protocol::ActorRoleV1;
use super::root_protocol::AuthenticatedActorSnapshotV1;
use super::root_protocol::AuthorizedVerifiedVendorOfferV1;
use super::root_protocol::admit_root_command;
use super::root_sqlite::RootSqlite;
use super::root_sqlite::SqlValue;
use super::root_sqlite::mutate_store_for_test;
use super::vendor_authority_store::ActivationExpectationV1;
use super::vendor_authority_store::GENESIS_LEASE_EPOCH;
use super::vendor_authority_store::StageFaultPoint;
use super::vendor_authority_store::VendorAuthorityRootStore;
use super::vendor_authority_store::VendorCurrentSnapshotV1;
use super::vendor_authority_store::VendorStoreError;
use super::vendor_release::PinnedVendorAnchorV1;
use super::vendor_release::VendorActorRoleV1;
use super::vendor_release::admit_vendor_offer_bundle;
use super::vendor_release::verify_vendor_genesis;
use super::vendor_release::verify_vendor_offer;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use sha2::Digest;
use sha2::Sha256;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::sync::Arc;
use std::sync::Barrier;
use std::sync::mpsc;
use std::thread;
use tempfile::TempDir;

const NOW: &str = "2026-08-28T12:00:00Z";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct SnapshotData {
    store_revision: u64,
    trust_sequence: u64,
    manifest_digest: [u8; 32],
    release_sequence: u64,
    release_digest: [u8; 32],
    lease_epoch: u64,
    actor_set_digest: [u8; 32],
    updater_tuple_digest: [u8; 32],
}

impl SnapshotData {
    fn snapshot(self) -> VendorCurrentSnapshotV1 {
        VendorCurrentSnapshotV1::new_for_test(
            self.store_revision,
            self.trust_sequence,
            self.manifest_digest,
            self.release_sequence,
            self.release_digest,
            self.lease_epoch,
            self.actor_set_digest,
            self.updater_tuple_digest,
        )
    }

    fn with_revision(self, store_revision: u64) -> Self {
        Self {
            store_revision,
            ..self
        }
    }

    fn with_release_digest(self, release_digest: [u8; 32]) -> Self {
        Self {
            release_digest,
            ..self
        }
    }
}

#[test]
fn verified_genesis_is_the_only_source_of_current_rows() {
    let root = private_tempdir();
    let verified_genesis = genesis();
    let expected_manifest = *verified_genesis.manifest_digest();
    let expected_release = *verified_genesis.release_object_digest();
    let expected_actor_set = *verified_genesis.actor_authorities().digest();
    let mut expected_actors = Vec::new();
    for role in VendorActorRoleV1::ALL {
        expected_actors.push((role, *verified_genesis.actor_authorities().tuple(role)));
    }

    let store = VendorAuthorityRootStore::create_new(root.path(), verified_genesis).unwrap();
    let snapshot = store.snapshot().unwrap();
    assert_eq!(snapshot.store_revision(), 1);
    assert_eq!(snapshot.trust_sequence(), 1);
    assert_eq!(snapshot.manifest_digest(), &expected_manifest);
    assert_eq!(snapshot.release_sequence(), 1);
    assert_eq!(snapshot.release_digest(), &expected_release);
    assert_eq!(snapshot.lease_epoch(), GENESIS_LEASE_EPOCH);
    assert_eq!(snapshot.lease_epoch(), 1);
    assert_eq!(snapshot.actor_set_digest(), &expected_actor_set);
    for (role, expected) in expected_actors {
        assert_eq!(store.actor_tuple(role).unwrap(), expected);
    }
    assert_eq!(store.path(), root.path().join("vendor-authority.db"));

    drop(store);
    assert_eq!(
        VendorAuthorityRootStore::create_new(root.path(), genesis()).err(),
        Some(VendorStoreError::AlreadyExists)
    );
}

#[test]
fn genesis_is_deterministic_across_stores_and_independent_of_vendor_bytes() {
    // 同一 verified genesis 双 store：全部 durable 字段逐一相等。
    let first_root = private_tempdir();
    let second_root = private_tempdir();
    let first = VendorAuthorityRootStore::create_new(first_root.path(), genesis()).unwrap();
    let second = VendorAuthorityRootStore::create_new(second_root.path(), genesis()).unwrap();
    let first_data = snapshot_data(&first);
    assert_eq!(first_data, snapshot_data(&second));
    for role in VendorActorRoleV1::ALL {
        assert_eq!(
            first.actor_tuple(role).unwrap(),
            second.actor_tuple(role).unwrap()
        );
    }
    assert_eq!(first_data.lease_epoch, GENESIS_LEASE_EPOCH);
    assert_eq!(first_data.store_revision, 1);
    drop(first);
    drop(second);

    // lease_epoch 不由 vendor 字节派生：内容不同的有效 genesis 仍然初始化为 1。
    let alternate_genesis = verify_vendor_genesis(
        admit_vendor_offer_bundle(
            &super::vendor_release_tests::alternate_genesis_carrier_fixture(),
        )
        .unwrap(),
        &PinnedVendorAnchorV1::for_test_fixture(),
        NOW,
    )
    .unwrap();
    let alternate_root = private_tempdir();
    let alternate_store =
        VendorAuthorityRootStore::create_new(alternate_root.path(), alternate_genesis).unwrap();
    let alternate_data = snapshot_data(&alternate_store);
    assert_eq!(alternate_data.lease_epoch, GENESIS_LEASE_EPOCH);
    assert_eq!(alternate_data.store_revision, 1);
    // manifest 内容不依赖 content_byte，两个 genesis 的 manifest_digest 相同；
    // release body 与 actor tuples 必须不同。
    assert_eq!(alternate_data.manifest_digest, first_data.manifest_digest);
    assert_ne!(alternate_data.release_digest, first_data.release_digest);
    assert_ne!(alternate_data.actor_set_digest, first_data.actor_set_digest);
}

#[test]
fn stage_exactly_cas_checks_current_identity_and_never_changes_current_actors() {
    let cases = [
        (2, 1, [17; 32], 1, VendorStoreError::StaleCurrent),
        (1, 2, [17; 32], 1, VendorStoreError::ActorDenied),
        (1, 1, [18; 32], 1, VendorStoreError::ActorDenied),
        (1, 1, [17; 32], 2, VendorStoreError::RevisionMismatch),
    ];
    for (snapshot_revision, actor_epoch, actor_tuple, expected_revision, expected_error) in cases {
        let root = private_tempdir();
        let (mut store, data) = store_and_snapshot(&root);
        let authorized = verified_offer(
            data.with_revision(snapshot_revision),
            actor_tuple,
            data.release_sequence,
            actor_epoch,
            expected_revision,
        );
        assert_eq!(store.stage(authorized).err(), Some(expected_error));
        assert_eq!(store.staged_count().unwrap(), 0);
        assert_eq!(snapshot_data(&store), data);
    }

    let root = private_tempdir();
    let (mut store, data) = store_and_snapshot(&root);
    let current_actors = VendorActorRoleV1::ALL.map(|role| store.actor_tuple(role).unwrap());
    let result = store
        .stage(verified_offer(data, data.updater_tuple_digest, 1, 1, 1))
        .unwrap();
    assert_eq!(result.revision, 2);
    assert_eq!(store.staged_count().unwrap(), 1);
    assert_eq!(snapshot_data(&store), data.with_revision(2));
    for (index, role) in VendorActorRoleV1::ALL.into_iter().enumerate() {
        assert_eq!(store.actor_tuple(role).unwrap(), current_actors[index]);
    }
    assert_eq!(
        store.actor_tuple(VendorActorRoleV1::Updater).unwrap(),
        [17; 32],
        "the candidate's signed updater tuple must not become current at stage"
    );
}

#[test]
fn wrong_release_digest_is_rejected_with_zero_state_change() {
    let root = private_tempdir();
    let (mut store, data) = store_and_snapshot(&root);
    // 自洽伪造世界：snapshot 声称一个不同的 release_digest，且 bundle 有效签名
    // 并链接到同一 digest——verify 因此通过，stage 必须以 durable 行为准拒绝，
    // 并保持完全零状态变化。
    let fabricated = data.with_release_digest([77_u8; 32]);
    let authorized = verified_offer(fabricated, fabricated.updater_tuple_digest, 1, 1, 1);
    assert_eq!(
        store.stage(authorized).err(),
        Some(VendorStoreError::StaleCurrent)
    );
    assert_eq!(store.staged_count().unwrap(), 0);
    assert_eq!(snapshot_data(&store), data);
}

#[test]
fn ack_loss_replay_is_idempotent_with_zero_state_change() {
    let root = private_tempdir();
    let (mut store, data) = store_and_snapshot(&root);
    let first = store
        .stage(verified_offer(data, data.updater_tuple_digest, 1, 1, 1))
        .unwrap();
    assert_eq!(first.revision, 2);

    // 形态一：重放方重读新鲜 snapshot（revision 已是 2）。
    let fresh = snapshot_data(&store);
    let replay_fresh = verified_offer(fresh, fresh.updater_tuple_digest, 1, 1, 1);
    assert_eq!(store.stage(replay_fresh).unwrap().revision, 2);

    // 形态二：懒惰重试，携带 stage 之前的 stale snapshot 与原 expected_revision。
    let replay_stale = verified_offer(data, data.updater_tuple_digest, 1, 1, 1);
    assert_eq!(store.stage(replay_stale).unwrap().revision, 2);

    assert_eq!(snapshot_data(&store), fresh);
    assert_eq!(store.staged_count().unwrap(), 1);
}

#[test]
fn staged_slot_conflicts_are_two_distinct_classes() {
    let root = private_tempdir();
    let (mut store, data) = store_and_snapshot(&root);
    store
        .stage(verified_offer(data, data.updater_tuple_digest, 1, 1, 1))
        .unwrap();

    // 同 operation_id、异 bundle bytes：operation id 复用必须冲突。
    let alternate_payload =
        super::vendor_release_tests::alternate_next_carrier_fixture(data.release_digest);
    let reused = verified_offer_with_payload(
        "vendor-operation-1",
        data,
        hex_bytes(&data.updater_tuple_digest),
        1,
        1,
        1,
        &alternate_payload,
    );
    assert_eq!(
        store.stage(reused).err(),
        Some(VendorStoreError::StagedOperationMismatch)
    );

    // 异 operation_id：唯一 slot 被其他 operation 占用必须冲突。
    let replay = verified_offer_with_payload(
        "vendor-operation-2",
        data,
        hex_bytes(&data.updater_tuple_digest),
        1,
        1,
        1,
        &super::vendor_release_tests::next_carrier_fixture(data.release_digest),
    );
    assert_eq!(
        store.stage(replay).err(),
        Some(VendorStoreError::StagedSlotOccupied)
    );

    assert_eq!(snapshot_data(&store), data.with_revision(2));
    assert_eq!(store.staged_count().unwrap(), 1);
}

#[test]
fn one_hundred_ack_loss_replays_yield_exactly_one_transition() {
    let root = private_tempdir();
    let (mut store, data) = store_and_snapshot(&root);
    let barrier = Arc::new(Barrier::new(101));
    let (sender, receiver) = mpsc::sync_channel::<AuthorizedVerifiedVendorOfferV1>(128);
    let mut workers = Vec::new();
    for _ in 0..100 {
        let barrier = Arc::clone(&barrier);
        let sender = sender.clone();
        workers.push(thread::spawn(move || {
            barrier.wait();
            sender
                .send(verified_offer(data, data.updater_tuple_digest, 1, 1, 1))
                .unwrap();
        }));
    }
    drop(sender);
    barrier.wait();

    let mut replays = 0;
    for authorized in receiver {
        let result = store.stage(authorized).unwrap();
        assert_eq!(result.revision, 2);
        replays += 1;
    }
    for worker in workers {
        worker.join().unwrap();
    }
    assert_eq!(replays, 100);
    assert_eq!(store.staged_count().unwrap(), 1);
    assert_eq!(snapshot_data(&store), data.with_revision(2));
}

#[test]
fn one_hundred_distinct_operations_conflict_with_zero_state_change() {
    let root = private_tempdir();
    let (mut store, data) = store_and_snapshot(&root);
    let barrier = Arc::new(Barrier::new(101));
    let (sender, receiver) = mpsc::sync_channel::<AuthorizedVerifiedVendorOfferV1>(128);
    let mut workers = Vec::new();
    for index in 0..100 {
        let barrier = Arc::clone(&barrier);
        let sender = sender.clone();
        workers.push(thread::spawn(move || {
            barrier.wait();
            let payload = super::vendor_release_tests::next_carrier_fixture(data.release_digest);
            let tuple = hex_bytes(&data.updater_tuple_digest);
            sender
                .send(verified_offer_with_payload(
                    &format!("vendor-operation-{index}"),
                    data,
                    tuple,
                    1,
                    1,
                    1,
                    &payload,
                ))
                .unwrap();
        }));
    }
    drop(sender);
    barrier.wait();

    let mut staged = 0;
    let mut occupied = 0;
    for authorized in receiver {
        match store.stage(authorized) {
            Ok(result) => {
                assert_eq!(result.revision, 2);
                staged += 1;
            }
            Err(VendorStoreError::StagedSlotOccupied) => occupied += 1,
            Err(error) => panic!("unexpected distinct-op stage result: {error:?}"),
        }
    }
    for worker in workers {
        worker.join().unwrap();
    }
    assert_eq!((staged, occupied), (1, 99));
    assert_eq!(store.staged_count().unwrap(), 1);
    assert_eq!(snapshot_data(&store), data.with_revision(2));
}

#[test]
fn every_stage_fault_rolls_back_candidate_and_revision_and_keeps_store_usable() {
    for fault in [
        StageFaultPoint::BeforeInsert,
        StageFaultPoint::AfterInsert,
        StageFaultPoint::AfterRevision,
        StageFaultPoint::Commit,
    ] {
        let root = private_tempdir();
        let (mut store, data) = store_and_snapshot(&root);
        let error = store
            .stage_with_fault(
                verified_offer(data, data.updater_tuple_digest, 1, 1, 1),
                fault,
            )
            .err();
        if matches!(fault, StageFaultPoint::Commit) {
            assert!(
                matches!(error, Some(VendorStoreError::CommitFailed(_))),
                "commit fault must surface as CommitFailed: {error:?}"
            );
        } else {
            assert_eq!(error, Some(VendorStoreError::InjectedFault));
        }
        assert_eq!(store.staged_count().unwrap(), 0);
        assert_eq!(snapshot_data(&store), data);
        // store 仍可用：同 operation_id + 同 bytes 正常重 stage 成功。
        let result = store
            .stage(verified_offer(data, data.updater_tuple_digest, 1, 1, 1))
            .unwrap();
        assert_eq!(result.revision, 2);
    }
}

#[test]
fn insert_or_replace_cannot_bypass_any_immutability_trigger() {
    let root = private_tempdir();
    let (mut store, data) = store_and_snapshot(&root);
    store
        .stage(verified_offer(data, data.updater_tuple_digest, 1, 1, 1))
        .unwrap();

    let zero_blob = format!("x'{}'", "00".repeat(32));
    let subject = "a".repeat(64);
    let attempts = [
        "INSERT OR REPLACE INTO vendor_actor_authorities(role,tuple_digest,release_sequence,lease_epoch) VALUES('updater',x'22',1,1)".to_string(),
        format!("INSERT OR REPLACE INTO vendor_current(singleton,schema_version,store_revision,trust_sequence,manifest_digest,release_sequence,release_digest,lease_epoch,actor_set_digest,updater_tuple_digest,current_bundle) VALUES(1,1,999,1,{zero_blob},1,{zero_blob},1,{zero_blob},{zero_blob},{zero_blob})"),
        format!("INSERT OR REPLACE INTO vendor_staged_release(singleton,operation_id,subject_digest,payload_digest,base_revision,trust_sequence,manifest_digest,release_sequence,release_digest,bundle_digest,actor_set_digest,raw_bundle) VALUES(1,'replaced-operation',{subject},{subject},1,1,{zero_blob},2,{zero_blob},{zero_blob},{zero_blob},x'00')"),
    ];
    for sql in &attempts {
        assert!(
            store.exec_raw_for_test(sql).is_err(),
            "INSERT OR REPLACE must be rejected by the store connection: {sql}"
        );
    }
    assert_eq!(snapshot_data(&store), data.with_revision(2));
    assert_eq!(store.staged_count().unwrap(), 1);
    assert_eq!(
        store.actor_tuple(VendorActorRoleV1::Updater).unwrap(),
        data.updater_tuple_digest
    );
}

#[test]
fn schema_triggers_and_foreign_keys_reject_direct_mutations() {
    let root = private_tempdir();
    let (store, data) = store_and_snapshot(&root);
    let zero_blob = format!("x'{}'", "00".repeat(32));
    let violations = vec![
        "UPDATE vendor_current SET store_revision=3 WHERE singleton=1".to_string(),
        "UPDATE vendor_current SET trust_sequence=2 WHERE singleton=1".to_string(),
        "UPDATE vendor_current SET trust_sequence=2, store_revision=store_revision+1 WHERE singleton=1".to_string(),
        format!("UPDATE vendor_current SET manifest_digest={zero_blob} WHERE singleton=1"),
        "UPDATE vendor_current SET release_sequence=2 WHERE singleton=1".to_string(),
        format!("UPDATE vendor_current SET release_digest={zero_blob} WHERE singleton=1"),
        "UPDATE vendor_current SET lease_epoch=2 WHERE singleton=1".to_string(),
        "UPDATE vendor_current SET lease_epoch=2, store_revision=store_revision+1 WHERE singleton=1".to_string(),
        format!("UPDATE vendor_current SET actor_set_digest={zero_blob} WHERE singleton=1"),
        format!("UPDATE vendor_current SET updater_tuple_digest={zero_blob} WHERE singleton=1"),
        "UPDATE vendor_current SET current_bundle=x'00' WHERE singleton=1".to_string(),
        "DELETE FROM vendor_current".to_string(),
        "UPDATE vendor_actor_authorities SET tuple_digest=x'22' WHERE role='updater'".to_string(),
        "DELETE FROM vendor_actor_authorities".to_string(),
    ];
    for sql in &violations {
        assert!(
            store.exec_raw_for_test(sql).is_err(),
            "mutation must be rejected: {sql}"
        );
    }
    assert_eq!(snapshot_data(&store), data);

    // 唯一 staged slot 不可变：先占槽，再试 UPDATE/DELETE。
    let mut store = store;
    store
        .stage(verified_offer(data, data.updater_tuple_digest, 1, 1, 1))
        .unwrap();
    assert!(
        store
            .exec_raw_for_test(
                "UPDATE vendor_staged_release SET operation_id='x' WHERE singleton=1"
            )
            .is_err()
    );
    assert!(
        store
            .exec_raw_for_test("DELETE FROM vendor_staged_release")
            .is_err()
    );
    assert_eq!(store.staged_count().unwrap(), 1);

    // 外键：actor 子行只能指向当前 (release_sequence, lease_epoch)。
    mutate_store_for_test(store.path(), "DROP TRIGGER vendor_actors_no_delete").unwrap();
    store
        .exec_raw_for_test("DELETE FROM vendor_actor_authorities WHERE role='main'")
        .unwrap();
    let orphan = format!(
        "INSERT INTO vendor_actor_authorities(role,tuple_digest,release_sequence,lease_epoch) VALUES('main',{zero_blob},2,2)"
    );
    assert!(
        store.exec_raw_for_test(&orphan).is_err(),
        "FK must reject a non-current generation: {orphan}"
    );
    assert_eq!(store.snapshot().unwrap().store_revision(), 2);
}

#[test]
fn actor_row_tampering_is_caught_by_recomputed_digest_before_actor_checks() {
    // 'main'：若无"重算先于四检"会被静默放过；'updater'：若无则会被伪装成
    // ActorDenied。两例都必须是 Integrity 且零状态变化。
    for role in ["main", "updater"] {
        let root = private_tempdir();
        let (mut store, data) = store_and_snapshot(&root);
        mutate_store_for_test(store.path(), "DROP TRIGGER vendor_actors_no_update").unwrap();
        mutate_store_for_test(store.path(), "DROP TRIGGER vendor_actors_no_delete").unwrap();
        let tampered_tuple = format!("x'{}'", "99".repeat(32));
        mutate_store_for_test(
            store.path(),
            &format!("UPDATE vendor_actor_authorities SET tuple_digest={tampered_tuple} WHERE role='{role}'"),
        )
        .unwrap();
        let error = store
            .stage(verified_offer(data, data.updater_tuple_digest, 1, 1, 1))
            .err();
        assert_eq!(error, Some(VendorStoreError::Integrity));
        assert_eq!(store.staged_count().unwrap(), 0);
        assert_eq!(snapshot_data(&store), data);
    }
}

#[test]
fn create_new_recovers_from_genesis_corpses_and_refuses_real_corruption() {
    // C1：空文件（0 字节）→ 视同 corpse，单次重建成功。
    let root = private_tempdir();
    let path = root.path().join("vendor-authority.db");
    fs::write(&path, b"").unwrap();
    make_private(&path);
    let store = VendorAuthorityRootStore::create_new(root.path(), genesis()).unwrap();
    assert_eq!(store.snapshot().unwrap().store_revision(), 1);
    drop(store);

    // B：0600 垃圾非 SQLite 文件 → 重建成功，且 root 目录仅剩 .db 与 .lock。
    let root = private_tempdir();
    let path = root.path().join("vendor-authority.db");
    fs::write(&path, b"this is not a sqlite database at all").unwrap();
    make_private(&path);
    let store = VendorAuthorityRootStore::create_new(root.path(), genesis()).unwrap();
    assert_eq!(store.snapshot().unwrap().store_revision(), 1);
    drop(store);
    let mut names = fs::read_dir(root.path())
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .collect::<Vec<_>>();
    names.sort();
    assert_eq!(names, ["vendor-authority.db", "vendor-authority.lock"]);

    // C：pragmas 不符（裸库 application_id=0/user_version=0）→ 重建成功。
    let root = private_tempdir();
    let path = root.path().join("vendor-authority.db");
    {
        let db = RootSqlite::open(&path, true).unwrap();
        db.exec("CREATE TABLE foreign_table(x)").unwrap();
    }
    make_private(&path);
    let store = VendorAuthorityRootStore::create_new(root.path(), genesis()).unwrap();
    assert_eq!(store.snapshot().unwrap().store_revision(), 1);
    drop(store);

    // D：pragmas 匹配但 schema 缺失 → Integrity，且文件原样不删。
    let root = private_tempdir();
    let path = root.path().join("vendor-authority.db");
    {
        let db = RootSqlite::open(&path, true).unwrap();
        db.exec("PRAGMA application_id=1447129905; PRAGMA user_version=1;")
            .unwrap();
    }
    make_private(&path);
    let bytes_before = fs::read(&path).unwrap();
    assert_eq!(
        VendorAuthorityRootStore::create_new(root.path(), genesis()).err(),
        Some(VendorStoreError::Integrity)
    );
    assert_eq!(fs::read(&path).unwrap(), bytes_before);

    // E：完整 store → AlreadyExists（在 genesis 唯一来源测试中覆盖）。
}

#[test]
fn transient_busy_is_not_misclassified_by_the_genesis_probe() {
    // 健康完整 store 在 genesis 分类探测期间遭遇瞬时 BUSY（独立连接先持
    // EXCLUSIVE 事务、后释放）时，probe 连接的有界 busy_timeout 会等出锁
    // 窗口（残留窗口由最多一次有界重探兜底），最终分类为 Complete：
    // create_new 必须返回 AlreadyExists，而不是把健康库误判成 Corrupt
    // （Integrity 砖化）或 Corpse（误删重建）；文件字节必须原样不动。
    let root = private_tempdir();
    let (store, _data) = store_and_snapshot(&root);
    let path = root.path().join("vendor-authority.db");
    let bytes_before = fs::read(&path).unwrap();
    drop(store);

    let (window_open, window_open_receiver) = mpsc::sync_channel(0);
    let blocker_path = path.clone();
    let releaser = thread::spawn(move || {
        use std::time::Duration;
        let blocker = RootSqlite::open(&blocker_path, false).expect("open busy-window holder");
        blocker
            .exec("BEGIN EXCLUSIVE")
            .expect("hold exclusive window");
        window_open.send(()).expect("announce busy window is held");
        thread::sleep(Duration::from_millis(150));
        blocker.exec("COMMIT").expect("release exclusive window");
    });
    window_open_receiver
        .recv()
        .expect("busy window is held before classification");
    assert_eq!(
        VendorAuthorityRootStore::create_new(root.path(), genesis()).err(),
        Some(VendorStoreError::AlreadyExists)
    );
    releaser.join().unwrap();
    assert_eq!(fs::read(&path).unwrap(), bytes_before);
}

#[test]
fn malformed_actor_tuple_digest_is_distinct_from_policy_denial() {
    let cases = [
        format!("z{}", "0".repeat(63)),
        "a".repeat(63),
        "A".repeat(64),
    ];
    for digest in cases {
        let root = private_tempdir();
        let (mut store, data) = store_and_snapshot(&root);
        let authorized = verified_offer_with_payload(
            "vendor-operation-1",
            data,
            digest,
            1,
            1,
            1,
            &super::vendor_release_tests::next_carrier_fixture(data.release_digest),
        );
        assert_eq!(
            store.stage(authorized).err(),
            Some(VendorStoreError::ActorIdentityMalformed)
        );
        assert_eq!(store.staged_count().unwrap(), 0);
        assert_eq!(snapshot_data(&store), data);
    }
}

fn snapshot_data(store: &VendorAuthorityRootStore) -> SnapshotData {
    let snapshot = store.snapshot().unwrap();
    SnapshotData {
        store_revision: snapshot.store_revision(),
        trust_sequence: snapshot.trust_sequence(),
        manifest_digest: *snapshot.manifest_digest(),
        release_sequence: snapshot.release_sequence(),
        release_digest: *snapshot.release_digest(),
        lease_epoch: snapshot.lease_epoch(),
        actor_set_digest: *snapshot.actor_set_digest(),
        updater_tuple_digest: *snapshot.updater_tuple_digest(),
    }
}

// ---------------------------------------------------------------------------
// S2 activation coverage
// ---------------------------------------------------------------------------

fn updater_actor(
    tuple_digest: &[u8; 32],
    release_sequence: u64,
    lease_epoch: u64,
) -> AuthenticatedActorSnapshotV1 {
    AuthenticatedActorSnapshotV1::new_for_test(
        ActorRoleV1::Updater,
        hex_bytes(tuple_digest),
        release_sequence,
        lease_epoch,
        "updater-instance-1".to_string(),
        b"activation-command-bytes",
    )
}

fn role_str(role: VendorActorRoleV1) -> &'static str {
    match role {
        VendorActorRoleV1::Gateway => "gateway",
        VendorActorRoleV1::Main => "main",
        VendorActorRoleV1::Renderer => "renderer",
        VendorActorRoleV1::ModelBroker => "model-broker",
        VendorActorRoleV1::NetworkBroker => "network-broker",
        VendorActorRoleV1::CurrentStateBroker => "current-state-broker",
        VendorActorRoleV1::Updater => "updater",
    }
}

fn blob32(bytes: Vec<u8>) -> [u8; 32] {
    bytes.try_into().unwrap()
}

fn actor_row(store: &VendorAuthorityRootStore, role: VendorActorRoleV1) -> ([u8; 32], u64, u64) {
    let db = RootSqlite::open(store.path(), false).unwrap();
    let mut statement = db
        .prepare("SELECT tuple_digest,release_sequence,lease_epoch FROM vendor_actor_authorities WHERE role=?")
        .unwrap();
    statement.bind(&[SqlValue::Text(role_str(role))]).unwrap();
    statement.step().unwrap();
    (
        blob32(statement.column_blob(0).unwrap()),
        u64::try_from(statement.column_i64(1)).unwrap(),
        u64::try_from(statement.column_i64(2)).unwrap(),
    )
}

fn query_blob(store: &VendorAuthorityRootStore, sql: &str) -> Vec<u8> {
    let db = RootSqlite::open(store.path(), false).unwrap();
    let mut statement = db.prepare(sql).unwrap();
    statement.step().unwrap();
    statement.column_blob(0).unwrap()
}

/// Builds a direct-SQL attempt at the activation form of the vendor_current
/// transition, with the epoch delta, revision delta, and the staged
/// current_bundle binding individually selectable so tests can omit exactly
/// one hard-gate element.
fn activation_form_sql(epoch_delta: &str, revision_delta: &str, with_bundle: bool) -> String {
    let bundle = if with_bundle {
        ", current_bundle=(SELECT raw_bundle FROM vendor_staged_release WHERE singleton=1)"
    } else {
        ""
    };
    format!(
        "UPDATE vendor_current SET store_revision=store_revision{revision_delta}, release_sequence=release_sequence+1, lease_epoch=lease_epoch{epoch_delta}, trust_sequence=(SELECT trust_sequence FROM vendor_staged_release WHERE singleton=1), manifest_digest=(SELECT manifest_digest FROM vendor_staged_release WHERE singleton=1), release_digest=(SELECT release_digest FROM vendor_staged_release WHERE singleton=1), actor_set_digest=(SELECT actor_set_digest FROM vendor_staged_release WHERE singleton=1){bundle} WHERE singleton=1"
    )
}

fn assert_transition_abort(store: &VendorAuthorityRootStore, sql: &str) {
    let error = store
        .exec_raw_for_test(sql)
        .expect_err("current transition must abort");
    assert!(
        format!("{error:?}").contains("invalid vendor current transition"),
        "expected the transition trigger to abort, got: {error:?}"
    );
}

#[test]
fn activation_installs_staged_release_with_epoch_and_authority_handover() {
    let root = private_tempdir();
    let (mut store, data) = store_and_snapshot(&root);
    let staged_carrier = super::vendor_release_tests::next_carrier_fixture(data.release_digest);
    store
        .stage(verified_offer(data, data.updater_tuple_digest, 1, 1, 1))
        .unwrap();
    let after_stage = snapshot_data(&store);
    assert_eq!(after_stage, data.with_revision(2));

    // 独立推导重验产物：激活写入的 release/actor 字段必须与新鲜 verify 的
    // 产物逐一相等，而不是与 staged 元数据或本测试的想象相等。
    let verified_next = verify_vendor_offer(
        admit_vendor_offer_bundle(&staged_carrier).unwrap(),
        &PinnedVendorAnchorV1::for_test_fixture(),
        &after_stage.snapshot(),
        NOW,
    )
    .unwrap();
    let expected_release_digest = *verified_next.release_object_digest();
    let expected_actor_set = *verified_next.actor_authorities().digest();
    let staged_raw = URL_SAFE_NO_PAD.decode(&staged_carrier).unwrap();

    let expectation = ActivationExpectationV1::new(
        store.snapshot().unwrap(),
        updater_actor(&data.updater_tuple_digest, 1, 1),
    );
    let result = store
        .activate(&expectation, &PinnedVendorAnchorV1::for_test_fixture(), NOW)
        .unwrap();
    assert_eq!(result.revision(), 3);
    assert_eq!(result.release_sequence(), 2);
    assert_eq!(result.lease_epoch(), 2);

    // current 八字段逐一：revision+1、trust/manifest 冻结、release 换代、
    // epoch+1、actor_set/updater_tuple 换代。
    let activated = snapshot_data(&store);
    assert_eq!(activated.store_revision, 3);
    assert_eq!(activated.trust_sequence, data.trust_sequence);
    assert_eq!(activated.manifest_digest, data.manifest_digest);
    assert_eq!(activated.release_sequence, 2);
    assert_eq!(activated.release_digest, expected_release_digest);
    assert_eq!(activated.lease_epoch, 2);
    assert_eq!(activated.actor_set_digest, expected_actor_set);
    assert_eq!(activated.updater_tuple_digest, [18; 32]);
    // current_bundle 必须是 staged raw 字节本身。
    assert_eq!(
        query_blob(&store, "SELECT current_bundle FROM vendor_current WHERE singleton=1"),
        staged_raw
    );
    // staged 槽被消费。
    assert_eq!(store.staged_count().unwrap(), 0);
    // 权威换代：7 个 role 行刷新为新 release tuple + 新一代 (rs, ep)。
    for (index, role) in VendorActorRoleV1::ALL.into_iter().enumerate() {
        assert_eq!(actor_row(&store, role), ([12 + index as u8; 32], 2, 2));
    }
}

#[test]
fn expired_activation_is_rejected_with_zero_state_change() {
    let root = private_tempdir();
    let (mut store, data) = store_and_snapshot(&root);
    store
        .stage(verified_offer(data, data.updater_tuple_digest, 1, 1, 1))
        .unwrap();
    let before = snapshot_data(&store);
    let actors_before = VendorActorRoleV1::ALL.map(|role| store.actor_tuple(role).unwrap());

    let expectation = ActivationExpectationV1::new(
        store.snapshot().unwrap(),
        updater_actor(&data.updater_tuple_digest, 1, 1),
    );
    // fixture 的证书与 release 窗口止于 2026-08-29T00:00:00Z。
    let error = store
        .activate(&expectation, &PinnedVendorAnchorV1::for_test_fixture(), "2026-08-29T12:00:00Z")
        .err();
    assert!(
        matches!(error, Some(VendorStoreError::StagedOfferRejected(_))),
        "expired offer must be refused through StagedOfferRejected: {error:?}"
    );
    assert_eq!(snapshot_data(&store), before);
    assert_eq!(store.staged_count().unwrap(), 1, "the audit row stays");
    for (index, role) in VendorActorRoleV1::ALL.into_iter().enumerate() {
        assert_eq!(store.actor_tuple(role).unwrap(), actors_before[index]);
    }

    // 拒绝后 store 照常可用：同一槽位、新鲜墙钟重试完整成功。
    let result = store
        .activate(&expectation, &PinnedVendorAnchorV1::for_test_fixture(), NOW)
        .unwrap();
    assert_eq!(result.revision(), 3);
    assert_eq!(result.lease_epoch(), 2);
    assert_eq!(store.staged_count().unwrap(), 0);
}

#[test]
fn tampered_raw_bundle_is_refused_by_full_reverification() {
    let root = private_tempdir();
    let path = root.path().join("vendor-authority.db");
    let (mut store, data) = store_and_snapshot(&root);
    store
        .stage(verified_offer(data, data.updater_tuple_digest, 1, 1, 1))
        .unwrap();
    let before = snapshot_data(&store);
    let actors_before = VendorActorRoleV1::ALL.map(|role| store.actor_tuple(role).unwrap());

    // 经测试通道外部篡改 staged raw 字节（先放行 staged UPDATE 触发器）。
    mutate_store_for_test(&path, "DROP TRIGGER vendor_staged_no_update").unwrap();
    mutate_store_for_test(
        &path,
        "UPDATE vendor_staged_release SET raw_bundle=x'00' WHERE singleton=1",
    )
    .unwrap();

    let expectation = ActivationExpectationV1::new(
        store.snapshot().unwrap(),
        updater_actor(&data.updater_tuple_digest, 1, 1),
    );
    let error = store
        .activate(&expectation, &PinnedVendorAnchorV1::for_test_fixture(), NOW)
        .err();
    assert!(
        matches!(error, Some(VendorStoreError::StagedOfferRejected(_))),
        "tampered bytes must fail admission before any write: {error:?}"
    );
    assert_eq!(snapshot_data(&store), before);
    assert_eq!(store.staged_count().unwrap(), 1);
    for (index, role) in VendorActorRoleV1::ALL.into_iter().enumerate() {
        assert_eq!(store.actor_tuple(role).unwrap(), actors_before[index]);
    }
}

#[test]
fn illegal_current_transitions_stay_blocked_in_the_activation_schema() {
    let root = private_tempdir();
    let (mut store, data) = store_and_snapshot(&root);

    // 空 staged 槽：完整激活形态也必须被 EXISTS 守卫拒绝（NULL 子查询永远
    // 不能把表单放松成"无条件放行"）。
    assert_transition_abort(&store, &activation_form_sql("+1", "+1", true));
    assert_transition_abort(&store, &activation_form_sql("+2", "+1", true));
    assert_eq!(snapshot_data(&store), data);

    store
        .stage(verified_offer(data, data.updater_tuple_digest, 1, 1, 1))
        .unwrap();
    let after_stage = snapshot_data(&store);

    // 占槽后：缺 current_bundle 绑定、epoch+2、revision 不动，都缺一个
    // 硬门要素，必须由 vendor_current_transition 触发器精确拒绝。
    assert_transition_abort(&store, &activation_form_sql("+1", "+1", false));
    assert_transition_abort(&store, &activation_form_sql("+2", "+1", true));
    assert_transition_abort(&store, &activation_form_sql("+1", "", true));
    assert_eq!(snapshot_data(&store), after_stage);
    assert_eq!(store.staged_count().unwrap(), 1);

    // 触发器拦截之后 store 未被弄脏：正路激活照常成功。
    let expectation = ActivationExpectationV1::new(
        store.snapshot().unwrap(),
        updater_actor(&data.updater_tuple_digest, 1, 1),
    );
    assert_eq!(
        store
            .activate(&expectation, &PinnedVendorAnchorV1::for_test_fixture(), NOW)
            .unwrap()
            .revision(),
        3
    );
}

#[test]
fn double_activation_fails_explicitly_with_zero_state_change() {
    let root = private_tempdir();
    let (mut store, data) = store_and_snapshot(&root);
    store
        .stage(verified_offer(data, data.updater_tuple_digest, 1, 1, 1))
        .unwrap();
    let expectation = ActivationExpectationV1::new(
        store.snapshot().unwrap(),
        updater_actor(&data.updater_tuple_digest, 1, 1),
    );
    store
        .activate(&expectation, &PinnedVendorAnchorV1::for_test_fixture(), NOW)
        .unwrap();
    let activated = snapshot_data(&store);
    assert_eq!(store.staged_count().unwrap(), 0);

    // 形态一：并发输家持有 stale expectation（上一代 release/epoch）——
    // actor 四检以 ActorDenied 明确拒绝。
    assert_eq!(
        store
            .activate(&expectation, &PinnedVendorAnchorV1::for_test_fixture(), NOW)
            .err(),
        Some(VendorStoreError::ActorDenied)
    );
    // 形态二：重读新鲜快照与换代后身份——槽位已空，StagedSlotEmpty。
    let fresh = ActivationExpectationV1::new(
        store.snapshot().unwrap(),
        updater_actor(&[18; 32], activated.release_sequence, activated.lease_epoch),
    );
    assert_eq!(
        store
            .activate(&fresh, &PinnedVendorAnchorV1::for_test_fixture(), NOW)
            .err(),
        Some(VendorStoreError::StagedSlotEmpty)
    );

    assert_eq!(snapshot_data(&store), activated);
    assert_eq!(store.staged_count().unwrap(), 0);
}

#[test]
fn epoch_advances_only_by_one_per_activation_and_never_without_a_slot() {
    let root = private_tempdir();
    let (mut store, data) = store_and_snapshot(&root);
    store
        .stage(verified_offer(data, data.updater_tuple_digest, 1, 1, 1))
        .unwrap();
    let expectation = ActivationExpectationV1::new(
        store.snapshot().unwrap(),
        updater_actor(&data.updater_tuple_digest, 1, 1),
    );
    assert_eq!(
        store
            .activate(&expectation, &PinnedVendorAnchorV1::for_test_fixture(), NOW)
            .unwrap()
            .lease_epoch(),
        2
    );

    // 无新 stage 就没有可消费的槽：epoch 不存在任何 +1 旁路。
    let fresh = ActivationExpectationV1::new(
        store.snapshot().unwrap(),
        updater_actor(&[18; 32], 2, 2),
    );
    assert_eq!(
        store
            .activate(&fresh, &PinnedVendorAnchorV1::for_test_fixture(), NOW)
            .err(),
        Some(VendorStoreError::StagedSlotEmpty)
    );
    let settled = snapshot_data(&store);
    assert_eq!(settled.lease_epoch, 2);
    assert_eq!(settled.store_revision, 3);
    assert_eq!(settled.release_sequence, 2);
    assert_eq!(store.staged_count().unwrap(), 0);
}

#[test]
fn activation_era_triggers_stay_closed_outside_activation() {
    let root = private_tempdir();
    let (mut store, data) = store_and_snapshot(&root);
    store
        .stage(verified_offer(data, data.updater_tuple_digest, 1, 1, 1))
        .unwrap();

    // staged 行：current 未安装该 release，DELETE 仍被钉死。
    let error = store
        .exec_raw_for_test("DELETE FROM vendor_staged_release")
        .expect_err("staged row must stay while current has not installed it");
    assert!(format!("{error:?}").contains("staged release is immutable"));

    // actors：current 仍在同一代，任何 UPDATE/DELETE 都没有放行条件。
    let error = store
        .exec_raw_for_test("UPDATE vendor_actor_authorities SET tuple_digest=x'22' WHERE role='main'")
        .expect_err("same-generation actor update must abort");
    assert!(format!("{error:?}").contains("vendor actors are immutable"));
    let error = store
        .exec_raw_for_test("UPDATE vendor_actor_authorities SET release_sequence=2, lease_epoch=2 WHERE role='main'")
        .expect_err("cross-generation actor move must abort while current has not advanced");
    assert!(format!("{error:?}").contains("vendor actors are immutable"));
    let error = store
        .exec_raw_for_test("DELETE FROM vendor_actor_authorities WHERE role='main'")
        .expect_err("actor delete must abort outside activation");
    assert!(format!("{error:?}").contains("vendor actors are immutable"));

    // current：单独 epoch+1 不是任何许可形态。
    assert_transition_abort(
        &store,
        "UPDATE vendor_current SET lease_epoch=lease_epoch+1 WHERE singleton=1",
    );
    assert_eq!(store.staged_count().unwrap(), 1);

    // 激活后：actor 行已在新一代，current 未再次领先，改/删仍被钉死。
    let expectation = ActivationExpectationV1::new(
        store.snapshot().unwrap(),
        updater_actor(&data.updater_tuple_digest, 1, 1),
    );
    store
        .activate(&expectation, &PinnedVendorAnchorV1::for_test_fixture(), NOW)
        .unwrap();
    let error = store
        .exec_raw_for_test("UPDATE vendor_actor_authorities SET tuple_digest=x'22' WHERE role='main'")
        .expect_err("post-activation actor update must abort");
    assert!(format!("{error:?}").contains("vendor actors are immutable"));
    let error = store
        .exec_raw_for_test("DELETE FROM vendor_actor_authorities WHERE role='updater'")
        .expect_err("post-activation actor delete must abort");
    assert!(format!("{error:?}").contains("vendor actors are immutable"));
    assert!(store.exec_raw_for_test("DELETE FROM vendor_current").is_err());
}

#[test]
fn legacy_v1_store_migrates_in_place_and_stays_usable() {
    // 场景一：无 staged 行的 v1 库（stage 期 genesis 库的原貌）。
    let root = private_tempdir();
    let path = root.path().join("vendor-authority.db");
    let (store, data) = store_and_snapshot(&root);
    let genesis_actors = VendorActorRoleV1::ALL.map(|role| store.actor_tuple(role).unwrap());
    drop(store);
    VendorAuthorityRootStore::downgrade_store_to_v1_for_test(&path).unwrap();
    assert_eq!(
        VendorAuthorityRootStore::stored_user_version_for_test(&path).unwrap(),
        1
    );

    let store = VendorAuthorityRootStore::open_existing(root.path()).unwrap();
    assert_eq!(
        VendorAuthorityRootStore::stored_user_version_for_test(&path).unwrap(),
        2
    );
    assert_eq!(snapshot_data(&store), data);
    assert_eq!(store.staged_count().unwrap(), 0);
    for (index, role) in VendorActorRoleV1::ALL.into_iter().enumerate() {
        assert_eq!(store.actor_tuple(role).unwrap(), genesis_actors[index]);
    }
    drop(store);

    // 迁移后的 v2 库是完整 store：create_new 拒绝且不删除，reopen 稳定。
    assert_eq!(
        VendorAuthorityRootStore::create_new(root.path(), genesis()).err(),
        Some(VendorStoreError::AlreadyExists)
    );
    let store = VendorAuthorityRootStore::open_existing(root.path()).unwrap();
    assert_eq!(snapshot_data(&store), data);
    drop(store);

    // 场景二：带 staged 行 + revision 2 的 v1 库迁移后必须可激活。
    let root = private_tempdir();
    let path = root.path().join("vendor-authority.db");
    let (mut store, data) = store_and_snapshot(&root);
    store
        .stage(verified_offer(data, data.updater_tuple_digest, 1, 1, 1))
        .unwrap();
    drop(store);
    VendorAuthorityRootStore::downgrade_store_to_v1_for_test(&path).unwrap();
    let mut store = VendorAuthorityRootStore::open_existing(root.path()).unwrap();
    assert_eq!(
        VendorAuthorityRootStore::stored_user_version_for_test(&path).unwrap(),
        2
    );
    assert_eq!(snapshot_data(&store), data.with_revision(2));
    assert_eq!(store.staged_count().unwrap(), 1);
    let expectation = ActivationExpectationV1::new(
        store.snapshot().unwrap(),
        updater_actor(&data.updater_tuple_digest, 1, 1),
    );
    let result = store
        .activate(&expectation, &PinnedVendorAnchorV1::for_test_fixture(), NOW)
        .unwrap();
    assert_eq!(result.revision(), 3);
    assert_eq!(result.lease_epoch(), 2);
    assert_eq!(store.staged_count().unwrap(), 0);
}


fn store_and_snapshot(root: &TempDir) -> (VendorAuthorityRootStore, SnapshotData) {
    let store = VendorAuthorityRootStore::create_new(root.path(), genesis()).unwrap();
    let data = snapshot_data(&store);
    (store, data)
}

fn genesis() -> super::vendor_release::VerifiedVendorGenesisV1 {
    verify_vendor_genesis(
        admit_vendor_offer_bundle(&super::vendor_release_tests::genesis_carrier_fixture()).unwrap(),
        &PinnedVendorAnchorV1::for_test_fixture(),
        NOW,
    )
    .unwrap()
}

fn verified_offer(
    current: SnapshotData,
    actor_tuple: [u8; 32],
    actor_release: u64,
    actor_epoch: u64,
    expected_revision: u64,
) -> AuthorizedVerifiedVendorOfferV1 {
    verified_offer_with_payload(
        "vendor-operation-1",
        current,
        hex_bytes(&actor_tuple),
        actor_release,
        actor_epoch,
        expected_revision,
        &super::vendor_release_tests::next_carrier_fixture(current.release_digest),
    )
}

fn verified_offer_with_payload(
    operation_id: &str,
    current: SnapshotData,
    actor_tuple_digest: String,
    actor_release: u64,
    actor_epoch: u64,
    expected_revision: u64,
    payload: &str,
) -> AuthorizedVerifiedVendorOfferV1 {
    let decoded = URL_SAFE_NO_PAD.decode(payload).unwrap();
    let command = serde_json::json!({
        "schema": "rb.root-command.v1",
        "operationId": operation_id,
        "expectedRevision": expected_revision,
        "clientNonce": "nonce-1",
        "method": "release-offer-vendor-metadata",
        "brokerRole": null,
        "subjectDigest": "a".repeat(64),
        "payload": payload,
        "payloadDigest": digest_hex(&decoded),
    })
    .to_string()
    .into_bytes();
    let actor = AuthenticatedActorSnapshotV1::new_for_test(
        ActorRoleV1::Updater,
        actor_tuple_digest,
        actor_release,
        actor_epoch,
        "updater-instance-1".to_string(),
        &command,
    );
    admit_root_command(actor, &command)
        .unwrap()
        .into_vendor_offer_command()
        .unwrap()
        .verify(
            &PinnedVendorAnchorV1::for_test_fixture(),
            current.snapshot(),
            NOW,
        )
        .unwrap()
}

fn make_private(path: &std::path::Path) {
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
}

fn private_tempdir() -> TempDir {
    let root = tempfile::tempdir_in("/private/tmp").unwrap();
    fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
    root
}

fn digest_hex(bytes: &[u8]) -> String {
    hex_bytes(&Sha256::digest(bytes))
}

fn hex_bytes(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
