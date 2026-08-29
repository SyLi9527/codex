// Test assertions express failure by panicking by design, while the workspace
// denies unwrap/expect globally; this module carries a scoped allowance.
#![allow(clippy::expect_used, clippy::unwrap_used)]

use super::root_protocol::ActorRoleV1;
use super::root_protocol::AuthenticatedActorSnapshotV1;
use super::root_protocol::AuthorizedVerifiedVendorOfferV1;
use super::root_protocol::admit_root_command;
use super::root_sqlite::RootSqlite;
use super::root_sqlite::mutate_store_for_test;
use super::vendor_authority_store::GENESIS_LEASE_EPOCH;
use super::vendor_authority_store::StageFaultPoint;
use super::vendor_authority_store::VendorAuthorityRootStore;
use super::vendor_authority_store::VendorCurrentSnapshotV1;
use super::vendor_authority_store::VendorStoreError;
use super::vendor_release::PinnedVendorAnchorV1;
use super::vendor_release::VendorActorRoleV1;
use super::vendor_release::admit_vendor_offer_bundle;
use super::vendor_release::verify_vendor_genesis;
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
