#![allow(clippy::expect_used)]

use super::root_broker_store_tests::initialize_external_effect_sink;
use super::root_protocol::ActorRoleV1;
use super::root_protocol::AuthenticatedActorSnapshotV1;
use super::root_service::SyntheticRootReplyV1;
use super::root_service::SyntheticRootServiceClientV1;
use super::root_service::SyntheticRootServiceErrorV1;
use super::root_service::SyntheticRootServiceV1;
use super::root_service::execute_synthetic_effect_for_test;
use super::root_store::RootStoreError;
use super::root_store_tests::bootstrap;
use super::root_store_tests::digest;
use super::root_store_tests::new_root;
use pretty_assertions::assert_eq;
use std::fs;
use std::sync::Arc;
use std::sync::Barrier;
use std::thread;

const OPERATION: &str = "operation-concurrent";
const PAYLOAD: &str = "request-a";

fn command(method: &str, operation_id: &str, revision: u64) -> Box<[u8]> {
    format!(
        "{{\"schema\":\"rb.root-command.v1\",\"operationId\":\"{operation_id}\",\"expectedRevision\":{revision},\"clientNonce\":\"nonce-1\",\"method\":\"{method}\",\"brokerRole\":\"model\",\"subjectDigest\":\"{}\",\"payload\":{PAYLOAD:?},\"payloadDigest\":\"{}\"}}",
        "a".repeat(64),
        digest(PAYLOAD.as_bytes())
    )
    .into_bytes()
    .into_boxed_slice()
}

fn request(
    client: &SyntheticRootServiceClientV1,
    role: ActorRoleV1,
    method: &str,
    operation_id: &str,
    revision: u64,
    connection: &str,
) -> Result<SyntheticRootReplyV1, SyntheticRootServiceErrorV1> {
    let bytes = command(method, operation_id, revision);
    let actor = AuthenticatedActorSnapshotV1::new_for_test(
        role,
        "c".repeat(64),
        3,
        5,
        connection.to_string(),
        &bytes,
    );
    client.dispatch(actor, bytes)
}

fn enqueue_request(
    client: &SyntheticRootServiceClientV1,
    role: ActorRoleV1,
    method: &str,
    operation_id: &str,
    revision: u64,
    connection: &str,
) -> std::sync::mpsc::Receiver<Result<SyntheticRootReplyV1, SyntheticRootServiceErrorV1>> {
    let bytes = command(method, operation_id, revision);
    let actor = AuthenticatedActorSnapshotV1::new_for_test(
        role,
        "c".repeat(64),
        3,
        5,
        connection.to_string(),
        &bytes,
    );
    client
        .enqueue_for_test(actor, bytes)
        .expect("enqueue request with observed reply")
}

#[expect(
    clippy::needless_collect,
    reason = "all workers must be spawned before the coordinator releases their shared barrier"
)]
fn concurrent_phase(
    client: &SyntheticRootServiceClientV1,
    role: ActorRoleV1,
    method: &'static str,
    revision: u64,
    connection: &'static str,
) -> Vec<Result<SyntheticRootReplyV1, SyntheticRootServiceErrorV1>> {
    let barrier = Arc::new(Barrier::new(101));
    let workers = (0..100)
        .map(|_| {
            let client = client.clone();
            let barrier = Arc::clone(&barrier);
            thread::spawn(move || {
                barrier.wait();
                request(&client, role, method, OPERATION, revision, connection)
            })
        })
        .collect::<Vec<_>>();
    barrier.wait();
    workers
        .into_iter()
        .map(|join| join.join().expect("concurrent request"))
        .collect()
}

fn assert_one_revision(
    results: Vec<Result<SyntheticRootReplyV1, SyntheticRootServiceErrorV1>>,
    revision: u64,
) {
    let mut success = 0;
    let mut conflict = 0;
    for result in results {
        match result {
            Ok(SyntheticRootReplyV1::Revision(actual)) if actual == revision => success += 1,
            Err(SyntheticRootServiceErrorV1::Store(RootStoreError::InvalidTransition)) => {
                conflict += 1;
            }
            unexpected => panic!("unexpected concurrent result: {unexpected:?}"),
        }
    }
    assert_eq!((success, conflict), (1, 99));
}

#[test]
fn one_hundred_concurrent_starts_emit_one_owned_external_effect() {
    let root = new_root();
    let service = SyntheticRootServiceV1::start(root.path().to_path_buf(), bootstrap(3, 5, b'c'))
        .expect("start single writer");
    let client = service.client();
    assert_one_revision(
        concurrent_phase(
            &client,
            ActorRoleV1::Gateway,
            "broker-authorize",
            0,
            "gateway-instance-1",
        ),
        1,
    );
    assert_one_revision(
        concurrent_phase(
            &client,
            ActorRoleV1::ModelBroker,
            "broker-claim",
            1,
            "model-broker-1",
        ),
        2,
    );

    let effect_root = new_root();
    let log = effect_root.path().join("external.log");
    assert!(initialize_external_effect_sink(&log, None).status.success());
    let mut conflicts = 0;
    for result in concurrent_phase(
        &client,
        ActorRoleV1::ModelBroker,
        "broker-effect-start",
        2,
        "model-broker-1",
    ) {
        match result {
            Ok(SyntheticRootReplyV1::ExecuteNow(disposition)) => {
                assert!(
                    execute_synthetic_effect_for_test(disposition, &log)
                        .status
                        .success()
                );
            }
            Err(SyntheticRootServiceErrorV1::Store(RootStoreError::InvalidTransition)) => {
                conflicts += 1;
            }
            unexpected => panic!("unexpected effect result: {unexpected:?}"),
        }
    }
    assert_eq!(conflicts, 99);
    assert_eq!(
        fs::read_to_string(log)
            .expect("external log")
            .lines()
            .count(),
        1
    );
}

#[test]
fn old_command_queued_before_quiesce_commits_and_blocks_activation() {
    let root = new_root();
    let service = SyntheticRootServiceV1::start(root.path().to_path_buf(), bootstrap(3, 5, b'c'))
        .expect("start service");
    let client = service.client();
    let release = service.pause_for_test();
    let old_reply = enqueue_request(
        &client,
        ActorRoleV1::Gateway,
        "broker-authorize",
        "old-first",
        0,
        "gateway-instance-1",
    );
    let quiesce = service
        .enqueue_begin_quiesce_for_test(3, 1)
        .expect("enqueue quiesce after old command");
    release.send(()).expect("release deterministic barrier");
    assert_eq!(
        old_reply.recv().expect("old command reply"),
        Ok(SyntheticRootReplyV1::Revision(1))
    );
    assert_eq!(quiesce.recv().expect("quiesce reply"), Ok(2));
    assert_eq!(
        service.activate_internal(3, 2, bootstrap(4, 6, b'd')),
        Err(RootStoreError::ActiveOperations)
    );
}

#[test]
fn quiesce_queued_before_old_command_rejects_old_state_change() {
    let root = new_root();
    let service = SyntheticRootServiceV1::start(root.path().to_path_buf(), bootstrap(3, 5, b'c'))
        .expect("start service");
    let client = service.client();
    let release = service.pause_for_test();
    let quiesce = service
        .enqueue_begin_quiesce_for_test(3, 1)
        .expect("enqueue quiesce first");
    let old_reply = enqueue_request(
        &client,
        ActorRoleV1::Gateway,
        "broker-authorize",
        "quiesce-first",
        0,
        "gateway-instance-1",
    );
    release.send(()).expect("release deterministic barrier");
    assert_eq!(quiesce.recv().expect("quiesce reply"), Ok(2));
    assert_eq!(
        old_reply.recv().expect("old command reply"),
        Err(SyntheticRootServiceErrorV1::Store(
            RootStoreError::Quiescing
        ))
    );
    assert_eq!(
        service.activate_internal(3, 2, bootstrap(4, 6, b'd')),
        Ok(3)
    );
}
