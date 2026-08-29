#![allow(clippy::expect_used)]

use super::root_broker_store::GuardVerifiedEffectReceiptV1;
use super::root_protocol::ActorRoleV1;
use super::root_store::RootStore;
use super::root_store::RootStoreError;
use super::root_store_tests::admitted_command;
use super::root_store_tests::admitted_command_with_subject;
use super::root_store_tests::bootstrap;
use super::root_store_tests::digest;
use super::root_store_tests::new_root;
use std::fs;
use std::fs::File;
use std::fs::OpenOptions;
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use std::process::Command;

const FAKE_LOG_ENV: &str = "RB_LG10_FAKE_EFFECT_LOG";
const FAKE_RECORD_ENV: &str = "RB_LG10_FAKE_EFFECT_RECORD";
const FAKE_FAULT_ENV: &str = "RB_LG10_FAKE_EFFECT_FAULT";
const FAKE_HELPER_TEST: &str =
    "root_broker_store_tests::external_fake_effect_process_appends_and_fsyncs_each_call";

fn broker_command(
    method: &str,
    operation_id: &str,
    expected_revision: u64,
    connection_instance: &str,
    payload: &str,
) -> super::root_protocol::AuthorizedRootCommandV1 {
    admitted_command(
        ActorRoleV1::ModelBroker,
        method,
        operation_id,
        expected_revision,
        3,
        5,
        b'c',
        connection_instance,
        payload,
    )
}

fn gateway_command(
    method: &str,
    operation_id: &str,
    expected_revision: u64,
    payload: &str,
) -> super::root_protocol::AuthorizedRootCommandV1 {
    gateway_command_from(
        "gateway-instance-1",
        b'c',
        &"a".repeat(64),
        method,
        operation_id,
        expected_revision,
        payload,
    )
}

#[allow(clippy::too_many_arguments)]
fn gateway_command_from(
    connection_instance: &str,
    tuple: u8,
    subject_digest: &str,
    method: &str,
    operation_id: &str,
    expected_revision: u64,
    payload: &str,
) -> super::root_protocol::AuthorizedRootCommandV1 {
    admitted_command_with_subject(
        ActorRoleV1::Gateway,
        method,
        operation_id,
        expected_revision,
        3,
        5,
        tuple,
        connection_instance,
        subject_digest,
        payload,
    )
}

fn authorize_claim_start(
    store: &mut RootStore,
    operation_id: &str,
    payload: &str,
) -> super::root_broker_store::ExecuteNowDispositionV1 {
    assert_eq!(
        store.authorize_broker(gateway_command(
            "broker-authorize",
            operation_id,
            0,
            payload
        )),
        Ok(1)
    );
    assert_eq!(
        store.claim_broker(broker_command(
            "broker-claim",
            operation_id,
            1,
            "model-broker-1",
            payload,
        )),
        Ok(2)
    );
    store
        .start_broker_effect(broker_command(
            "broker-effect-start",
            operation_id,
            2,
            "model-broker-1",
            payload,
        ))
        .expect("first effect-start returns execute-now")
}

pub(super) fn run_external_effect(
    log: &Path,
    record: &str,
    fail_after_fsync: bool,
) -> std::process::Output {
    let mut command = Command::new(std::env::current_exe().expect("current test executable"));
    command
        .arg("--exact")
        .arg(FAKE_HELPER_TEST)
        .arg("--nocapture")
        .env(FAKE_LOG_ENV, log)
        .env(FAKE_RECORD_ENV, record);
    if fail_after_fsync {
        command.env(FAKE_FAULT_ENV, "append-after-file-sync");
    }
    command
        .output()
        .expect("run independent fake effect process")
}

pub(super) fn initialize_external_effect_sink(
    log: &Path,
    fault: Option<&str>,
) -> std::process::Output {
    let mut command = Command::new(std::env::current_exe().expect("current test executable"));
    command
        .arg("--exact")
        .arg(FAKE_HELPER_TEST)
        .arg("--nocapture")
        .env(FAKE_LOG_ENV, log);
    if let Some(fault) = fault {
        command.env(FAKE_FAULT_ENV, fault);
    }
    command
        .output()
        .expect("initialize independent fake effect sink")
}

fn initialize_and_sync_fake_effect_sink(log: &Path) {
    let file = OpenOptions::new()
        .create_new(true)
        .read(true)
        .write(true)
        .mode(0o600)
        .open(log)
        .expect("create independent effect log");
    file.sync_all().expect("fsync empty effect log");
    if std::env::var(FAKE_FAULT_ENV).as_deref() == Ok("init-after-file-sync") {
        std::process::exit(84);
    }
    let parent = File::open(log.parent().expect("effect log parent"))
        .expect("open independent effect parent directory");
    parent
        .sync_all()
        .expect("fsync effect parent directory before ready");
}

fn validate_fake_effect_record(record: &str) {
    assert!(record.len() <= 512, "bounded fake effect record");
    let fields = record.split(';').collect::<Vec<_>>();
    assert_eq!(fields.len(), 3, "exact fake effect record fields");
    assert!(
        fields[0]
            .strip_prefix("callSeq=")
            .and_then(|value| value.parse::<u64>().ok())
            .is_some_and(|value| value > 0)
    );
    let operation_id = fields[1].strip_prefix("opId=").expect("operation field");
    assert!(
        !operation_id.is_empty()
            && operation_id.len() <= 128
            && operation_id
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
    );
    let payload_digest = fields[2]
        .strip_prefix("payloadDigest=")
        .expect("payload digest field");
    assert!(
        payload_digest.len() == 64
            && payload_digest
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    );
}

fn append_and_sync_fake_effect(log: &Path, record: &str) {
    validate_fake_effect_record(record);
    let mut file = OpenOptions::new()
        .append(true)
        .open(log)
        .expect("open pre-created independent append-only effect log");
    writeln!(file, "{record}").expect("append effect record");
    if std::env::var(FAKE_FAULT_ENV).as_deref() == Ok("append-before-file-sync") {
        std::process::exit(85);
    }
    file.sync_all().expect("fsync effect record before ACK");
    if std::env::var(FAKE_FAULT_ENV).as_deref() == Ok("append-after-file-sync") {
        std::process::exit(86);
    }
}

#[test]
fn external_fake_effect_process_appends_and_fsyncs_each_call() {
    let _spawn_exclusion = super::root_store::test_spawn_and_flock_exclusion();
    if let Some(log) = std::env::var_os(FAKE_LOG_ENV) {
        let path = Path::new(&log);
        if let Some(record) = std::env::var_os(FAKE_RECORD_ENV) {
            let record = record.into_string().expect("UTF-8 fake effect record");
            append_and_sync_fake_effect(path, &record);
            println!("{}", digest(record.as_bytes()));
        } else {
            initialize_and_sync_fake_effect_sink(path);
        }
        return;
    }

    let root = new_root();
    let log = root.path().join("independent-effect.log");
    assert!(initialize_external_effect_sink(&log, None).status.success());
    let payload_digest = digest(b"request-a");
    for call_sequence in 1..=2 {
        let record =
            format!("callSeq={call_sequence};opId=same-operation;payloadDigest={payload_digest}");
        let output = run_external_effect(&log, &record, false);
        assert!(output.status.success(), "helper stderr={:?}", output.stderr);
    }
    let records = fs::read_to_string(log).expect("read durable external log");
    assert_eq!(records.lines().count(), 2);
    assert!(records.contains("callSeq=1"));
    assert!(records.contains("callSeq=2"));

    let failed_init_root = new_root();
    let failed_init_log = failed_init_root.path().join("effect.log");
    assert_eq!(
        initialize_external_effect_sink(&failed_init_log, Some("init-after-file-sync"))
            .status
            .code(),
        Some(84)
    );
    assert_eq!(
        fs::read_to_string(failed_init_log).expect("empty unready sink"),
        ""
    );

    let uncertain_root = new_root();
    let uncertain_log = uncertain_root.path().join("effect.log");
    assert!(
        initialize_external_effect_sink(&uncertain_log, None)
            .status
            .success()
    );
    let uncertain_record =
        format!("callSeq=1;opId=uncertain-operation;payloadDigest={payload_digest}");
    let mut command = Command::new(std::env::current_exe().expect("current test executable"));
    let output = command
        .arg("--exact")
        .arg(FAKE_HELPER_TEST)
        .arg("--nocapture")
        .env(FAKE_LOG_ENV, &uncertain_log)
        .env(FAKE_RECORD_ENV, &uncertain_record)
        .env(FAKE_FAULT_ENV, "append-before-file-sync")
        .output()
        .expect("inject append-before-sync fault");
    assert_eq!(output.status.code(), Some(85));
    assert_eq!(
        fs::read_to_string(uncertain_log)
            .expect("reopen uncertain external log")
            .lines()
            .count(),
        1
    );
}

#[test]
fn current_gateway_reconnect_queries_and_cancels_exact_authorization_only() {
    let _spawn_exclusion = super::root_store::test_spawn_and_flock_exclusion();
    let root = new_root();
    let mut store = RootStore::open(root.path(), &bootstrap(3, 5, b'c')).expect("open store");
    assert_eq!(
        store.authorize_broker(gateway_command(
            "broker-authorize",
            "operation-reconnect",
            0,
            "request-a",
        )),
        Ok(1)
    );

    let reconnect_query = || {
        gateway_command_from(
            "gateway-instance-2",
            b'c',
            &"a".repeat(64),
            "broker-query",
            "operation-reconnect",
            1,
            "request-a",
        )
    };
    assert_eq!(
        store
            .query_broker(reconnect_query())
            .expect("query after ACK loss")
            .state,
        "authorized"
    );
    assert!(matches!(
        store.query_broker(gateway_command_from(
            "gateway-instance-2",
            b'c',
            &"a".repeat(64),
            "broker-query",
            "operation-reconnect",
            1,
            "wrong-payload",
        )),
        Err(RootStoreError::InvalidTransition)
    ));
    assert!(matches!(
        store.query_broker(gateway_command_from(
            "gateway-instance-2",
            b'c',
            &"b".repeat(64),
            "broker-query",
            "operation-reconnect",
            1,
            "request-a",
        )),
        Err(RootStoreError::InvalidTransition)
    ));
    assert_eq!(
        store
            .query_broker(gateway_command_from(
                "gateway-instance-2",
                b'd',
                &"a".repeat(64),
                "broker-query",
                "operation-reconnect",
                1,
                "request-a",
            ))
            .err(),
        Some(RootStoreError::ActorStale)
    );
    assert_eq!(
        store.cancel_before_claim(gateway_command_from(
            "gateway-instance-2",
            b'c',
            &"a".repeat(64),
            "broker-cancel-before-claim",
            "operation-reconnect",
            1,
            "request-a",
        )),
        Ok(2)
    );
    assert_eq!(
        store.cancel_before_claim(gateway_command_from(
            "gateway-instance-3",
            b'c',
            &"a".repeat(64),
            "broker-cancel-before-claim",
            "operation-reconnect",
            1,
            "request-a",
        )),
        Err(RootStoreError::InvalidTransition)
    );
}

#[test]
fn first_effect_start_is_the_only_execute_now_and_safe_settlement_drains_release() {
    let _spawn_exclusion = super::root_store::test_spawn_and_flock_exclusion();
    let root = new_root();
    let mut store = RootStore::open(root.path(), &bootstrap(3, 5, b'c')).expect("open store");
    let disposition = authorize_claim_start(&mut store, "operation-1", "request-a");
    assert_eq!(disposition.operation_id(), "operation-1");
    assert_eq!(disposition.revision(), 3);
    assert_eq!(disposition.effect_request_digest(), digest(b"request-a"));
    assert_eq!(
        store
            .start_broker_effect(broker_command(
                "broker-effect-start",
                "operation-1",
                2,
                "model-broker-1",
                "request-a",
            ))
            .err(),
        Some(RootStoreError::InvalidTransition)
    );
    let view = store
        .query_broker(broker_command(
            "broker-query",
            "operation-1",
            3,
            "model-broker-1",
            "query",
        ))
        .expect("owner query after lost execute-now reply");
    assert_eq!(view.state, "effect-starting");
    assert_eq!(view.revision, 3);
    assert_eq!(view.effect_attempt_count, 1);

    let external_root = new_root();
    let log = external_root.path().join("external-effect.log");
    assert!(initialize_external_effect_sink(&log, None).status.success());
    let evidence = format!(
        "callSeq=1;opId=operation-1;payloadDigest={}",
        disposition.effect_request_digest()
    );
    let output = run_external_effect(&log, &evidence, false);
    assert!(output.status.success());
    let evidence_digest = digest(evidence.as_bytes());
    let receipt = GuardVerifiedEffectReceiptV1::new_for_test(
        "operation-1".to_string(),
        "model-broker-1".to_string(),
        evidence_digest,
    );
    assert_eq!(
        store.settle_broker_safe(
            broker_command(
                "broker-settle",
                "operation-1",
                3,
                "model-broker-1",
                &evidence,
            ),
            receipt,
        ),
        Ok(4)
    );
    assert_eq!(
        fs::read_to_string(log).expect("effect log").lines().count(),
        1
    );
    assert_eq!(store.begin_quiesce(3, 1), Ok(2));
    assert_eq!(store.activate_release(3, 2, &bootstrap(4, 6, b'd')), Ok(3));
}

#[test]
fn restart_freezes_effect_starting_as_unknown_and_never_reissues_or_ordinarily_settles() {
    let _spawn_exclusion = super::root_store::test_spawn_and_flock_exclusion();
    let root = new_root();
    {
        let mut store = RootStore::open(root.path(), &bootstrap(3, 5, b'c')).expect("open store");
        let _ = authorize_claim_start(&mut store, "operation-unknown", "request-a");
    }
    let mut reopened = RootStore::open(root.path(), &bootstrap(3, 5, b'c')).expect("reopen store");
    let view = reopened
        .query_broker(broker_command(
            "broker-query",
            "operation-unknown",
            4,
            "model-broker-1",
            "query",
        ))
        .expect("query frozen unknown");
    assert_eq!(view.state, "effect-unknown");
    assert_eq!(view.revision, 4);
    assert_eq!(view.effect_attempt_count, 1);
    assert!(matches!(
        reopened.start_broker_effect(broker_command(
            "broker-effect-start",
            "operation-unknown",
            2,
            "model-broker-1",
            "request-a",
        )),
        Err(RootStoreError::InvalidTransition)
    ));
    let evidence = "operation-unknown|unverified";
    let receipt = GuardVerifiedEffectReceiptV1::new_for_test(
        "operation-unknown".to_string(),
        "model-broker-1".to_string(),
        digest(evidence.as_bytes()),
    );
    assert_eq!(
        reopened.settle_broker_safe(
            broker_command(
                "broker-settle",
                "operation-unknown",
                4,
                "model-broker-1",
                evidence,
            ),
            receipt,
        ),
        Err(RootStoreError::InvalidTransition)
    );
    assert_eq!(reopened.begin_quiesce(3, 1), Ok(2));
    assert_eq!(
        reopened.activate_release(3, 2, &bootstrap(4, 6, b'd')),
        Err(RootStoreError::ActiveOperations)
    );
}

#[test]
fn external_ack_loss_records_one_call_then_unknown_blocks_retry() {
    let _spawn_exclusion = super::root_store::test_spawn_and_flock_exclusion();
    let root = new_root();
    let mut store = RootStore::open(root.path(), &bootstrap(3, 5, b'c')).expect("open store");
    let disposition = authorize_claim_start(&mut store, "operation-ack-loss", "request-a");
    let external_root = new_root();
    let log = external_root.path().join("external-effect.log");
    assert!(initialize_external_effect_sink(&log, None).status.success());
    let record = format!(
        "callSeq=1;opId=operation-ack-loss;payloadDigest={}",
        disposition.effect_request_digest()
    );
    let output = run_external_effect(&log, &record, true);
    assert_eq!(output.status.code(), Some(86));
    assert_eq!(
        fs::read_to_string(&log)
            .expect("effect survived helper failure")
            .lines()
            .count(),
        1
    );
    assert_eq!(
        store.mark_broker_effect_unknown(disposition.operation_id(), disposition.revision()),
        Ok(4)
    );
    assert!(matches!(
        store.start_broker_effect(broker_command(
            "broker-effect-start",
            "operation-ack-loss",
            2,
            "model-broker-1",
            "request-a",
        )),
        Err(RootStoreError::InvalidTransition)
    ));
    assert_eq!(
        fs::read_to_string(log)
            .expect("single external call")
            .lines()
            .count(),
        1
    );
}

#[test]
fn wrong_broker_instance_cannot_start_query_or_settle_owned_operation() {
    let _spawn_exclusion = super::root_store::test_spawn_and_flock_exclusion();
    let root = new_root();
    let mut store = RootStore::open(root.path(), &bootstrap(3, 5, b'c')).expect("open store");
    let _ = authorize_claim_start(&mut store, "operation-owned", "request-a");
    assert!(matches!(
        store.query_broker(broker_command(
            "broker-query",
            "operation-owned",
            3,
            "model-broker-2",
            "query",
        )),
        Err(RootStoreError::InvalidTransition)
    ));
    let evidence = "operation-owned|forged";
    let receipt = GuardVerifiedEffectReceiptV1::new_for_test(
        "operation-owned".to_string(),
        "model-broker-2".to_string(),
        digest(evidence.as_bytes()),
    );
    assert_eq!(
        store.settle_broker_safe(
            broker_command(
                "broker-settle",
                "operation-owned",
                3,
                "model-broker-2",
                evidence,
            ),
            receipt,
        ),
        Err(RootStoreError::InvalidTransition)
    );
}
