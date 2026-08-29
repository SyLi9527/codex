use super::SyntheticExecuteNowDispositionV1;
use crate::root_broker_store_tests::run_external_effect;
use std::path::Path;

pub(crate) fn execute_synthetic_effect_for_test(
    disposition: SyntheticExecuteNowDispositionV1,
    log: &Path,
) -> std::process::Output {
    let (operation_id, revision, effect_request_digest) = disposition.into_effect_invocation();
    let record =
        format!("callSeq={revision};opId={operation_id};payloadDigest={effect_request_digest}");
    run_external_effect(log, &record, false)
}
