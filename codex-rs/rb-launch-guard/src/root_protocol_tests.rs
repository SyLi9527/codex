// Test assertions express failure by panicking by design, while the workspace
// denies unwrap/expect globally; this module carries a scoped allowance.
#![allow(clippy::expect_used, clippy::unwrap_used)]

use super::root_protocol::ActorRoleV1;
use super::root_protocol::AuthenticatedActorSnapshotV1;
use super::root_protocol::BrokerRoleV1;
use super::root_protocol::ROOT_COMMAND_MAX_BYTES;
use super::root_protocol::RootMethodV1;
use super::root_protocol::RootProtocolError;
use super::root_protocol::admit_root_command;
use pretty_assertions::assert_eq;
use sha2::Digest;
use sha2::Sha256;

fn digest(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn command(method: &str, broker_role: Option<&str>, payload: &str) -> Vec<u8> {
    command_with_digest(method, broker_role, payload, &digest(payload.as_bytes()))
}

fn command_with_digest(
    method: &str,
    broker_role: Option<&str>,
    payload: &str,
    payload_digest: &str,
) -> Vec<u8> {
    let broker = broker_role.map_or("null".to_string(), |role| format!("\"{role}\""));
    format!(
        "{{\"schema\":\"rb.root-command.v1\",\"operationId\":\"operation-1\",\"expectedRevision\":1,\"clientNonce\":\"nonce-1\",\"method\":\"{method}\",\"brokerRole\":{broker},\"subjectDigest\":\"{}\",\"payload\":{payload:?},\"payloadDigest\":\"{}\"}}",
        "a".repeat(64),
        payload_digest
    )
    .into_bytes()
}

fn actor(role: ActorRoleV1, exact_message: &[u8]) -> AuthenticatedActorSnapshotV1 {
    AuthenticatedActorSnapshotV1::new_for_test(
        role,
        "c".repeat(64),
        3,
        5,
        "connection-1".to_string(),
        exact_message,
    )
}

fn admit(
    role: ActorRoleV1,
    method: &str,
    broker_role: Option<&str>,
) -> Result<super::root_protocol::AuthorizedRootCommandV1, RootProtocolError> {
    let bytes = if method == "release-offer-vendor-metadata" {
        let payload = super::vendor_release_tests::genesis_carrier_fixture();
        let bundle = super::vendor_release::admit_vendor_offer_bundle(&payload).unwrap();
        command_with_digest(method, broker_role, &payload, &digest(bundle.raw()))
    } else {
        command(method, broker_role, "opaque-payload")
    };
    admit_root_command(actor(role, &bytes), &bytes)
}

#[test]
fn bounded_admission_rejects_oversize_unknown_and_broker_shape_mismatch() {
    let oversized = vec![b' '; ROOT_COMMAND_MAX_BYTES + 1];
    assert_eq!(
        admit_root_command(actor(ActorRoleV1::Main, &oversized), &oversized).err(),
        Some(RootProtocolError::TooLong)
    );

    let mut unknown = command("public-status", None, "payload");
    unknown.pop();
    unknown.extend_from_slice(b",\"extra\":true}");
    assert_eq!(
        admit_root_command(actor(ActorRoleV1::Main, &unknown), &unknown).err(),
        Some(RootProtocolError::InvalidJson)
    );
    assert_eq!(
        admit(ActorRoleV1::ModelBroker, "broker-effect-start", None).err(),
        Some(RootProtocolError::BrokerRoleMismatch)
    );
    assert_eq!(
        admit(ActorRoleV1::Main, "public-status", Some("model")).err(),
        Some(RootProtocolError::BrokerRoleMismatch)
    );
}

#[test]
fn admission_binds_identity_to_exact_message_and_owned_payload() {
    let message_a = command("public-status", None, "payload-a");
    let message_b = command("launch-start", None, "payload-b");
    assert_eq!(
        admit_root_command(actor(ActorRoleV1::Main, &message_a), &message_b).err(),
        Some(RootProtocolError::MessageDigestMismatch)
    );

    let wrong_payload_digest = String::from_utf8(command("public-status", None, "payload-a"))
        .expect("utf8 fixture")
        .replacen(&digest(b"payload-a"), &"f".repeat(64), 1)
        .into_bytes();
    assert_eq!(
        admit_root_command(
            actor(ActorRoleV1::Main, &wrong_payload_digest),
            &wrong_payload_digest
        )
        .err(),
        Some(RootProtocolError::PayloadDigestMismatch)
    );

    let mut original = command("public-status", None, "payload-a");
    let authorized = admit_root_command(actor(ActorRoleV1::Main, &original), &original)
        .expect("admit exact message");
    original.fill(b'x');
    assert_eq!(authorized.command().method(), RootMethodV1::PublicStatus);
    assert_eq!(authorized.command().payload_digest(), digest(b"payload-a"));
}

#[test]
fn vendor_offer_admission_binds_payload_digest_to_owned_decoded_bundle() {
    let payload = super::vendor_release_tests::genesis_carrier_fixture();
    let bundle = super::vendor_release::admit_vendor_offer_bundle(&payload).unwrap();
    let bytes = command_with_digest(
        "release-offer-vendor-metadata",
        None,
        &payload,
        &digest(bundle.raw()),
    );
    let authorized = admit_root_command(actor(ActorRoleV1::Updater, &bytes), &bytes).unwrap();
    let owned = authorized.into_vendor_offer_command().unwrap();
    assert_eq!(owned.bundle_digest(), bundle.digest());

    let wrong = command("release-offer-vendor-metadata", None, &payload);
    assert_eq!(
        admit_root_command(actor(ActorRoleV1::Updater, &wrong), &wrong).err(),
        Some(RootProtocolError::PayloadDigestMismatch)
    );
}

#[test]
fn updater_identity_and_cas_fields_survive_crypto_verification() {
    let genesis_payload = super::vendor_release_tests::genesis_carrier_fixture();
    let genesis = super::vendor_release::verify_vendor_genesis(
        super::vendor_release::admit_vendor_offer_bundle(&genesis_payload).unwrap(),
        &super::vendor_release::PinnedVendorAnchorV1::for_test_fixture(),
        "2026-08-28T12:00:00Z",
    )
    .unwrap();
    let payload =
        super::vendor_release_tests::next_carrier_fixture(*genesis.release_object_digest());
    let bundle = super::vendor_release::admit_vendor_offer_bundle(&payload).unwrap();
    let bytes = command_with_digest(
        "release-offer-vendor-metadata",
        None,
        &payload,
        &digest(bundle.raw()),
    );
    let verified = admit_root_command(actor(ActorRoleV1::Updater, &bytes), &bytes)
        .unwrap()
        .into_vendor_offer_command()
        .unwrap()
        .verify(
            &super::vendor_release::PinnedVendorAnchorV1::for_test_fixture(),
            super::vendor_authority_store::VendorCurrentSnapshotV1::new_for_test(
                1,
                1,
                *genesis.manifest_digest(),
                1,
                *genesis.release_object_digest(),
                1,
                *genesis.actor_authorities().digest(),
                *genesis
                    .actor_authorities()
                    .tuple(super::vendor_release::VendorActorRoleV1::Updater),
            ),
            "2026-08-28T12:00:00Z",
        )
        .unwrap();
    assert_eq!(verified.actor().role(), ActorRoleV1::Updater);
    assert_eq!(verified.operation_id(), "operation-1");
    assert_eq!(verified.subject_digest(), "a".repeat(64));
    assert_eq!(verified.expected_revision(), 1);
    assert_eq!(verified.payload_digest(), digest(bundle.raw()));
    assert_eq!(verified.current().store_revision(), 1);
    assert_eq!(verified.current().trust_sequence(), 1);
    assert_eq!(
        verified.current().manifest_digest(),
        genesis.manifest_digest()
    );
    assert_eq!(verified.current().release_sequence(), 1);
    assert_eq!(
        verified.current().release_digest(),
        genesis.release_object_digest()
    );
    assert_eq!(verified.verified().release_sequence(), 2);
}

#[test]
fn actor_method_cross_product_enforces_exact_broker_role() {
    let actors = [
        ActorRoleV1::Gateway,
        ActorRoleV1::Main,
        ActorRoleV1::Renderer,
        ActorRoleV1::ModelBroker,
        ActorRoleV1::NetworkBroker,
        ActorRoleV1::CurrentStateBroker,
        ActorRoleV1::Updater,
        ActorRoleV1::Unknown,
    ];
    let methods = [
        ("launch-prepare", None),
        ("launch-start", None),
        ("launch-cancel", None),
        ("launch-query", None),
        ("broker-authorize", Some("model")),
        ("broker-cancel-before-claim", Some("model")),
        ("broker-query", Some("model")),
        ("broker-claim", Some("model")),
        ("broker-effect-start", Some("model")),
        ("broker-settle", Some("model")),
        ("release-offer-vendor-metadata", None),
        ("release-query-status", None),
        ("public-status", None),
    ];

    for actor_role in actors {
        for (method, broker_role) in methods {
            assert_eq!(
                admit(actor_role, method, broker_role).is_ok(),
                expected_allowed(actor_role, method, broker_role),
                "actor={actor_role:?}, method={method}, broker={broker_role:?}"
            );
        }
    }

    for (actor_role, exact_role) in [
        (ActorRoleV1::ModelBroker, "model"),
        (ActorRoleV1::NetworkBroker, "network"),
        (ActorRoleV1::CurrentStateBroker, "current-state"),
    ] {
        assert!(admit(actor_role, "broker-query", Some(exact_role)).is_ok());
        assert_eq!(
            admit(actor_role, "broker-query", None).err(),
            Some(RootProtocolError::BrokerRoleMismatch)
        );
        let wrong_role = if exact_role == "model" {
            "network"
        } else {
            "model"
        };
        assert_eq!(
            admit(actor_role, "broker-query", Some(wrong_role)).err(),
            Some(RootProtocolError::ActorDenied)
        );
    }
}

#[test]
fn authorized_command_preserves_store_cas_inputs() {
    let bytes = command("broker-claim", Some("model"), "opaque-payload");
    let authorized = admit_root_command(actor(ActorRoleV1::ModelBroker, &bytes), &bytes)
        .expect("valid broker claim command");
    let parsed = authorized.command();
    assert_eq!(parsed.method(), RootMethodV1::BrokerClaim);
    assert_eq!(parsed.broker_role(), Some(BrokerRoleV1::Model));
    assert_eq!(parsed.operation_id(), "operation-1");
    assert_eq!(parsed.expected_revision(), 1);
    assert_eq!(parsed.subject_digest(), "a".repeat(64));
    assert_eq!(parsed.payload_digest(), digest(b"opaque-payload"));

    let snapshot = authorized.actor();
    assert_eq!(snapshot.role(), ActorRoleV1::ModelBroker);
    assert_eq!(snapshot.component_tuple_digest(), "c".repeat(64));
    assert_eq!(snapshot.release_sequence(), 3);
    assert_eq!(snapshot.lease_epoch(), 5);
    assert_eq!(snapshot.connection_instance(), "connection-1");
    assert_eq!(snapshot.message_digest(), digest(&bytes));
}

fn expected_allowed(actor: ActorRoleV1, method: &str, broker_role: Option<&str>) -> bool {
    match actor {
        ActorRoleV1::Gateway => matches!(
            method,
            "launch-prepare"
                | "launch-start"
                | "launch-cancel"
                | "launch-query"
                | "broker-authorize"
                | "broker-cancel-before-claim"
                | "broker-query"
        ),
        ActorRoleV1::ModelBroker => broker_role == Some("model") && broker_owner_method(method),
        ActorRoleV1::NetworkBroker => broker_role == Some("network") && broker_owner_method(method),
        ActorRoleV1::CurrentStateBroker => {
            broker_role == Some("current-state") && broker_owner_method(method)
        }
        ActorRoleV1::Updater => matches!(
            method,
            "release-offer-vendor-metadata" | "release-query-status"
        ),
        ActorRoleV1::Main | ActorRoleV1::Renderer => method == "public-status",
        ActorRoleV1::Unknown => false,
    }
}

fn broker_owner_method(method: &str) -> bool {
    matches!(
        method,
        "broker-query" | "broker-claim" | "broker-effect-start" | "broker-settle"
    )
}
