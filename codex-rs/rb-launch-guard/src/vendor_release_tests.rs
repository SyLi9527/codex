// Test assertions express failure by panicking by design, while the workspace
// denies unwrap/expect globally; this module carries a scoped allowance.
#![allow(clippy::expect_used, clippy::unwrap_used)]

use super::vendor_authority_store::VendorCurrentSnapshotV1;
use super::vendor_release::PinnedVendorAnchorV1;
use super::vendor_release::VendorReleaseError;
use super::vendor_release::admit_vendor_offer_bundle;
use super::vendor_release::verify_vendor_genesis;
use super::vendor_release::verify_vendor_offer;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ed25519_dalek::Signature;
use ed25519_dalek::Signer;
use ed25519_dalek::SigningKey;
use ed25519_dalek::Verifier;
use ed25519_dalek::VerifyingKey;
use pretty_assertions::assert_eq;
use sha2::Digest;
use sha2::Sha256;

const BUNDLE_MAGIC: &[u8] = b"RBVO1\0";
const MANIFEST_BODY_MAGIC: &[u8] = b"MAN1";
const RELEASE_BODY_MAGIC: &[u8] = b"REL1";
const MANIFEST_DOMAIN: &[u8] = b"rb.vendor-manifest.v1\0";
const RELEASE_DOMAIN: &[u8] = b"rb.vendor-release.v1\0";
const KEY_ID_DOMAIN: &[u8] = b"rb.vendor-release-key-id.v1\0ed25519\0";
const ACTOR_SET_DIGEST_DOMAIN: &[u8] = b"rb.vendor-actor-authority-set.v1\0";
const NOW: &str = "2026-08-28T12:00:00Z";
const NOT_BEFORE: &str = "2026-08-28T00:00:00Z";
const EXPIRES: &str = "2026-08-29T00:00:00Z";
const ROOT_SEED: [u8; 32] = [
    0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c, 0xc4,
    0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19, 0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae, 0x7f, 0x60,
];
// Generated independently with OpenSSL 3 Ed25519 pkeyutl and a Python
// struct/base64 encoder. This locks producer/verifier byte compatibility.
const OPENSSL_GENESIS_GOLDEN: &str = "UkJWTzEAAQAAASlyYi52ZW5kb3ItbWFuaWZlc3QudjEAAAAAAAAAAMtNQU4xAAAAAAAAAAEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAG62WTJ4k05LvAeH3i3EVmcZilOLomMnu94xaE9N5yZWAQB6Af0XJDhaoMdbZPt4zWAvodmR_ev3axPFjtcC6sg16fYYIfzkX7NTaeKgOe0UXsyxp3rp_98d3vX7uXlHJeL2oFcBAAAAAAAAAAEAAAAAAAAAZDIwMjYtMDgtMjhUMDA6MDA6MDBaMjAyNi0wOC0yOVQwMDowMDowMFoAAHWxpNra3EetE5kH9rUCnnluwCh6mXUrixb6Fy5JX8VaGeUDQTuRocNTt3yPOHyhwfWuMQoAshWWtRNdFmKutQ4AAAH5cmIudmVuZG9yLXJlbGVhc2UudjEAAAAAAAAAAZxSRUwxAAAAAAAAAAEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAPV9mcj8y2cG_FPj4bGAirbr43_6A099u4dSCe_eIUpGIfzkX7NTaeKgOe0UXsyxp3rp_98d3vX7uXlHJeL2oFe9pECmQPUH0zGUhZXSwrYblNMdqtx6aHXZjZBgaHDbkzIwMjYtMDgtMjhUMDA6MDA6MDBaMjAyNi0wOC0yOVQwMDowMDowMFoHAQsLCwsLCwsLCwsLCwsLCwsLCwsLCwsLCwsLCwsLCwsLAgwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMAw0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NBA4ODg4ODg4ODg4ODg4ODg4ODg4ODg4ODg4ODg4ODg4OBQ8PDw8PDw8PDw8PDw8PDw8PDw8PDw8PDw8PDw8PDw8PBhAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQBxERERERERERERERERERERERERERERERERERERERERERZwrjA4mUhke3lCuV6DsVYanKPHHzvSH7qMc76vm_i657dtPXuKTf16x3AoivxyWwv26MKcLiHhX2YYYIbLP5BA";

pub(super) fn genesis_carrier_fixture() -> String {
    bundle_fixture(
        &SigningKey::from_bytes(&ROOT_SEED),
        &SigningKey::from_bytes(&[9; 32]),
        1,
        [0; 32],
        1,
        [0; 32],
        11,
    )
}

pub(super) fn next_carrier_fixture(previous_release_digest: [u8; 32]) -> String {
    bundle_fixture(
        &SigningKey::from_bytes(&ROOT_SEED),
        &SigningKey::from_bytes(&[9; 32]),
        1,
        [0; 32],
        2,
        previous_release_digest,
        12,
    )
}

/// Genesis variant with different content bytes: proves lease_epoch is not
/// derived from vendor bytes.
pub(super) fn alternate_genesis_carrier_fixture() -> String {
    bundle_fixture(
        &SigningKey::from_bytes(&ROOT_SEED),
        &SigningKey::from_bytes(&[9; 32]),
        1,
        [0; 32],
        1,
        [0; 32],
        42,
    )
}

/// Next-release variant with different content bytes but the same chain
/// anchor: a second validly signed bundle for slot-conflict tests.
pub(super) fn alternate_next_carrier_fixture(previous_release_digest: [u8; 32]) -> String {
    bundle_fixture(
        &SigningKey::from_bytes(&ROOT_SEED),
        &SigningKey::from_bytes(&[9; 32]),
        1,
        [0; 32],
        2,
        previous_release_digest,
        13,
    )
}

#[test]
fn one_owned_bundle_verifies_genesis_and_exact_next_release_chain() {
    let root = SigningKey::from_bytes(&ROOT_SEED);
    let release = SigningKey::from_bytes(&[9; 32]);
    let genesis_carrier = bundle_fixture(&root, &release, 1, [0; 32], 1, [0; 32], 11);
    let genesis_bundle = admit_vendor_offer_bundle(&genesis_carrier).unwrap();
    let expected_bundle_digest = sha256(&URL_SAFE_NO_PAD.decode(&genesis_carrier).unwrap());
    assert_eq!(genesis_bundle.digest(), &expected_bundle_digest);
    assert_eq!(
        genesis_bundle.raw(),
        URL_SAFE_NO_PAD.decode(&genesis_carrier).unwrap()
    );
    let genesis = verify_vendor_genesis(
        genesis_bundle,
        &PinnedVendorAnchorV1::for_test_fixture(),
        NOW,
    )
    .unwrap();
    assert_eq!(genesis.release_sequence(), 1);
    assert_eq!(genesis.bundle_digest(), &expected_bundle_digest);
    for (index, role) in [
        super::vendor_release::VendorActorRoleV1::Gateway,
        super::vendor_release::VendorActorRoleV1::Main,
        super::vendor_release::VendorActorRoleV1::Renderer,
        super::vendor_release::VendorActorRoleV1::ModelBroker,
        super::vendor_release::VendorActorRoleV1::NetworkBroker,
        super::vendor_release::VendorActorRoleV1::CurrentStateBroker,
        super::vendor_release::VendorActorRoleV1::Updater,
    ]
    .into_iter()
    .enumerate()
    {
        assert_eq!(
            genesis.actor_authorities().tuple(role),
            &[11 + index as u8; 32]
        );
    }
    assert_eq!(genesis.actor_authorities().digest(), &actor_set_digest(11));

    let next_carrier = bundle_fixture(
        &root,
        &release,
        1,
        [0; 32],
        2,
        *genesis.release_object_digest(),
        12,
    );
    let next = verify_vendor_offer(
        admit_vendor_offer_bundle(&next_carrier).unwrap(),
        &PinnedVendorAnchorV1::for_test_fixture(),
        &VendorCurrentSnapshotV1::new_for_test(
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
        NOW,
    )
    .unwrap();
    assert_eq!(next.release_sequence(), 2);
    assert_ne!(
        next.release_object_digest(),
        genesis.release_object_digest()
    );
    assert_eq!(
        next.actor_authorities()
            .tuple(super::vendor_release::VendorActorRoleV1::Updater),
        &[18; 32]
    );
    assert_eq!(next.manifest_digest(), genesis.manifest_digest());
    assert_eq!(
        next.bundle_digest(),
        &sha256(&URL_SAFE_NO_PAD.decode(&next_carrier).unwrap())
    );
}

#[test]
fn independent_openssl_golden_matches_exact_bytes_and_verifies() {
    assert_eq!(genesis_carrier_fixture(), OPENSSL_GENESIS_GOLDEN);
    let bundle = admit_vendor_offer_bundle(OPENSSL_GENESIS_GOLDEN).unwrap();
    assert_eq!(
        bundle.digest(),
        &[
            0xc3, 0xef, 0xbc, 0x77, 0xe6, 0x0c, 0xb9, 0xb7, 0xa7, 0x98, 0xbe, 0x5a, 0x81, 0x5c,
            0xb4, 0xc0, 0x93, 0x49, 0xb2, 0x86, 0xf0, 0x09, 0x8b, 0xca, 0xda, 0x5d, 0x05, 0x5e,
            0xad, 0xa4, 0xfd, 0x6c,
        ]
    );
    verify_vendor_genesis(bundle, &PinnedVendorAnchorV1::for_test_fixture(), NOW).unwrap();
}

#[test]
fn outer_carrier_caps_lengths_eof_and_aliases_fail_before_verification() {
    let root = SigningKey::from_bytes(&ROOT_SEED);
    let release = SigningKey::from_bytes(&[9; 32]);
    let carrier = bundle_fixture(&root, &release, 1, [0; 32], 1, [0; 32], 11);
    assert_eq!(
        admit_vendor_offer_bundle(&"A".repeat(27_328)).err(),
        Some(VendorReleaseError::CarrierTooLong)
    );
    for invalid in [
        format!("{carrier}="),
        format!(" {carrier}"),
        "AB".to_string(),
    ] {
        assert_eq!(
            admit_vendor_offer_bundle(&invalid).err(),
            Some(VendorReleaseError::InvalidCarrier)
        );
    }

    let raw = URL_SAFE_NO_PAD.decode(&carrier).unwrap();
    let mut truncated = raw.clone();
    truncated.pop();
    assert!(admit_vendor_offer_bundle(&URL_SAFE_NO_PAD.encode(truncated)).is_err());
    let mut trailing = raw.clone();
    trailing.push(0);
    assert_eq!(
        admit_vendor_offer_bundle(&URL_SAFE_NO_PAD.encode(trailing)).err(),
        Some(VendorReleaseError::InvalidBundle)
    );
    let mut rewritten_length = raw;
    rewritten_length[7..11].copy_from_slice(&u32::MAX.to_be_bytes());
    assert_eq!(
        admit_vendor_offer_bundle(&URL_SAFE_NO_PAD.encode(rewritten_length)).err(),
        Some(VendorReleaseError::InvalidBundle)
    );
}

#[test]
fn segment_and_signature_domains_cannot_be_swapped_or_extended() {
    let root = SigningKey::from_bytes(&ROOT_SEED);
    let release = SigningKey::from_bytes(&[9; 32]);
    let (manifest, release_object) = signed_artifacts(&root, &release, 1, [0; 32], 1, [0; 32], 11);

    let swapped = encode_bundle(&release_object, &manifest);
    assert!(
        verify_vendor_genesis(
            admit_vendor_offer_bundle(&swapped).unwrap(),
            &PinnedVendorAnchorV1::for_test_fixture(),
            NOW,
        )
        .is_err()
    );

    let mut wrong_domain = release_object;
    wrong_domain[0] ^= 1;
    let wrong_domain = encode_bundle(&manifest, &wrong_domain);
    assert_eq!(
        verify_vendor_genesis(
            admit_vendor_offer_bundle(&wrong_domain).unwrap(),
            &PinnedVendorAnchorV1::for_test_fixture(),
            NOW,
        )
        .err(),
        Some(VendorReleaseError::InvalidArtifact)
    );

    let mut signed_trailing = manifest;
    let signature = signed_trailing.split_off(signed_trailing.len() - 64);
    signed_trailing.push(0xff);
    let body_len = u64::try_from(signed_trailing.len() - MANIFEST_DOMAIN.len() - 8).unwrap();
    signed_trailing[MANIFEST_DOMAIN.len()..MANIFEST_DOMAIN.len() + 8]
        .copy_from_slice(&body_len.to_be_bytes());
    signed_trailing.extend_from_slice(&signature);
    let invalid = encode_bundle(
        &signed_trailing,
        &signed_artifacts(&root, &release, 1, [0; 32], 1, [0; 32], 11).1,
    );
    assert_eq!(
        verify_vendor_genesis(
            admit_vendor_offer_bundle(&invalid).unwrap(),
            &PinnedVendorAnchorV1::for_test_fixture(),
            NOW,
        )
        .err(),
        Some(VendorReleaseError::InvalidSignature)
    );
}

#[test]
fn fixed_pinned_root_rejects_an_independent_valid_root() {
    let attacker = SigningKey::from_bytes(&[8; 32]);
    let release = SigningKey::from_bytes(&[9; 32]);
    let carrier = bundle_fixture(&attacker, &release, 1, [0; 32], 1, [0; 32], 11);
    assert_eq!(
        verify_vendor_genesis(
            admit_vendor_offer_bundle(&carrier).unwrap(),
            &PinnedVendorAnchorV1::for_test_fixture(),
            NOW,
        )
        .err(),
        Some(VendorReleaseError::InvalidSignature)
    );
}

#[test]
fn release_object_identity_is_derived_and_previous_digest_is_exact() {
    let root = SigningKey::from_bytes(&ROOT_SEED);
    let release = SigningKey::from_bytes(&[9; 32]);
    let genesis_carrier = bundle_fixture(&root, &release, 1, [0; 32], 1, [0; 32], 11);
    let genesis = verify_vendor_genesis(
        admit_vendor_offer_bundle(&genesis_carrier).unwrap(),
        &PinnedVendorAnchorV1::for_test_fixture(),
        NOW,
    )
    .unwrap();
    let changed_content = bundle_fixture(
        &root,
        &release,
        1,
        [0; 32],
        2,
        *genesis.release_object_digest(),
        99,
    );
    let changed = verify_vendor_offer(
        admit_vendor_offer_bundle(&changed_content).unwrap(),
        &PinnedVendorAnchorV1::for_test_fixture(),
        &VendorCurrentSnapshotV1::new_for_test(
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
        NOW,
    )
    .unwrap();
    assert_ne!(
        changed.release_object_digest(),
        genesis.release_object_digest()
    );

    let wrong_previous = bundle_fixture(&root, &release, 1, [0; 32], 2, [77; 32], 99);
    assert_eq!(
        verify_vendor_offer(
            admit_vendor_offer_bundle(&wrong_previous).unwrap(),
            &PinnedVendorAnchorV1::for_test_fixture(),
            &VendorCurrentSnapshotV1::new_for_test(
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
            NOW,
        )
        .err(),
        Some(VendorReleaseError::InvalidRelease)
    );
}

#[test]
fn certificate_algorithm_lifecycle_order_and_signer_binding_are_exact() {
    let root = SigningKey::from_bytes(&ROOT_SEED);
    let release = SigningKey::from_bytes(&[9; 32]);
    let mut certificate = certificate_entry(&release, 1);
    certificate[0] = 2;
    let invalid_algorithm = bundle_with_certificates(&root, &release, vec![certificate], 1);
    assert_eq!(
        verify_vendor_genesis(
            admit_vendor_offer_bundle(&invalid_algorithm).unwrap(),
            &PinnedVendorAnchorV1::for_test_fixture(),
            NOW,
        )
        .err(),
        Some(VendorReleaseError::InvalidArtifact)
    );

    let retiring_only =
        bundle_with_certificates(&root, &release, vec![certificate_entry(&release, 2)], 1);
    assert_eq!(
        verify_vendor_genesis(
            admit_vendor_offer_bundle(&retiring_only).unwrap(),
            &PinnedVendorAnchorV1::for_test_fixture(),
            NOW,
        )
        .err(),
        Some(VendorReleaseError::InvalidArtifact)
    );

    let duplicate = certificate_entry(&release, 1);
    let duplicate =
        bundle_with_certificates(&root, &release, vec![duplicate.clone(), duplicate], 1);
    assert_eq!(
        verify_vendor_genesis(
            admit_vendor_offer_bundle(&duplicate).unwrap(),
            &PinnedVendorAnchorV1::for_test_fixture(),
            NOW,
        )
        .err(),
        Some(VendorReleaseError::InvalidArtifact)
    );

    let same_key_two_lifecycles = bundle_with_certificates(
        &root,
        &release,
        vec![
            certificate_entry(&release, 1),
            certificate_entry(&release, 2),
        ],
        1,
    );
    assert_eq!(
        verify_vendor_genesis(
            admit_vendor_offer_bundle(&same_key_two_lifecycles).unwrap(),
            &PinnedVendorAnchorV1::for_test_fixture(),
            NOW,
        )
        .err(),
        Some(VendorReleaseError::InvalidArtifact)
    );

    let mut same_key_different_bounds = certificate_entry(&release, 2);
    same_key_different_bounds[66..74].copy_from_slice(&2_u64.to_be_bytes());
    let same_key_different_bounds = bundle_with_certificates(
        &root,
        &release,
        vec![certificate_entry(&release, 1), same_key_different_bounds],
        1,
    );
    assert_eq!(
        verify_vendor_genesis(
            admit_vendor_offer_bundle(&same_key_different_bounds).unwrap(),
            &PinnedVendorAnchorV1::for_test_fixture(),
            NOW,
        )
        .err(),
        Some(VendorReleaseError::InvalidArtifact)
    );

    let retiring = SigningKey::from_bytes(&[10; 32]);
    let distinct_keys = bundle_with_certificates(
        &root,
        &release,
        vec![
            certificate_entry(&release, 1),
            certificate_entry(&retiring, 2),
        ],
        1,
    );
    verify_vendor_genesis(
        admit_vendor_offer_bundle(&distinct_keys).unwrap(),
        &PinnedVendorAnchorV1::for_test_fixture(),
        NOW,
    )
    .unwrap();
}

#[test]
fn metadata_signer_and_certificate_digest_are_not_interchangeable() {
    let root = SigningKey::from_bytes(&ROOT_SEED);
    let release = SigningKey::from_bytes(&[9; 32]);
    let (manifest, release_object) = signed_artifacts(&root, &release, 1, [0; 32], 1, [0; 32], 11);
    for body_offset in [4 + 8 + 32 + 32, 4 + 8 + 32 + 32 + 32] {
        let mutated_release = mutate_and_resign_release(&release_object, &release, body_offset);
        let carrier = encode_bundle(&manifest, &mutated_release);
        assert_eq!(
            verify_vendor_genesis(
                admit_vendor_offer_bundle(&carrier).unwrap(),
                &PinnedVendorAnchorV1::for_test_fixture(),
                NOW,
            )
            .err(),
            Some(VendorReleaseError::InvalidRelease)
        );
    }
}

#[test]
fn actor_authority_set_requires_all_seven_roles_in_canonical_order() {
    let root = SigningKey::from_bytes(&ROOT_SEED);
    let release = SigningKey::from_bytes(&[9; 32]);
    let (_, release_object) = signed_artifacts(&root, &release, 1, [0; 32], 1, [0; 32], 11);
    const ACTOR_SET_OFFSET: usize = 4 + 8 + 32 + 32 + 32 + 32 + 20 + 20;
    for (offset, value) in [
        (ACTOR_SET_OFFSET, 6),
        (ACTOR_SET_OFFSET + 1, 2),
        (ACTOR_SET_OFFSET + 1, 0),
    ] {
        let mutated_release = mutate_and_resign_release(&release_object, &release, offset);
        let mut body = release_body_from_object(&mutated_release);
        body[offset] = value;
        let invalid_release = sign_object(RELEASE_DOMAIN, &body, &release);
        let manifest = signed_artifacts(&root, &release, 1, [0; 32], 1, [0; 32], 11).0;
        assert_eq!(
            verify_vendor_genesis(
                admit_vendor_offer_bundle(&encode_bundle(&manifest, &invalid_release)).unwrap(),
                &PinnedVendorAnchorV1::for_test_fixture(),
                NOW,
            )
            .err(),
            Some(VendorReleaseError::InvalidRelease)
        );
    }
}

#[test]
fn trust_sequence_previous_manifest_and_timestamp_windows_are_exact() {
    let root = SigningKey::from_bytes(&ROOT_SEED);
    let release = SigningKey::from_bytes(&[9; 32]);
    let genesis_carrier = genesis_carrier_fixture();
    let genesis = verify_vendor_genesis(
        admit_vendor_offer_bundle(&genesis_carrier).unwrap(),
        &PinnedVendorAnchorV1::for_test_fixture(),
        NOW,
    )
    .unwrap();
    assert_eq!(
        verify_vendor_genesis(
            admit_vendor_offer_bundle(&genesis_carrier).unwrap(),
            &PinnedVendorAnchorV1::for_test_fixture(),
            "2026-08-28T12:00:00.0Z",
        )
        .err(),
        Some(VendorReleaseError::InvalidTimestamp)
    );
    assert_eq!(
        verify_vendor_genesis(
            admit_vendor_offer_bundle(&genesis_carrier).unwrap(),
            &PinnedVendorAnchorV1::for_test_fixture(),
            EXPIRES,
        )
        .err(),
        Some(VendorReleaseError::InvalidArtifact)
    );

    for (trust_sequence, previous_manifest_digest) in [
        (3, *genesis.manifest_digest()),
        (2, [88; 32]),
        (1, *genesis.manifest_digest()),
    ] {
        let carrier = bundle_fixture(
            &root,
            &release,
            trust_sequence,
            previous_manifest_digest,
            2,
            *genesis.release_object_digest(),
            12,
        );
        assert_eq!(
            verify_vendor_offer(
                admit_vendor_offer_bundle(&carrier).unwrap(),
                &PinnedVendorAnchorV1::for_test_fixture(),
                &VendorCurrentSnapshotV1::new_for_test(
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
                NOW,
            )
            .err(),
            Some(VendorReleaseError::InvalidTrustTransition)
        );
    }
}

#[test]
fn segment_caps_accept_exact_limits_and_reject_one_more() {
    let exact = raw_bundle(&vec![1; 4_096], &vec![2; 16_384]);
    assert!(admit_vendor_offer_bundle(&URL_SAFE_NO_PAD.encode(exact)).is_ok());

    for (manifest_len, release_len) in [(4_097, 1), (1, 16_385)] {
        let carrier =
            URL_SAFE_NO_PAD.encode(raw_bundle(&vec![1; manifest_len], &vec![2; release_len]));
        assert!(matches!(
            admit_vendor_offer_bundle(&carrier).err(),
            Some(VendorReleaseError::CarrierTooLong | VendorReleaseError::InvalidBundle)
        ));
    }
}

#[test]
fn strict_verifier_rejects_small_order_and_noncanonical_scalar_vectors() {
    let mut weak_public = [0_u8; 32];
    weak_public[0] = 1;
    let weak_key = VerifyingKey::from_bytes(&weak_public).unwrap();
    let mut forged = [0_u8; 64];
    forged[0] = 1;
    let forged = Signature::from_bytes(&forged);
    let message = b"independent strict Ed25519 protocol vector";
    assert!(weak_key.verify(message, &forged).is_ok());
    assert!(weak_key.verify_strict(message, &forged).is_err());

    let root = SigningKey::from_bytes(&ROOT_SEED);
    let release = SigningKey::from_bytes(&[9; 32]);
    let (mut manifest, release_object) =
        signed_artifacts(&root, &release, 1, [0; 32], 1, [0; 32], 11);
    let scalar_start = manifest.len() - 32;
    let mut scalar: [u8; 32] = manifest[scalar_start..].try_into().unwrap();
    add_group_order(&mut scalar);
    manifest[scalar_start..].copy_from_slice(&scalar);
    let invalid = encode_bundle(&manifest, &release_object);
    assert_eq!(
        verify_vendor_genesis(
            admit_vendor_offer_bundle(&invalid).unwrap(),
            &PinnedVendorAnchorV1::for_test_fixture(),
            NOW,
        )
        .err(),
        Some(VendorReleaseError::InvalidSignature)
    );
}

fn bundle_fixture(
    root: &SigningKey,
    release: &SigningKey,
    trust_sequence: u64,
    previous_manifest_digest: [u8; 32],
    release_sequence: u64,
    previous_release_digest: [u8; 32],
    content_byte: u8,
) -> String {
    let (manifest, release_object) = signed_artifacts(
        root,
        release,
        trust_sequence,
        previous_manifest_digest,
        release_sequence,
        previous_release_digest,
        content_byte,
    );
    encode_bundle(&manifest, &release_object)
}

fn bundle_with_certificates(
    root: &SigningKey,
    release: &SigningKey,
    certificates: Vec<Vec<u8>>,
    release_sequence: u64,
) -> String {
    let manifest_body = manifest_body(root, 1, [0; 32], certificates, &[], &[]);
    let manifest = sign_object(MANIFEST_DOMAIN, &manifest_body, root);
    let manifest_digest = object_digest(MANIFEST_DOMAIN, &manifest_body);
    let certificate = certificate_entry(release, 1);
    let release_body = release_body(
        release,
        release_sequence,
        [0; 32],
        manifest_digest,
        sha256(&certificate),
        11,
    );
    let release_object = sign_object(RELEASE_DOMAIN, &release_body, release);
    encode_bundle(&manifest, &release_object)
}

fn signed_artifacts(
    root: &SigningKey,
    release: &SigningKey,
    trust_sequence: u64,
    previous_manifest_digest: [u8; 32],
    release_sequence: u64,
    previous_release_digest: [u8; 32],
    content_byte: u8,
) -> (Vec<u8>, Vec<u8>) {
    let certificate = certificate_entry(release, 1);
    let manifest_body = manifest_body(
        root,
        trust_sequence,
        previous_manifest_digest,
        vec![certificate.clone()],
        &[],
        &[],
    );
    let manifest = sign_object(MANIFEST_DOMAIN, &manifest_body, root);
    let release_body = release_body(
        release,
        release_sequence,
        previous_release_digest,
        object_digest(MANIFEST_DOMAIN, &manifest_body),
        sha256(&certificate),
        content_byte,
    );
    let release_object = sign_object(RELEASE_DOMAIN, &release_body, release);
    (manifest, release_object)
}

fn manifest_body(
    root: &SigningKey,
    trust_sequence: u64,
    previous_manifest_digest: [u8; 32],
    mut certificates: Vec<Vec<u8>>,
    revoked_keys: &[[u8; 32]],
    revoked_releases: &[[u8; 32]],
) -> Vec<u8> {
    certificates.sort();
    let mut body = Vec::new();
    body.extend_from_slice(MANIFEST_BODY_MAGIC);
    body.extend_from_slice(&trust_sequence.to_be_bytes());
    body.extend_from_slice(&previous_manifest_digest);
    body.extend_from_slice(&derive_key_id(&root.verifying_key().to_bytes()));
    body.push(u8::try_from(certificates.len()).unwrap());
    for certificate in certificates {
        body.extend_from_slice(&u16::try_from(certificate.len()).unwrap().to_be_bytes());
        body.extend_from_slice(&certificate);
    }
    append_digests(&mut body, revoked_keys);
    append_digests(&mut body, revoked_releases);
    body
}

fn certificate_entry(release: &SigningKey, lifecycle: u8) -> Vec<u8> {
    let public = release.verifying_key().to_bytes();
    let mut entry = Vec::new();
    entry.push(1);
    entry.extend_from_slice(&public);
    entry.extend_from_slice(&derive_key_id(&public));
    entry.push(lifecycle);
    entry.extend_from_slice(&1_u64.to_be_bytes());
    entry.extend_from_slice(&100_u64.to_be_bytes());
    entry.extend_from_slice(NOT_BEFORE.as_bytes());
    entry.extend_from_slice(EXPIRES.as_bytes());
    entry
}

fn release_body(
    release: &SigningKey,
    release_sequence: u64,
    previous_release_digest: [u8; 32],
    manifest_digest: [u8; 32],
    certificate_digest: [u8; 32],
    content_byte: u8,
) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(RELEASE_BODY_MAGIC);
    body.extend_from_slice(&release_sequence.to_be_bytes());
    body.extend_from_slice(&previous_release_digest);
    body.extend_from_slice(&manifest_digest);
    body.extend_from_slice(&derive_key_id(&release.verifying_key().to_bytes()));
    body.extend_from_slice(&certificate_digest);
    body.extend_from_slice(NOT_BEFORE.as_bytes());
    body.extend_from_slice(EXPIRES.as_bytes());
    body.push(7);
    for (index, value) in (content_byte..content_byte + 7).enumerate() {
        body.push(u8::try_from(index + 1).unwrap());
        body.extend_from_slice(&[value; 32]);
    }
    body
}

fn sign_object(domain: &[u8], body: &[u8], signer: &SigningKey) -> Vec<u8> {
    let mut object = Vec::new();
    object.extend_from_slice(domain);
    object.extend_from_slice(&u64::try_from(body.len()).unwrap().to_be_bytes());
    object.extend_from_slice(body);
    object.extend_from_slice(&signer.sign(&object).to_bytes());
    object
}

fn mutate_and_resign_release(object: &[u8], signer: &SigningKey, body_offset: usize) -> Vec<u8> {
    let body_start = RELEASE_DOMAIN.len() + 8;
    let body_end = object.len() - 64;
    let mut body = object[body_start..body_end].to_vec();
    body[body_offset] ^= 1;
    sign_object(RELEASE_DOMAIN, &body, signer)
}

fn release_body_from_object(object: &[u8]) -> Vec<u8> {
    let body_start = RELEASE_DOMAIN.len() + 8;
    object[body_start..object.len() - 64].to_vec()
}

fn encode_bundle(manifest: &[u8], release: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(raw_bundle(manifest, release))
}

fn raw_bundle(manifest: &[u8], release: &[u8]) -> Vec<u8> {
    let mut bundle = Vec::new();
    bundle.extend_from_slice(BUNDLE_MAGIC);
    bundle.push(1);
    bundle.extend_from_slice(&u32::try_from(manifest.len()).unwrap().to_be_bytes());
    bundle.extend_from_slice(manifest);
    bundle.extend_from_slice(&u32::try_from(release.len()).unwrap().to_be_bytes());
    bundle.extend_from_slice(release);
    bundle
}

fn append_digests(body: &mut Vec<u8>, values: &[[u8; 32]]) {
    body.push(u8::try_from(values.len()).unwrap());
    for value in values {
        body.extend_from_slice(value);
    }
}

fn derive_key_id(public_key: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(KEY_ID_DOMAIN);
    hasher.update(public_key);
    hasher.finalize().into()
}

fn object_digest(domain: &[u8], body: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update(u64::try_from(body.len()).unwrap().to_be_bytes());
    hasher.update(body);
    hasher.finalize().into()
}

fn sha256(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

fn actor_set_digest(content_byte: u8) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(ACTOR_SET_DIGEST_DOMAIN);
    hasher.update([7]);
    for (index, value) in (content_byte..content_byte + 7).enumerate() {
        hasher.update([u8::try_from(index + 1).unwrap()]);
        hasher.update([value; 32]);
    }
    hasher.finalize().into()
}

fn add_group_order(scalar: &mut [u8; 32]) {
    let order: [u8; 32] = [
        0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde,
        0x14, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10,
    ];
    let mut carry = 0_u16;
    for (value, addend) in scalar.iter_mut().zip(order) {
        let sum = u16::from(*value) + u16::from(addend) + carry;
        *value = sum as u8;
        carry = sum >> 8;
    }
    assert_eq!(carry, 0, "fixture signature scalar must not overflow");
}
