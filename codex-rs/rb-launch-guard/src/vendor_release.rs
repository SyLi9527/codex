use crate::vendor_authority_store::VendorCurrentSnapshotV1;
use crate::vendor_codec::Cursor;
use crate::vendor_codec::decode_carrier;
use crate::vendor_codec::parse_timestamp;
use ed25519_dalek::Signature;
use ed25519_dalek::VerifyingKey;
use sha2::Digest;
use sha2::Sha256;

const BUNDLE_MAGIC: &[u8; 6] = b"RBVO1\0";
const BUNDLE_VERSION: u8 = 1;
const MANIFEST_BODY_MAGIC: &[u8; 4] = b"MAN1";
const RELEASE_BODY_MAGIC: &[u8; 4] = b"REL1";
const MANIFEST_SIGNATURE_DOMAIN: &[u8] = b"rb.vendor-manifest.v1\0";
const RELEASE_SIGNATURE_DOMAIN: &[u8] = b"rb.vendor-release.v1\0";
const KEY_ID_DOMAIN: &[u8] = b"rb.vendor-release-key-id.v1\0ed25519\0";
const MANIFEST_MAX_BYTES: usize = 4 * 1024;
const RELEASE_MAX_BYTES: usize = 16 * 1024;
const BUNDLE_MAX_BYTES: usize =
    BUNDLE_MAGIC.len() + 1 + 4 + MANIFEST_MAX_BYTES + 4 + RELEASE_MAX_BYTES;
const DIGEST_BYTES: usize = 32;
const SIGNATURE_BYTES: usize = 64;
const ED25519_ALGORITHM: u8 = 1;
const CERT_CURRENT: u8 = 1;
const CERT_RETIRING: u8 = 2;
pub(crate) const ACTOR_AUTHORITY_SET_DOMAIN: &[u8] = b"rb.vendor-actor-authority-set.v1\0";

// RFC 8032 test vector 1 public key. Its private seed exists only in tests.
const TEST_VENDOR_ROOT_PUBLIC_KEY: [u8; DIGEST_BYTES] = [
    0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7, 0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64, 0x07, 0x3a,
    0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25, 0xaf, 0x02, 0x1a, 0x68, 0xf7, 0x07, 0x51, 0x1a,
];

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum VendorReleaseError {
    CarrierTooLong,
    InvalidCarrier,
    InvalidEncoding,
    InvalidBundle,
    InvalidArtifact,
    InvalidTimestamp,
    InvalidSignature,
    InvalidTrustTransition,
    InvalidRelease,
}

/// A binary-pinned test trust anchor. Callers cannot select its public key.
pub(crate) struct PinnedVendorAnchorV1 {
    root_key: VerifyingKey,
    key_id: [u8; DIGEST_BYTES],
}

impl PinnedVendorAnchorV1 {
    #[expect(
        clippy::expect_used,
        reason = "the pinned RFC 8032 public key is a static test invariant"
    )]
    pub(crate) fn for_test_fixture() -> Self {
        let root_key = VerifyingKey::from_bytes(&TEST_VENDOR_ROOT_PUBLIC_KEY)
            .expect("the pinned RFC 8032 public key is valid");
        Self {
            root_key,
            key_id: derive_key_id(&TEST_VENDOR_ROOT_PUBLIC_KEY),
        }
    }
}

/// Owned bounded bytes from the one and only release-offer carrier.
pub(crate) struct OwnedVendorOfferBundleV1 {
    raw: Box<[u8]>,
    digest: [u8; DIGEST_BYTES],
    manifest: Box<[u8]>,
    release: Box<[u8]>,
}

impl OwnedVendorOfferBundleV1 {
    pub(crate) fn digest(&self) -> &[u8; DIGEST_BYTES] {
        &self.digest
    }

    pub(crate) fn raw(&self) -> &[u8] {
        &self.raw
    }
}

pub(crate) struct VerifiedVendorGenesisV1 {
    manifest: VerifiedManifestV1,
    release: VerifiedReleaseV1,
    bundle: OwnedVendorOfferBundleV1,
}

impl VerifiedVendorGenesisV1 {
    pub(crate) fn trust_sequence(&self) -> u64 {
        self.manifest.trust_sequence
    }

    pub(crate) fn manifest_digest(&self) -> &[u8; DIGEST_BYTES] {
        &self.manifest.object_digest
    }

    pub(crate) fn release_object_digest(&self) -> &[u8; DIGEST_BYTES] {
        &self.release.object_digest
    }

    pub(crate) fn release_sequence(&self) -> u64 {
        self.release.release_sequence
    }

    pub(crate) fn bundle_digest(&self) -> &[u8; DIGEST_BYTES] {
        self.bundle.digest()
    }

    pub(crate) fn actor_authorities(&self) -> &ActorAuthoritySetV1 {
        &self.release.actor_authorities
    }

    pub(crate) fn bundle_raw(&self) -> &[u8] {
        self.bundle.raw()
    }
}

pub(crate) struct VerifiedVendorOfferV1 {
    manifest: VerifiedManifestV1,
    release: VerifiedReleaseV1,
    bundle: OwnedVendorOfferBundleV1,
}

impl VerifiedVendorOfferV1 {
    pub(crate) fn trust_sequence(&self) -> u64 {
        self.manifest.trust_sequence
    }

    pub(crate) fn release_sequence(&self) -> u64 {
        self.release.release_sequence
    }

    pub(crate) fn release_object_digest(&self) -> &[u8; DIGEST_BYTES] {
        &self.release.object_digest
    }

    pub(crate) fn manifest_digest(&self) -> &[u8; DIGEST_BYTES] {
        &self.manifest.object_digest
    }

    pub(crate) fn bundle_digest(&self) -> &[u8; DIGEST_BYTES] {
        self.bundle.digest()
    }

    pub(crate) fn actor_authorities(&self) -> &ActorAuthoritySetV1 {
        &self.release.actor_authorities
    }

    pub(crate) fn bundle_raw(&self) -> &[u8] {
        self.bundle.raw()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub(crate) enum VendorActorRoleV1 {
    Gateway = 1,
    Main = 2,
    Renderer = 3,
    ModelBroker = 4,
    NetworkBroker = 5,
    CurrentStateBroker = 6,
    Updater = 7,
}

impl VendorActorRoleV1 {
    pub(crate) const ALL: [Self; 7] = [
        Self::Gateway,
        Self::Main,
        Self::Renderer,
        Self::ModelBroker,
        Self::NetworkBroker,
        Self::CurrentStateBroker,
        Self::Updater,
    ];

    fn index(self) -> usize {
        usize::from(self as u8) - 1
    }
}

pub(crate) struct ActorAuthoritySetV1 {
    tuples: [[u8; DIGEST_BYTES]; VendorActorRoleV1::ALL.len()],
    digest: [u8; DIGEST_BYTES],
}

impl ActorAuthoritySetV1 {
    pub(crate) fn tuple(&self, role: VendorActorRoleV1) -> &[u8; DIGEST_BYTES] {
        &self.tuples[role.index()]
    }

    pub(crate) fn digest(&self) -> &[u8; DIGEST_BYTES] {
        &self.digest
    }
}

struct VerifiedManifestV1 {
    object_digest: [u8; DIGEST_BYTES],
    trust_sequence: u64,
    previous_digest: [u8; DIGEST_BYTES],
    certificates: Vec<ReleaseKeyCertificateV1>,
    revoked_key_ids: Vec<[u8; DIGEST_BYTES]>,
    revoked_release_digests: Vec<[u8; DIGEST_BYTES]>,
}

struct ReleaseKeyCertificateV1 {
    digest: [u8; DIGEST_BYTES],
    key_id: [u8; DIGEST_BYTES],
    key: VerifyingKey,
    lifecycle: u8,
    first_release_sequence: u64,
    last_release_sequence: u64,
    not_before: i64,
    expires_at: i64,
}

struct VerifiedReleaseV1 {
    release_sequence: u64,
    previous_release_digest: [u8; DIGEST_BYTES],
    object_digest: [u8; DIGEST_BYTES],
    actor_authorities: ActorAuthoritySetV1,
}

pub(crate) fn admit_vendor_offer_bundle(
    encoded: &str,
) -> Result<OwnedVendorOfferBundleV1, VendorReleaseError> {
    let raw = decode_carrier(encoded, BUNDLE_MAX_BYTES)?;
    let mut cursor = Cursor::new(&raw);
    if cursor.take(BUNDLE_MAGIC.len())? != BUNDLE_MAGIC || cursor.u8()? != BUNDLE_VERSION {
        return Err(VendorReleaseError::InvalidBundle);
    }
    let manifest_len = cursor.u32_len(MANIFEST_MAX_BYTES)?;
    let manifest = cursor.take(manifest_len)?.to_vec().into_boxed_slice();
    let release_len = cursor.u32_len(RELEASE_MAX_BYTES)?;
    let release = cursor.take(release_len)?.to_vec().into_boxed_slice();
    if !cursor.is_done() {
        return Err(VendorReleaseError::InvalidBundle);
    }
    Ok(OwnedVendorOfferBundleV1 {
        digest: sha256(&raw),
        raw: raw.into_boxed_slice(),
        manifest,
        release,
    })
}

pub(crate) fn verify_vendor_genesis(
    bundle: OwnedVendorOfferBundleV1,
    anchor: &PinnedVendorAnchorV1,
    observed_wall: &str,
) -> Result<VerifiedVendorGenesisV1, VendorReleaseError> {
    let observed_wall = parse_timestamp(observed_wall)?;
    let manifest = verify_manifest(&bundle.manifest, anchor, observed_wall)?;
    if manifest.trust_sequence != 1 || manifest.previous_digest != [0; DIGEST_BYTES] {
        return Err(VendorReleaseError::InvalidTrustTransition);
    }
    let release = verify_release(&bundle.release, &manifest, observed_wall)?;
    if release.release_sequence != 1 || release.previous_release_digest != [0; DIGEST_BYTES] {
        return Err(VendorReleaseError::InvalidRelease);
    }
    Ok(VerifiedVendorGenesisV1 {
        manifest,
        release,
        bundle,
    })
}

pub(crate) fn verify_vendor_offer(
    bundle: OwnedVendorOfferBundleV1,
    anchor: &PinnedVendorAnchorV1,
    current: &VendorCurrentSnapshotV1,
    observed_wall: &str,
) -> Result<VerifiedVendorOfferV1, VendorReleaseError> {
    let observed_wall = parse_timestamp(observed_wall)?;
    let manifest = verify_manifest(&bundle.manifest, anchor, observed_wall)?;
    let same_manifest = manifest.trust_sequence == current.trust_sequence()
        && &manifest.object_digest == current.manifest_digest();
    let next_manifest = manifest.trust_sequence
        == current
            .trust_sequence()
            .checked_add(1)
            .ok_or(VendorReleaseError::InvalidTrustTransition)?
        && &manifest.previous_digest == current.manifest_digest();
    if !same_manifest && !next_manifest {
        return Err(VendorReleaseError::InvalidTrustTransition);
    }
    let release = verify_release(&bundle.release, &manifest, observed_wall)?;
    if release.release_sequence
        != current
            .release_sequence()
            .checked_add(1)
            .ok_or(VendorReleaseError::InvalidRelease)?
        || &release.previous_release_digest != current.release_digest()
        || manifest
            .revoked_release_digests
            .binary_search(&release.object_digest)
            .is_ok()
    {
        return Err(VendorReleaseError::InvalidRelease);
    }
    Ok(VerifiedVendorOfferV1 {
        manifest,
        release,
        bundle,
    })
}

fn verify_manifest(
    object: &[u8],
    anchor: &PinnedVendorAnchorV1,
    observed_wall: i64,
) -> Result<VerifiedManifestV1, VendorReleaseError> {
    let body = verify_signed_object(object, MANIFEST_SIGNATURE_DOMAIN, &anchor.root_key)?;
    let mut cursor = Cursor::new(body);
    if cursor.take(MANIFEST_BODY_MAGIC.len())? != MANIFEST_BODY_MAGIC {
        return Err(VendorReleaseError::InvalidArtifact);
    }
    let trust_sequence = cursor.u64()?;
    let previous_digest = cursor.digest()?;
    if cursor.digest()? != anchor.key_id || trust_sequence == 0 {
        return Err(VendorReleaseError::InvalidArtifact);
    }
    let certificate_count = usize::from(cursor.u8()?);
    if certificate_count == 0 {
        return Err(VendorReleaseError::InvalidArtifact);
    }
    let mut certificates = Vec::with_capacity(certificate_count);
    let mut certificate_key_ids = Vec::with_capacity(certificate_count);
    let mut previous_entry: Option<&[u8]> = None;
    let mut current_count = 0;
    for _ in 0..certificate_count {
        let entry_len = cursor.u16_len(256)?;
        let entry = cursor.take(entry_len)?;
        if previous_entry.is_some_and(|previous| previous >= entry) {
            return Err(VendorReleaseError::InvalidArtifact);
        }
        previous_entry = Some(entry);
        let certificate = parse_certificate(entry, observed_wall)?;
        if certificate_key_ids.contains(&certificate.key_id) {
            return Err(VendorReleaseError::InvalidArtifact);
        }
        certificate_key_ids.push(certificate.key_id);
        current_count += usize::from(certificate.lifecycle == CERT_CURRENT);
        certificates.push(certificate);
    }
    let revoked_key_ids = cursor.sorted_digests()?;
    let revoked_release_digests = cursor.sorted_digests()?;
    if !cursor.is_done()
        || current_count != 1
        || certificates.iter().any(|certificate| {
            revoked_key_ids.binary_search(&certificate.key_id).is_ok()
                && certificate.lifecycle == CERT_CURRENT
        })
    {
        return Err(VendorReleaseError::InvalidArtifact);
    }
    Ok(VerifiedManifestV1 {
        object_digest: object_digest(MANIFEST_SIGNATURE_DOMAIN, body),
        trust_sequence,
        previous_digest,
        certificates,
        revoked_key_ids,
        revoked_release_digests,
    })
}

fn parse_certificate(
    entry: &[u8],
    observed_wall: i64,
) -> Result<ReleaseKeyCertificateV1, VendorReleaseError> {
    let mut cursor = Cursor::new(entry);
    if cursor.u8()? != ED25519_ALGORITHM {
        return Err(VendorReleaseError::InvalidArtifact);
    }
    let public_key = cursor.digest()?;
    let key =
        VerifyingKey::from_bytes(&public_key).map_err(|_| VendorReleaseError::InvalidSignature)?;
    let key_id = cursor.digest()?;
    let lifecycle = cursor.u8()?;
    let first_release_sequence = cursor.u64()?;
    let last_release_sequence = cursor.u64()?;
    let not_before = cursor.timestamp()?;
    let expires_at = cursor.timestamp()?;
    if !cursor.is_done()
        || key_id != derive_key_id(&public_key)
        || !matches!(lifecycle, CERT_CURRENT | CERT_RETIRING)
        || first_release_sequence == 0
        || first_release_sequence > last_release_sequence
        || observed_wall < not_before
        || observed_wall >= expires_at
    {
        return Err(VendorReleaseError::InvalidArtifact);
    }
    Ok(ReleaseKeyCertificateV1 {
        digest: sha256(entry),
        key_id,
        key,
        lifecycle,
        first_release_sequence,
        last_release_sequence,
        not_before,
        expires_at,
    })
}

fn verify_release(
    object: &[u8],
    manifest: &VerifiedManifestV1,
    observed_wall: i64,
) -> Result<VerifiedReleaseV1, VendorReleaseError> {
    let (body, signature, body_end) = split_signed_object(object, RELEASE_SIGNATURE_DOMAIN)?;
    let mut cursor = Cursor::new(body);
    if cursor.take(RELEASE_BODY_MAGIC.len())? != RELEASE_BODY_MAGIC {
        return Err(VendorReleaseError::InvalidArtifact);
    }
    let release_sequence = cursor.u64()?;
    let previous_release_digest = cursor.digest()?;
    let target_manifest_digest = cursor.digest()?;
    let signer_key_id = cursor.digest()?;
    let certificate_digest = cursor.digest()?;
    let not_before = cursor.timestamp()?;
    let expires_at = cursor.timestamp()?;
    let actor_authorities = parse_actor_authorities(&mut cursor)?;
    if !cursor.is_done() || target_manifest_digest != manifest.object_digest {
        return Err(VendorReleaseError::InvalidRelease);
    }
    let certificate = manifest
        .certificates
        .iter()
        .find(|certificate| {
            certificate.key_id == signer_key_id && certificate.digest == certificate_digest
        })
        .ok_or(VendorReleaseError::InvalidRelease)?;
    if manifest
        .revoked_key_ids
        .binary_search(&signer_key_id)
        .is_ok()
        || release_sequence < certificate.first_release_sequence
        || release_sequence > certificate.last_release_sequence
        || observed_wall < not_before
        || observed_wall >= expires_at
        || observed_wall < certificate.not_before
        || observed_wall >= certificate.expires_at
    {
        return Err(VendorReleaseError::InvalidRelease);
    }
    certificate
        .key
        .verify_strict(&object[..body_end], &signature)
        .map_err(|_| VendorReleaseError::InvalidSignature)?;
    Ok(VerifiedReleaseV1 {
        release_sequence,
        previous_release_digest,
        object_digest: object_digest(RELEASE_SIGNATURE_DOMAIN, body),
        actor_authorities,
    })
}

fn parse_actor_authorities(
    cursor: &mut Cursor<'_>,
) -> Result<ActorAuthoritySetV1, VendorReleaseError> {
    if usize::from(cursor.u8()?) != VendorActorRoleV1::ALL.len() {
        return Err(VendorReleaseError::InvalidRelease);
    }
    let mut tuples = [[0_u8; DIGEST_BYTES]; VendorActorRoleV1::ALL.len()];
    let mut hasher = Sha256::new();
    hasher.update(ACTOR_AUTHORITY_SET_DOMAIN);
    hasher.update([VendorActorRoleV1::ALL.len() as u8]);
    for role in VendorActorRoleV1::ALL {
        let encoded_role = cursor.u8()?;
        if encoded_role != role as u8 {
            return Err(VendorReleaseError::InvalidRelease);
        }
        let tuple = cursor.digest()?;
        tuples[role.index()] = tuple;
        hasher.update([encoded_role]);
        hasher.update(tuple);
    }
    Ok(ActorAuthoritySetV1 {
        tuples,
        digest: hasher.finalize().into(),
    })
}

fn verify_signed_object<'a>(
    object: &'a [u8],
    domain: &[u8],
    key: &VerifyingKey,
) -> Result<&'a [u8], VendorReleaseError> {
    let (body, signature, body_end) = split_signed_object(object, domain)?;
    key.verify_strict(&object[..body_end], &signature)
        .map_err(|_| VendorReleaseError::InvalidSignature)?;
    Ok(body)
}

fn split_signed_object<'a>(
    object: &'a [u8],
    domain: &[u8],
) -> Result<(&'a [u8], Signature, usize), VendorReleaseError> {
    if object.len() < domain.len() + 8 + SIGNATURE_BYTES || &object[..domain.len()] != domain {
        return Err(VendorReleaseError::InvalidArtifact);
    }
    let body_len = usize::try_from(u64::from_be_bytes(
        object[domain.len()..domain.len() + 8]
            .try_into()
            .map_err(|_| VendorReleaseError::InvalidArtifact)?,
    ))
    .map_err(|_| VendorReleaseError::InvalidArtifact)?;
    let body_start = domain.len() + 8;
    let body_end = body_start
        .checked_add(body_len)
        .ok_or(VendorReleaseError::InvalidArtifact)?;
    if body_end + SIGNATURE_BYTES != object.len() {
        return Err(VendorReleaseError::InvalidArtifact);
    }
    let signature = Signature::from_slice(&object[body_end..])
        .map_err(|_| VendorReleaseError::InvalidSignature)?;
    Ok((&object[body_start..body_end], signature, body_end))
}

fn derive_key_id(public_key: &[u8; DIGEST_BYTES]) -> [u8; DIGEST_BYTES] {
    let mut hasher = Sha256::new();
    hasher.update(KEY_ID_DOMAIN);
    hasher.update(public_key);
    hasher.finalize().into()
}

#[expect(
    clippy::expect_used,
    reason = "usize to u64 is infallible on all supported targets and the body length is bounded by BUNDLE_MAX_BYTES"
)]
fn object_digest(domain: &[u8], body: &[u8]) -> [u8; DIGEST_BYTES] {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update(
        u64::try_from(body.len())
            .expect("bounded body length")
            .to_be_bytes(),
    );
    hasher.update(body);
    hasher.finalize().into()
}

fn sha256(bytes: &[u8]) -> [u8; DIGEST_BYTES] {
    Sha256::digest(bytes).into()
}
