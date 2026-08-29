use serde::Deserialize;
use sha2::Digest;
use sha2::Sha256;

use crate::vendor_authority_store::VendorCurrentSnapshotV1;
use crate::vendor_release::OwnedVendorOfferBundleV1;
use crate::vendor_release::PinnedVendorAnchorV1;
use crate::vendor_release::VendorReleaseError;
use crate::vendor_release::VerifiedVendorOfferV1;
use crate::vendor_release::admit_vendor_offer_bundle;
use crate::vendor_release::verify_vendor_offer;

pub(crate) const ROOT_COMMAND_MAX_BYTES: usize = 64 * 1024;
const ROOT_ID_MAX_BYTES: usize = 256;
const ROOT_DIGEST_BYTES: usize = 64;
const ROOT_PAYLOAD_MAX_BYTES: usize = 32 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ActorRoleV1 {
    Gateway,
    Main,
    Renderer,
    ModelBroker,
    NetworkBroker,
    CurrentStateBroker,
    Updater,
    Unknown,
}

impl ActorRoleV1 {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Gateway => "gateway",
            Self::Main => "main",
            Self::Renderer => "renderer",
            Self::ModelBroker => "model-broker",
            Self::NetworkBroker => "network-broker",
            Self::CurrentStateBroker => "current-state-broker",
            Self::Updater => "updater",
            Self::Unknown => "unknown",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum BrokerRoleV1 {
    Model,
    Network,
    CurrentState,
}

impl BrokerRoleV1 {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Model => "model",
            Self::Network => "network",
            Self::CurrentState => "current-state",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum RootMethodV1 {
    LaunchPrepare,
    LaunchStart,
    LaunchCancel,
    LaunchQuery,
    BrokerAuthorize,
    BrokerCancelBeforeClaim,
    BrokerQuery,
    BrokerClaim,
    BrokerEffectStart,
    BrokerSettle,
    ReleaseOfferVendorMetadata,
    ReleaseQueryStatus,
    PublicStatus,
}

#[derive(Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(crate) struct RootCommandV1 {
    schema: String,
    operation_id: String,
    expected_revision: u64,
    client_nonce: String,
    method: RootMethodV1,
    broker_role: Option<BrokerRoleV1>,
    subject_digest: String,
    payload: String,
    payload_digest: String,
}

impl RootCommandV1 {
    pub(crate) fn method(&self) -> RootMethodV1 {
        self.method
    }

    pub(crate) fn broker_role(&self) -> Option<BrokerRoleV1> {
        self.broker_role
    }

    pub(crate) fn operation_id(&self) -> &str {
        &self.operation_id
    }

    pub(crate) fn expected_revision(&self) -> u64 {
        self.expected_revision
    }

    pub(crate) fn subject_digest(&self) -> &str {
        &self.subject_digest
    }

    pub(crate) fn payload_digest(&self) -> &str {
        &self.payload_digest
    }
}

/// Identity facts established from the message-associated live code identity.
///
/// This is intentionally neither cloneable nor serializable. It is evidence
/// for a later store transaction recheck, not an authorization permit.
///
/// Live-seam contract (the product constructor is deliberately unimplemented;
/// CP3 stays product-unreachable behind `cfg(all(test, feature))`):
/// 1. The only product-path producer is the Main-side live code identity
///    verification. No path may fabricate this snapshot from raw
///    caller-supplied values, and no caller-supplied digest is ever trusted
///    as authorization by itself.
/// 2. `component_tuple_digest` is the lowercase hex encoding (exactly 64
///    characters from `[0-9a-f]`) of the vendor-signed canonical component
///    tuple for the actor role. The format is not a negotiable store input.
/// 3. Error boundary inside the stage transaction: a malformed digest maps to
///    `ActorIdentityMalformed` (identity-seam defect) and is strictly
///    distinct from the policy denial `ActorDenied` (role, release, epoch, or
///    tuple mismatch). Both outcomes fail closed and never fall back.
pub(crate) struct AuthenticatedActorSnapshotV1 {
    role: ActorRoleV1,
    component_tuple_digest: String,
    release_sequence: u64,
    lease_epoch: u64,
    connection_instance: String,
    message_digest: String,
}

impl AuthenticatedActorSnapshotV1 {
    #[cfg(test)]
    pub(crate) fn new_for_test(
        role: ActorRoleV1,
        component_tuple_digest: String,
        release_sequence: u64,
        lease_epoch: u64,
        connection_instance: String,
        exact_message_bytes: &[u8],
    ) -> Self {
        Self {
            role,
            component_tuple_digest,
            release_sequence,
            lease_epoch,
            connection_instance,
            message_digest: sha256_hex(exact_message_bytes),
        }
    }

    pub(crate) fn role(&self) -> ActorRoleV1 {
        self.role
    }

    pub(crate) fn component_tuple_digest(&self) -> &str {
        &self.component_tuple_digest
    }

    pub(crate) fn release_sequence(&self) -> u64 {
        self.release_sequence
    }

    pub(crate) fn lease_epoch(&self) -> u64 {
        self.lease_epoch
    }

    pub(crate) fn connection_instance(&self) -> &str {
        &self.connection_instance
    }

    pub(crate) fn message_digest(&self) -> &str {
        &self.message_digest
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum RootProtocolError {
    Empty,
    TooLong,
    InvalidJson,
    InvalidSchema,
    InvalidField(&'static str),
    BrokerRoleMismatch,
    ActorDenied,
    MessageDigestMismatch,
    PayloadDigestMismatch,
    InvalidVendorBundle,
}

/// A command whose exact bytes, payload digest, message-associated identity,
/// and method-level actor policy were verified by the central admission seam.
///
/// It is intentionally private to this crate, non-cloneable, and
/// non-serializable. Durable state-changing APIs consume this wrapper rather
/// than accepting an independently parsed command plus identity snapshot.
pub(crate) struct AuthorizedRootCommandV1 {
    actor: AuthenticatedActorSnapshotV1,
    command: RootCommandV1,
    vendor_offer_bundle: Option<OwnedVendorOfferBundleV1>,
}

impl AuthorizedRootCommandV1 {
    pub(crate) fn actor(&self) -> &AuthenticatedActorSnapshotV1 {
        &self.actor
    }

    pub(crate) fn command(&self) -> &RootCommandV1 {
        &self.command
    }

    pub(crate) fn into_vendor_offer_command(self) -> Option<AuthorizedVendorOfferCommandV1> {
        let bundle = self.vendor_offer_bundle?;
        Some(AuthorizedVendorOfferCommandV1 {
            actor: self.actor,
            operation_id: self.command.operation_id,
            subject_digest: self.command.subject_digest,
            expected_revision: self.command.expected_revision,
            payload_digest: self.command.payload_digest,
            bundle,
        })
    }
}

/// A live Updater identity and its exact owned release-offer command bytes.
///
/// This wrapper is intentionally non-cloneable and non-serializable. Crypto
/// verification consumes it without separating the bundle from its actor and
/// future store-CAS inputs.
pub(crate) struct AuthorizedVendorOfferCommandV1 {
    actor: AuthenticatedActorSnapshotV1,
    operation_id: String,
    subject_digest: String,
    expected_revision: u64,
    payload_digest: String,
    bundle: OwnedVendorOfferBundleV1,
}

impl AuthorizedVendorOfferCommandV1 {
    pub(crate) fn bundle_digest(&self) -> &[u8; 32] {
        self.bundle.digest()
    }

    pub(crate) fn verify(
        self,
        anchor: &PinnedVendorAnchorV1,
        current: VendorCurrentSnapshotV1,
        observed_wall: &str,
    ) -> Result<AuthorizedVerifiedVendorOfferV1, VendorReleaseError> {
        let verified = verify_vendor_offer(self.bundle, anchor, &current, observed_wall)?;
        Ok(AuthorizedVerifiedVendorOfferV1 {
            actor: self.actor,
            operation_id: self.operation_id,
            subject_digest: self.subject_digest,
            expected_revision: self.expected_revision,
            payload_digest: self.payload_digest,
            current,
            verified,
        })
    }
}

/// The only authority type a future vendor store stage transaction may accept.
pub(crate) struct AuthorizedVerifiedVendorOfferV1 {
    actor: AuthenticatedActorSnapshotV1,
    operation_id: String,
    subject_digest: String,
    expected_revision: u64,
    payload_digest: String,
    current: VendorCurrentSnapshotV1,
    verified: VerifiedVendorOfferV1,
}

impl AuthorizedVerifiedVendorOfferV1 {
    pub(crate) fn actor(&self) -> &AuthenticatedActorSnapshotV1 {
        &self.actor
    }

    pub(crate) fn operation_id(&self) -> &str {
        &self.operation_id
    }

    pub(crate) fn subject_digest(&self) -> &str {
        &self.subject_digest
    }

    pub(crate) fn expected_revision(&self) -> u64 {
        self.expected_revision
    }

    pub(crate) fn payload_digest(&self) -> &str {
        &self.payload_digest
    }

    pub(crate) fn verified(&self) -> &VerifiedVendorOfferV1 {
        &self.verified
    }

    pub(crate) fn current(&self) -> &VendorCurrentSnapshotV1 {
        &self.current
    }
}

pub(crate) fn revalidate_authorized_command(
    authorized: &AuthorizedRootCommandV1,
) -> Result<(), RootProtocolError> {
    authorize_actor(&authorized.actor, &authorized.command)
}

pub(crate) fn admit_root_command(
    actor: AuthenticatedActorSnapshotV1,
    exact_message_bytes: &[u8],
) -> Result<AuthorizedRootCommandV1, RootProtocolError> {
    if sha256_hex(exact_message_bytes) != actor.message_digest {
        return Err(RootProtocolError::MessageDigestMismatch);
    }
    let command = parse_root_command(exact_message_bytes)?;
    let vendor_offer_bundle = if command.method == RootMethodV1::ReleaseOfferVendorMetadata {
        let bundle = admit_vendor_offer_bundle(&command.payload)
            .map_err(|_| RootProtocolError::InvalidVendorBundle)?;
        if hex_digest(bundle.digest()) != command.payload_digest {
            return Err(RootProtocolError::PayloadDigestMismatch);
        }
        Some(bundle)
    } else {
        if sha256_hex(command.payload.as_bytes()) != command.payload_digest {
            return Err(RootProtocolError::PayloadDigestMismatch);
        }
        None
    };
    authorize_actor(&actor, &command)?;
    Ok(AuthorizedRootCommandV1 {
        actor,
        command,
        vendor_offer_bundle,
    })
}

fn parse_root_command(bytes: &[u8]) -> Result<RootCommandV1, RootProtocolError> {
    if bytes.is_empty() {
        return Err(RootProtocolError::Empty);
    }
    if bytes.len() > ROOT_COMMAND_MAX_BYTES {
        return Err(RootProtocolError::TooLong);
    }
    let command = serde_json::from_slice::<RootCommandV1>(bytes)
        .map_err(|_| RootProtocolError::InvalidJson)?;
    if command.schema != "rb.root-command.v1" {
        return Err(RootProtocolError::InvalidSchema);
    }
    validate_ascii_id("operationId", &command.operation_id)?;
    validate_ascii_id("clientNonce", &command.client_nonce)?;
    validate_digest("subjectDigest", &command.subject_digest)?;
    validate_digest("payloadDigest", &command.payload_digest)?;
    if command.payload.len() > ROOT_PAYLOAD_MAX_BYTES {
        return Err(RootProtocolError::InvalidField("payload"));
    }
    validate_method_shape(&command)?;
    Ok(command)
}

fn authorize_actor(
    actor: &AuthenticatedActorSnapshotV1,
    command: &RootCommandV1,
) -> Result<(), RootProtocolError> {
    let allowed = match actor.role {
        ActorRoleV1::Gateway => matches!(
            command.method,
            RootMethodV1::LaunchPrepare
                | RootMethodV1::LaunchStart
                | RootMethodV1::LaunchCancel
                | RootMethodV1::LaunchQuery
                | RootMethodV1::BrokerAuthorize
                | RootMethodV1::BrokerCancelBeforeClaim
                | RootMethodV1::BrokerQuery
        ),
        ActorRoleV1::ModelBroker => broker_method_allowed(command, BrokerRoleV1::Model),
        ActorRoleV1::NetworkBroker => broker_method_allowed(command, BrokerRoleV1::Network),
        ActorRoleV1::CurrentStateBroker => {
            broker_method_allowed(command, BrokerRoleV1::CurrentState)
        }
        ActorRoleV1::Updater => matches!(
            command.method,
            RootMethodV1::ReleaseOfferVendorMetadata | RootMethodV1::ReleaseQueryStatus
        ),
        ActorRoleV1::Main | ActorRoleV1::Renderer => {
            matches!(command.method, RootMethodV1::PublicStatus)
        }
        ActorRoleV1::Unknown => false,
    };
    if allowed {
        Ok(())
    } else {
        Err(RootProtocolError::ActorDenied)
    }
}

fn broker_method_allowed(command: &RootCommandV1, role: BrokerRoleV1) -> bool {
    command.broker_role == Some(role)
        && matches!(
            command.method,
            RootMethodV1::BrokerClaim
                | RootMethodV1::BrokerEffectStart
                | RootMethodV1::BrokerSettle
                | RootMethodV1::BrokerQuery
        )
}

fn validate_method_shape(command: &RootCommandV1) -> Result<(), RootProtocolError> {
    let requires_broker = matches!(
        command.method,
        RootMethodV1::BrokerAuthorize
            | RootMethodV1::BrokerCancelBeforeClaim
            | RootMethodV1::BrokerQuery
            | RootMethodV1::BrokerClaim
            | RootMethodV1::BrokerEffectStart
            | RootMethodV1::BrokerSettle
    );
    if requires_broker != command.broker_role.is_some() {
        return Err(RootProtocolError::BrokerRoleMismatch);
    }
    Ok(())
}

fn validate_ascii_id(field: &'static str, value: &str) -> Result<(), RootProtocolError> {
    if value.is_empty()
        || value.len() > ROOT_ID_MAX_BYTES
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._:-".contains(&byte))
    {
        return Err(RootProtocolError::InvalidField(field));
    }
    Ok(())
}

fn validate_digest(field: &'static str, value: &str) -> Result<(), RootProtocolError> {
    if value.len() != ROOT_DIGEST_BYTES
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(RootProtocolError::InvalidField(field));
    }
    Ok(())
}

fn sha256_hex(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn hex_digest(digest: &[u8; 32]) -> String {
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}
