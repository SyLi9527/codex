#![cfg_attr(
    feature = "rb-managed-sandbox-feasibility",
    doc = "```compile_fail\nuse codex_rb_launch_guard::VendorAuthorityRootStore;\nuse codex_rb_launch_guard::VerifiedVendorGenesisV1;\nfn forge(_: VerifiedVendorGenesisV1) -> VendorAuthorityRootStore { unimplemented!() }\n```\n\n```compile_fail\nuse codex_rb_launch_guard::VendorCurrentSnapshotV1;\nfn fabricate() -> VendorCurrentSnapshotV1 { unimplemented!() }\n```\n\n```compile_fail\nuse codex_rb_launch_guard::AuthorizedVerifiedVendorOfferV1;\nfn replay(value: &AuthorizedVerifiedVendorOfferV1) -> AuthorizedVerifiedVendorOfferV1 { value.clone() }\n```\n\n```compile_fail\nuse codex_rb_launch_guard::VendorCurrentSnapshotV1;\nfn duplicate(value: &VendorCurrentSnapshotV1) -> VendorCurrentSnapshotV1 { value.clone() }\n```\n\nThese compile_fail examples are tripwires rather than proofs: today they fail for the trivial reason that the involved types are not exported from the crate root. They pin exactly that fact, plus non-Cloneability once the types become nameable. The unforgeability guarantees themselves are private fields, no non-test constructor, the cfg(all(test, feature)) module gates below, and move-only consumption of authorized values."
)]

mod authority;
#[cfg(all(
    target_os = "macos",
    any(test, feature = "rb-managed-sandbox-feasibility")
))]
mod rendezvous;
#[cfg(all(test, feature = "rb-managed-sandbox-feasibility"))]
mod root_broker_store;
#[cfg(all(test, feature = "rb-managed-sandbox-feasibility"))]
mod root_protocol;
#[cfg(all(test, feature = "rb-managed-sandbox-feasibility"))]
mod root_service;
#[cfg(all(test, feature = "rb-managed-sandbox-feasibility"))]
mod root_sqlite;
#[cfg(all(test, feature = "rb-managed-sandbox-feasibility"))]
mod root_store;
#[cfg(all(test, feature = "rb-managed-sandbox-feasibility"))]
mod vendor_authority_store;
#[cfg(all(test, feature = "rb-managed-sandbox-feasibility"))]
mod vendor_codec;
#[cfg(all(test, feature = "rb-managed-sandbox-feasibility"))]
mod vendor_release;

#[cfg(all(
    target_os = "macos",
    any(test, feature = "rb-managed-sandbox-feasibility")
))]
mod launch;
#[cfg(all(
    target_os = "macos",
    any(test, feature = "rb-managed-sandbox-feasibility")
))]
mod live_identity;
#[cfg(all(
    target_os = "macos",
    any(test, feature = "rb-managed-sandbox-feasibility")
))]
mod process_events;
#[cfg(all(
    target_os = "macos",
    any(test, feature = "rb-managed-sandbox-feasibility")
))]
mod suspended_spawn;

#[cfg(all(
    target_os = "macos",
    any(test, feature = "rb-managed-sandbox-feasibility")
))]
pub use authority::GuardReservedLaunchAttempt;
pub use authority::LaunchGuardError;
pub use authority::LaunchPolicyCandidateV1;
pub use authority::ValidatedLaunchPolicy;
pub use authority::validate_launch_policy;
#[cfg(all(
    target_os = "macos",
    any(test, feature = "rb-managed-sandbox-feasibility")
))]
pub use launch::AuthenticatedInboundFrame;
#[cfg(all(
    target_os = "macos",
    any(test, feature = "rb-managed-sandbox-feasibility")
))]
pub use launch::AuthenticatedUnreachableTransport;
#[cfg(all(
    target_os = "macos",
    any(test, feature = "rb-managed-sandbox-feasibility")
))]
pub use launch::PreparedRendezvousLaunch;
#[cfg(all(
    target_os = "macos",
    any(test, feature = "rb-managed-sandbox-feasibility")
))]
pub use launch::RB_OMP_MAX_PHYSICAL_FRAME_BYTES;
#[cfg(all(
    target_os = "macos",
    any(test, feature = "rb-managed-sandbox-feasibility")
))]
pub use launch::SpawnedRendezvousLaunch;
#[cfg(all(
    target_os = "macos",
    any(test, feature = "rb-managed-sandbox-feasibility")
))]
pub use launch::prepare_rendezvous_launch;
#[cfg(all(
    target_os = "macos",
    any(test, feature = "rb-managed-sandbox-feasibility")
))]
pub use live_identity::MacLivePeerIdentity;
#[cfg(all(
    target_os = "macos",
    any(test, feature = "rb-managed-sandbox-feasibility")
))]
pub use live_identity::verify_macos_live_peer_identity;
#[cfg(all(
    target_os = "macos",
    any(test, feature = "rb-managed-sandbox-feasibility")
))]
pub use process_events::MacProcessEvent;
#[cfg(all(
    target_os = "macos",
    any(test, feature = "rb-managed-sandbox-feasibility")
))]
pub use process_events::MacProcessEventWatcher;

#[cfg(test)]
#[path = "tests.rs"]
mod tests;

/// Test-only cross-domain exclusion: serializes lock-lifecycle tests
/// (root store open/drop/reopen) against spawn-heavy tests. A fork or
/// posix_spawn window transiently duplicates every flocked descriptor into
/// the child until exec applies O_CLOEXEC, so a parallel drop-then-reopen
/// inside that window observes a spurious AlreadyOpen.
#[cfg(test)]
pub(crate) mod test_spawn_exclusion {
    pub(crate) fn acquire() -> std::sync::MutexGuard<'static, ()> {
        static EXCLUSION: std::sync::Mutex<()> = std::sync::Mutex::new(());
        EXCLUSION
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

#[cfg(all(test, feature = "rb-managed-sandbox-feasibility"))]
#[path = "root_protocol_tests.rs"]
mod root_protocol_tests;

#[cfg(all(test, feature = "rb-managed-sandbox-feasibility"))]
#[path = "root_store_tests.rs"]
mod root_store_tests;

#[cfg(all(test, feature = "rb-managed-sandbox-feasibility"))]
#[path = "root_broker_store_tests.rs"]
mod root_broker_store_tests;

#[cfg(all(test, feature = "rb-managed-sandbox-feasibility"))]
#[path = "root_service_tests.rs"]
mod root_service_tests;

#[cfg(all(test, feature = "rb-managed-sandbox-feasibility"))]
#[path = "vendor_release_tests.rs"]
mod vendor_release_tests;

#[cfg(all(test, feature = "rb-managed-sandbox-feasibility"))]
#[path = "vendor_authority_store_tests.rs"]
mod vendor_authority_store_tests;

#[cfg(all(
    target_os = "macos",
    any(test, feature = "rb-managed-sandbox-feasibility")
))]
use rendezvous::OneShotRendezvous;
#[cfg(all(
    target_os = "macos",
    any(test, feature = "rb-managed-sandbox-feasibility")
))]
use rendezvous::reject_buffered_pre_identity_bytes;
