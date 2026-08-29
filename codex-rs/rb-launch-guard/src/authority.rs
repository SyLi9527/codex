use codex_sandboxing::RB_OUTER_OMP_LG5_PROVENANCE_EVIDENCE_SHA256;
use codex_sandboxing::RB_OUTER_OMP_TEMPLATE_SHA256;
use serde::Deserialize;
use sha2::Digest;
use sha2::Sha256;
use std::fmt;
use std::fs::File;
use std::io::Read;
use std::path::Path;
use std::path::PathBuf;

const POLICY_SCHEMA: &str = "rb.launch-policy-candidate.v1";
const MAX_AUTHORITY_STRING_BYTES: usize = 4096;
const MAX_ARGV_ITEMS: usize = 64;
const MAX_ARG_BYTES: usize = 4096;
const MAX_ARGV_BYTES: usize = 65_536;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct LaunchPolicyCandidateV1 {
    pub schema: String,
    pub expected_macos_build: String,
    pub expected_arch: String,
    pub expected_profile_template_sha256: String,
    pub expected_lg5_provenance_evidence_sha256: String,
    pub executable: PathBuf,
    pub executable_sha256: String,
    pub argv: Vec<String>,
    pub signed_runtime_root: PathBuf,
    pub session_cwd: PathBuf,
    pub session_cwd_device: u64,
    pub session_cwd_inode: u64,
    pub launch_guard_root: PathBuf,
    pub launch_guard_root_device: u64,
    pub launch_guard_root_inode: u64,
    pub forbidden_roots: Vec<PathBuf>,
    pub designated_requirement: String,
}

/// Locally validated launch policy. This is not a launch ticket, grant, or
/// reservation and cannot be passed to the product-unreachable launch seam.
///
/// The default crate graph exposes no launch preparation API.
#[cfg_attr(
    not(feature = "rb-managed-sandbox-feasibility"),
    doc = "```compile_fail\nuse codex_rb_launch_guard::prepare_rendezvous_launch;\n```"
)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidatedLaunchPolicy {
    pub(crate) expected_macos_build: String,
    pub(crate) expected_arch: String,
    pub(crate) executable: PathBuf,
    pub(crate) executable_sha256: String,
    pub(crate) argv: Vec<String>,
    pub(crate) signed_runtime_root: PathBuf,
    pub(crate) session_cwd: PathBuf,
    pub(crate) session_cwd_device: u64,
    pub(crate) session_cwd_inode: u64,
    pub(crate) launch_guard_root: PathBuf,
    pub(crate) launch_guard_root_device: u64,
    pub(crate) launch_guard_root_inode: u64,
    pub(crate) forbidden_roots: Vec<PathBuf>,
    pub(crate) designated_requirement: String,
}

impl ValidatedLaunchPolicy {
    #[cfg(any(test, feature = "rb-managed-sandbox-feasibility"))]
    pub(crate) fn revalidate_for_exec(&self) -> Result<(), LaunchGuardError> {
        verify_session_identity(
            &self.session_cwd,
            self.session_cwd_device,
            self.session_cwd_inode,
        )?;
        verify_private_directory_identity(
            &self.launch_guard_root,
            self.launch_guard_root_device,
            self.launch_guard_root_inode,
            "launch guard root",
        )?;
        let executable = canonical_file(&self.executable, "executable")?;
        let actual = sha256_file(&executable)?;
        if actual != self.executable_sha256 {
            return Err(LaunchGuardError::DigestMismatch {
                field: "executable",
                expected: self.executable_sha256.clone(),
                actual,
            });
        }
        Ok(())
    }

    pub fn argv(&self) -> &[String] {
        &self.argv
    }

    pub fn executable(&self) -> &Path {
        &self.executable
    }

    pub fn session_cwd(&self) -> &Path {
        &self.session_cwd
    }
}

/// Opaque proof that the authoritative Guard store reserved a launch attempt.
///
/// This feasibility type deliberately has no public constructor, `Clone`,
/// `Default`, serde implementation, or conversion from [`ValidatedLaunchPolicy`].
/// A future production constructor must consume a successful durable Guard CAS;
/// this slice provides only a crate-private test constructor.
///
/// ```compile_fail
/// use codex_rb_launch_guard::GuardReservedLaunchAttempt;
/// let _ = GuardReservedLaunchAttempt {};
/// ```
///
/// ```compile_fail
/// use codex_rb_launch_guard::GuardReservedLaunchAttempt;
/// fn duplicate(value: GuardReservedLaunchAttempt) { let _ = value.clone(); }
/// ```
///
/// ```compile_fail
/// use codex_rb_launch_guard::GuardReservedLaunchAttempt;
/// let _ = GuardReservedLaunchAttempt::default();
/// ```
///
/// ```compile_fail
/// use codex_rb_launch_guard::GuardReservedLaunchAttempt;
/// fn encode(value: &GuardReservedLaunchAttempt) { let _ = serde_json::to_string(value); }
/// ```
///
/// ```compile_fail
/// use codex_rb_launch_guard::{GuardReservedLaunchAttempt, ValidatedLaunchPolicy};
/// fn policy() -> ValidatedLaunchPolicy { unimplemented!() }
/// let _: GuardReservedLaunchAttempt = policy().into();
/// ```
///
/// ```compile_fail
/// use codex_rb_launch_guard::{ValidatedLaunchPolicy, prepare_rendezvous_launch};
/// fn policy() -> ValidatedLaunchPolicy { unimplemented!() }
/// let _ = prepare_rendezvous_launch(policy());
/// ```
#[cfg(any(test, feature = "rb-managed-sandbox-feasibility"))]
pub struct GuardReservedLaunchAttempt {
    policy: ValidatedLaunchPolicy,
    epoch: u64,
    generation: u64,
    one_shot_ticket_digest: String,
}

#[cfg(any(test, feature = "rb-managed-sandbox-feasibility"))]
impl GuardReservedLaunchAttempt {
    #[cfg(test)]
    pub(crate) fn new_for_test(
        policy: ValidatedLaunchPolicy,
        epoch: u64,
        generation: u64,
        one_shot_ticket_digest: String,
    ) -> Self {
        Self {
            policy,
            epoch,
            generation,
            one_shot_ticket_digest,
        }
    }

    #[cfg(any(test, feature = "rb-managed-sandbox-feasibility"))]
    pub(crate) fn into_parts(self) -> (ValidatedLaunchPolicy, u64, u64, String) {
        (
            self.policy,
            self.epoch,
            self.generation,
            self.one_shot_ticket_digest,
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum LaunchGuardError {
    UnsupportedPlatform,
    InvalidAuthority(String),
    InvalidPath(String),
    IdentityDrift(String),
    DigestMismatch {
        field: &'static str,
        expected: String,
        actual: String,
    },
    Io(String),
    Sandbox(String),
    LiveIdentity(String),
    PeerPidMismatch {
        socket_pid: i32,
        token_pid: i32,
        spawned_pid: u32,
    },
    PeerTokenPidMismatch {
        socket_pid: i32,
        token_pid: i32,
    },
    InitialExecGenerationInvalid {
        baseline_pid_version: u32,
        peer_pid_version: u32,
        current_pid_version: u32,
    },
    AuthenticatedExecGenerationDrift {
        authenticated_pid_version: u32,
        peer_pid_version: u32,
        current_pid_version: u32,
    },
    SecCodeInvalid(String),
    TransportRevoked,
    TransportEof,
    PartialFrameAtEof,
    InvalidFrameUtf8,
    InvalidFrameJson,
    FrameMustBeObject,
    EmptyFrame,
    FrameTooLong {
        max_physical_bytes: usize,
    },
    FrameSequenceOverflow,
    ProcessExecObserved,
    ProcessExitObserved,
    ProcessExecAndExitObserved,
}

impl fmt::Display for LaunchGuardError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedPlatform => f.write_str("RB LaunchGuard requires macOS"),
            Self::InvalidAuthority(message) => write!(f, "invalid launch authority: {message}"),
            Self::InvalidPath(message) => write!(f, "invalid launch path: {message}"),
            Self::IdentityDrift(message) => write!(f, "launch identity drift: {message}"),
            Self::DigestMismatch {
                field,
                expected,
                actual,
            } => {
                write!(
                    f,
                    "{field} digest mismatch: expected {expected}, got {actual}"
                )
            }
            Self::Io(message) => write!(f, "launch I/O failed: {message}"),
            Self::Sandbox(message) => write!(f, "sandbox preparation failed: {message}"),
            Self::LiveIdentity(message) => write!(f, "live identity failed: {message}"),
            Self::PeerPidMismatch {
                socket_pid,
                token_pid,
                spawned_pid,
            } => write!(
                f,
                "peer pid mismatch: socket={socket_pid}, token={token_pid}, spawned={spawned_pid}"
            ),
            Self::PeerTokenPidMismatch {
                socket_pid,
                token_pid,
            } => write!(
                f,
                "peer token pid mismatch: socket={socket_pid}, token={token_pid}"
            ),
            Self::InitialExecGenerationInvalid {
                baseline_pid_version,
                peer_pid_version,
                current_pid_version,
            } => write!(
                f,
                "initial exec generation invalid: baseline={baseline_pid_version}, peer={peer_pid_version}, current={current_pid_version}"
            ),
            Self::AuthenticatedExecGenerationDrift {
                authenticated_pid_version,
                peer_pid_version,
                current_pid_version,
            } => write!(
                f,
                "authenticated exec generation drift: authenticated={authenticated_pid_version}, peer={peer_pid_version}, current={current_pid_version}"
            ),
            Self::SecCodeInvalid(message) => write!(f, "live SecCode invalid: {message}"),
            Self::TransportRevoked => f.write_str("authenticated transport is revoked"),
            Self::TransportEof => f.write_str("authenticated transport reached EOF"),
            Self::PartialFrameAtEof => f.write_str("authenticated transport ended mid-frame"),
            Self::InvalidFrameUtf8 => f.write_str("authenticated frame is not valid UTF-8"),
            Self::InvalidFrameJson => f.write_str("authenticated frame is not valid JSON"),
            Self::FrameMustBeObject => {
                f.write_str("authenticated frame must be a top-level JSON object")
            }
            Self::EmptyFrame => f.write_str("authenticated frame is empty"),
            Self::FrameTooLong { max_physical_bytes } => write!(
                f,
                "authenticated frame exceeds the {max_physical_bytes}-byte physical limit"
            ),
            Self::FrameSequenceOverflow => f.write_str("authenticated frame sequence overflowed"),
            Self::ProcessExecObserved => {
                f.write_str("authenticated transport observed process exec")
            }
            Self::ProcessExitObserved => {
                f.write_str("authenticated transport observed process exit")
            }
            Self::ProcessExecAndExitObserved => {
                f.write_str("authenticated transport observed process exec and exit")
            }
        }
    }
}

impl std::error::Error for LaunchGuardError {}

pub fn validate_launch_policy(
    authority: LaunchPolicyCandidateV1,
) -> Result<ValidatedLaunchPolicy, LaunchGuardError> {
    if !cfg!(target_os = "macos") {
        return Err(LaunchGuardError::UnsupportedPlatform);
    }
    if authority.schema != POLICY_SCHEMA {
        return Err(LaunchGuardError::InvalidAuthority(
            "unknown schema".to_string(),
        ));
    }
    validate_digest("executableSha256", &authority.executable_sha256)?;
    validate_argv(&authority.argv)?;
    if authority.expected_profile_template_sha256 != RB_OUTER_OMP_TEMPLATE_SHA256 {
        return Err(LaunchGuardError::DigestMismatch {
            field: "profileTemplate",
            expected: RB_OUTER_OMP_TEMPLATE_SHA256.to_string(),
            actual: authority.expected_profile_template_sha256,
        });
    }
    if authority.expected_lg5_provenance_evidence_sha256
        != RB_OUTER_OMP_LG5_PROVENANCE_EVIDENCE_SHA256
    {
        return Err(LaunchGuardError::DigestMismatch {
            field: "lg5ProvenanceEvidence",
            expected: RB_OUTER_OMP_LG5_PROVENANCE_EVIDENCE_SHA256.to_string(),
            actual: authority.expected_lg5_provenance_evidence_sha256,
        });
    }
    validate_bounded_ascii("expectedMacosBuild", &authority.expected_macos_build, 64)?;
    validate_bounded_ascii("expectedArch", &authority.expected_arch, 16)?;
    validate_bounded_ascii(
        "designatedRequirement",
        &authority.designated_requirement,
        MAX_AUTHORITY_STRING_BYTES,
    )?;
    if !authority.designated_requirement.contains("identifier ")
        || !authority
            .designated_requirement
            .contains("certificate leaf[subject.OU]")
        || !authority.designated_requirement.contains("cdhash H\"")
    {
        return Err(LaunchGuardError::InvalidAuthority(
            "production designated requirement must bind identifier, Team ID and cdhash"
                .to_string(),
        ));
    }
    validate_designated_requirement(&authority.designated_requirement)?;

    let runtime = canonical_dir(&authority.signed_runtime_root, "signed runtime root")?;
    let session = canonical_dir(&authority.session_cwd, "session cwd")?;
    let launch_guard_root = canonical_dir(&authority.launch_guard_root, "launch guard root")?;
    let executable = canonical_file(&authority.executable, "executable")?;
    verify_executable_permissions(&executable)?;
    if Path::new(&authority.argv[0]) != executable {
        return Err(LaunchGuardError::InvalidAuthority(
            "argv[0] does not equal the verified executable".to_string(),
        ));
    }
    if !executable.starts_with(&runtime) {
        return Err(LaunchGuardError::InvalidPath(
            "executable is outside signed runtime root".to_string(),
        ));
    }
    if overlaps(&runtime, &session) {
        return Err(LaunchGuardError::InvalidPath(
            "runtime and session roots overlap".to_string(),
        ));
    }
    if overlaps(&runtime, &launch_guard_root) || overlaps(&session, &launch_guard_root) {
        return Err(LaunchGuardError::InvalidPath(
            "launch guard root overlaps runtime or session roots".to_string(),
        ));
    }
    for forbidden in &authority.forbidden_roots {
        let forbidden = canonical_dir(forbidden, "forbidden root")?;
        if overlaps(&runtime, &forbidden)
            || overlaps(&session, &forbidden)
            || overlaps(&launch_guard_root, &forbidden)
        {
            return Err(LaunchGuardError::InvalidPath(
                "model-invisible roots overlap a forbidden root".to_string(),
            ));
        }
    }

    verify_session_identity(
        &session,
        authority.session_cwd_device,
        authority.session_cwd_inode,
    )?;
    verify_private_directory_identity(
        &launch_guard_root,
        authority.launch_guard_root_device,
        authority.launch_guard_root_inode,
        "launch guard root",
    )?;
    verify_runtime_permissions(&runtime)?;
    let actual_executable_sha256 = sha256_file(&executable)?;
    if actual_executable_sha256 != authority.executable_sha256 {
        return Err(LaunchGuardError::DigestMismatch {
            field: "executable",
            expected: authority.executable_sha256,
            actual: actual_executable_sha256,
        });
    }

    Ok(ValidatedLaunchPolicy {
        expected_macos_build: authority.expected_macos_build,
        expected_arch: authority.expected_arch,
        executable,
        executable_sha256: actual_executable_sha256,
        argv: authority.argv,
        signed_runtime_root: runtime,
        session_cwd: session,
        session_cwd_device: authority.session_cwd_device,
        session_cwd_inode: authority.session_cwd_inode,
        launch_guard_root,
        launch_guard_root_device: authority.launch_guard_root_device,
        launch_guard_root_inode: authority.launch_guard_root_inode,
        forbidden_roots: authority.forbidden_roots,
        designated_requirement: authority.designated_requirement,
    })
}

fn validate_argv(argv: &[String]) -> Result<(), LaunchGuardError> {
    if argv.is_empty() || argv.len() > MAX_ARGV_ITEMS {
        return Err(LaunchGuardError::InvalidAuthority(
            "argv is empty or exceeds 64 items".to_string(),
        ));
    }
    let mut total = 0_usize;
    for argument in argv {
        if argument.is_empty() || argument.as_bytes().contains(&0) || argument.len() > MAX_ARG_BYTES
        {
            return Err(LaunchGuardError::InvalidAuthority(
                "argv contains an empty, NUL, or oversized item".to_string(),
            ));
        }
        total = total.checked_add(argument.len()).ok_or_else(|| {
            LaunchGuardError::InvalidAuthority("argv byte count overflow".to_string())
        })?;
    }
    if total > MAX_ARGV_BYTES {
        return Err(LaunchGuardError::InvalidAuthority(
            "argv exceeds 65536 bytes".to_string(),
        ));
    }
    Ok(())
}

fn validate_digest(field: &'static str, value: &str) -> Result<(), LaunchGuardError> {
    if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(LaunchGuardError::InvalidAuthority(format!(
            "{field} is not a SHA-256 digest"
        )));
    }
    Ok(())
}

fn validate_bounded_ascii(field: &str, value: &str, max: usize) -> Result<(), LaunchGuardError> {
    if value.is_empty() || value.len() > max || !value.is_ascii() {
        return Err(LaunchGuardError::InvalidAuthority(format!(
            "{field} is empty, oversized, or non-ASCII"
        )));
    }
    Ok(())
}

fn canonical_dir(path: &Path, label: &str) -> Result<PathBuf, LaunchGuardError> {
    reject_symlink(path, label)?;
    let canonical = path
        .canonicalize()
        .map_err(|error| LaunchGuardError::InvalidPath(format!("{label}: {error}")))?;
    if canonical != path || !canonical.is_dir() {
        return Err(LaunchGuardError::InvalidPath(format!(
            "{label} is not an exact canonical directory"
        )));
    }
    path.to_str()
        .ok_or_else(|| LaunchGuardError::InvalidPath(format!("{label} is not UTF-8")))?;
    Ok(canonical)
}

fn canonical_file(path: &Path, label: &str) -> Result<PathBuf, LaunchGuardError> {
    reject_symlink(path, label)?;
    let canonical = path
        .canonicalize()
        .map_err(|error| LaunchGuardError::InvalidPath(format!("{label}: {error}")))?;
    if canonical != path || !canonical.is_file() {
        return Err(LaunchGuardError::InvalidPath(format!(
            "{label} is not an exact canonical regular file"
        )));
    }
    path.to_str()
        .ok_or_else(|| LaunchGuardError::InvalidPath(format!("{label} is not UTF-8")))?;
    Ok(canonical)
}

fn reject_symlink(path: &Path, label: &str) -> Result<(), LaunchGuardError> {
    let metadata = path
        .symlink_metadata()
        .map_err(|error| LaunchGuardError::InvalidPath(format!("{label}: {error}")))?;
    if metadata.file_type().is_symlink() {
        return Err(LaunchGuardError::InvalidPath(format!(
            "{label} must not be a symlink"
        )));
    }
    Ok(())
}

#[cfg(unix)]
fn verify_session_identity(path: &Path, device: u64, inode: u64) -> Result<(), LaunchGuardError> {
    verify_private_directory_identity(path, device, inode, "session cwd")
}

#[cfg(unix)]
fn verify_private_directory_identity(
    path: &Path,
    device: u64,
    inode: u64,
    label: &str,
) -> Result<(), LaunchGuardError> {
    use std::os::unix::fs::MetadataExt;
    use std::os::unix::fs::PermissionsExt;

    let metadata = path
        .metadata()
        .map_err(|error| LaunchGuardError::Io(error.to_string()))?;
    if !metadata.is_dir() || metadata.dev() != device || metadata.ino() != inode {
        return Err(LaunchGuardError::IdentityDrift(format!(
            "{label} type/dev/ino mismatch"
        )));
    }
    if metadata.uid() != unsafe { libc::geteuid() }
        || metadata.permissions().mode() & 0o777 != 0o700
    {
        return Err(LaunchGuardError::InvalidPath(format!(
            "{label} must be owned by LaunchGuard euid with mode 0700"
        )));
    }
    Ok(())
}

#[cfg(not(unix))]
fn verify_session_identity(_: &Path, _: u64, _: u64) -> Result<(), LaunchGuardError> {
    Err(LaunchGuardError::UnsupportedPlatform)
}

#[cfg(not(unix))]
fn verify_private_directory_identity(
    _: &Path,
    _: u64,
    _: u64,
    _: &str,
) -> Result<(), LaunchGuardError> {
    Err(LaunchGuardError::UnsupportedPlatform)
}

#[cfg(unix)]
fn verify_runtime_permissions(path: &Path) -> Result<(), LaunchGuardError> {
    use std::os::unix::fs::PermissionsExt;

    let mode = path
        .metadata()
        .map_err(|error| LaunchGuardError::Io(error.to_string()))?
        .permissions()
        .mode();
    if mode & 0o022 != 0 {
        return Err(LaunchGuardError::InvalidPath(
            "signed runtime root is group- or other-writable".to_string(),
        ));
    }
    Ok(())
}

#[cfg(unix)]
fn verify_executable_permissions(path: &Path) -> Result<(), LaunchGuardError> {
    use std::os::unix::fs::PermissionsExt;

    let mode = path
        .metadata()
        .map_err(|error| LaunchGuardError::Io(error.to_string()))?
        .permissions()
        .mode();
    if mode & 0o111 == 0 || mode & 0o022 != 0 {
        return Err(LaunchGuardError::InvalidPath(
            "executable must be executable and not group- or other-writable".to_string(),
        ));
    }
    Ok(())
}

#[cfg(not(unix))]
fn verify_executable_permissions(_: &Path) -> Result<(), LaunchGuardError> {
    Err(LaunchGuardError::UnsupportedPlatform)
}

#[cfg(target_os = "macos")]
fn validate_designated_requirement(requirement: &str) -> Result<(), LaunchGuardError> {
    requirement
        .parse::<security_framework::os::macos::code_signing::SecRequirement>()
        .map(|_| ())
        .map_err(|error| LaunchGuardError::InvalidAuthority(error.to_string()))
}

#[cfg(not(target_os = "macos"))]
fn validate_designated_requirement(_: &str) -> Result<(), LaunchGuardError> {
    Err(LaunchGuardError::UnsupportedPlatform)
}

#[cfg(not(unix))]
fn verify_runtime_permissions(_: &Path) -> Result<(), LaunchGuardError> {
    Err(LaunchGuardError::UnsupportedPlatform)
}

fn overlaps(left: &Path, right: &Path) -> bool {
    left.starts_with(right) || right.starts_with(left)
}

fn sha256_file(path: &Path) -> Result<String, LaunchGuardError> {
    let mut file = File::open(path).map_err(|error| LaunchGuardError::Io(error.to_string()))?;
    let mut digest = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = file
            .read(&mut buffer)
            .map_err(|error| LaunchGuardError::Io(error.to_string()))?;
        if read == 0 {
            break;
        }
        digest.update(&buffer[..read]);
    }
    Ok(format!("{:x}", digest.finalize()))
}
