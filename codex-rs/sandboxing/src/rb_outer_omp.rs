use crate::SandboxablePreference;
use codex_utils_absolute_path::AbsolutePathBuf;
use sha2::Digest;
use sha2::Sha256;
use std::collections::BTreeSet;
use std::ffi::CStr;
use std::fmt;
use std::path::Path;
use std::path::PathBuf;

const RB_OUTER_OMP_POLICY: &str = include_str!("rb_outer_omp.sbpl");
pub const RB_OUTER_OMP_LG5_PROVENANCE_EVIDENCE_SHA256: &str =
    "97e765e0a1782ddea0f70d5e9e8c46ea4980c3286b72e6747d2b5c95cce11c5d";
pub const RB_OUTER_OMP_TEMPLATE_SHA256: &str =
    "5f38d368ad88cbab3fce33d5a3754602569cfa49b04cf365f8b443d2b94df22a";
pub const RB_OUTER_OMP_SUPPORTED_MACOS_BUILD: &str = "25F80";
pub const RB_OUTER_OMP_SUPPORTED_ARCH: &str = "arm64";
const MAX_ROOTS_PER_ACCESS_CLASS: usize = 32;
const MAX_INHERITED_FDS: usize = 16;
const BROAD_ROOTS: &[&str] = &[
    "/",
    "/Users",
    "/private",
    "/private/tmp",
    "/tmp",
    "/var",
    "/var/tmp",
    "/private/var",
    "/private/var/tmp",
];

/// Host-owned inputs for compiling ResearchBuddy's outer OMP Seatbelt profile.
///
/// Every path must already be canonical and must exist. `forbidden_roots`
/// carries the current workspace, home, protected credential roots, and other
/// session roots so a signed-runtime or session grant cannot overlap them.
pub struct RbOuterOmpSeatbeltRequest<'a> {
    pub command: &'a [String],
    pub verified_executable: &'a AbsolutePathBuf,
    pub signed_runtime_read_roots: &'a [AbsolutePathBuf],
    pub session_read_write_roots: &'a [AbsolutePathBuf],
    pub forbidden_roots: &'a [AbsolutePathBuf],
    pub inherited_fds: &'a [i32],
    pub rendezvous: RbOuterOmpRendezvous<'a>,
    pub expected_macos_build: &'a str,
    pub expected_arch: &'a str,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RbOuterOmpRendezvous<'a> {
    DenyAll,
    ConnectExact(&'a AbsolutePathBuf),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RbOuterOmpProfileSeal {
    pub macos_build: String,
    pub arch: String,
    pub template_sha256: String,
    pub lg5_provenance_evidence_sha256: String,
    pub concrete_policy_sha256: String,
    pub compiled_launch_sha256: String,
}

/// A fail-closed, direct-spawn command for ResearchBuddy's outer OMP process.
#[derive(Debug, Eq, PartialEq)]
pub struct RbOuterOmpSeatbeltCommand {
    pub program: PathBuf,
    pub args: Vec<String>,
    pub sandbox_preference: SandboxablePreference,
    pub inherited_fds: Vec<i32>,
    pub profile_seal: RbOuterOmpProfileSeal,
}

#[derive(Debug, Eq, PartialEq)]
pub enum RbOuterOmpPreparationError {
    UnsupportedPlatform,
    UnsupportedArchitecture,
    ArchitectureMismatch { expected: String, actual: String },
    ProfileSealMismatch { expected: String, actual: String },
    SandboxExecutableUnavailable(String),
    MacosBuildUnavailable(String),
    MacosBuildMismatch { expected: String, actual: String },
    MissingCommand,
    ExecutableMismatch,
    InvalidExecutable(String),
    InvalidRoot(String),
    BroadRoot(String),
    OverlappingRoots { left: String, right: String },
    TooManyRoots { access_class: &'static str },
    InvalidInheritedFd(i32),
    TooManyInheritedFds,
}

impl fmt::Display for RbOuterOmpPreparationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedPlatform => f.write_str("RB outer OMP Seatbelt requires macOS"),
            Self::UnsupportedArchitecture => {
                f.write_str("RB outer OMP Seatbelt supports only arm64 and x86_64")
            }
            Self::ArchitectureMismatch { expected, actual } => {
                write!(
                    f,
                    "architecture mismatch: expected {expected}, got {actual}"
                )
            }
            Self::ProfileSealMismatch { expected, actual } => {
                write!(
                    f,
                    "RB outer OMP profile seal mismatch: expected {expected}, got {actual}"
                )
            }
            Self::SandboxExecutableUnavailable(message) => {
                write!(f, "/usr/bin/sandbox-exec is unavailable: {message}")
            }
            Self::MacosBuildUnavailable(message) => {
                write!(f, "cannot determine the macOS build: {message}")
            }
            Self::MacosBuildMismatch { expected, actual } => {
                write!(f, "macOS build mismatch: expected {expected}, got {actual}")
            }
            Self::MissingCommand => f.write_str("RB outer OMP command is empty"),
            Self::ExecutableMismatch => {
                f.write_str("RB outer OMP argv[0] does not match the verified executable")
            }
            Self::InvalidExecutable(message) => write!(f, "invalid executable: {message}"),
            Self::InvalidRoot(message) => write!(f, "invalid RB outer OMP root: {message}"),
            Self::BroadRoot(path) => write!(f, "RB outer OMP root is too broad: {path}"),
            Self::OverlappingRoots { left, right } => {
                write!(f, "RB outer OMP roots overlap: {left} and {right}")
            }
            Self::TooManyRoots { access_class } => {
                write!(f, "too many RB outer OMP {access_class} roots")
            }
            Self::InvalidInheritedFd(fd) => write!(f, "invalid inherited descriptor: {fd}"),
            Self::TooManyInheritedFds => f.write_str("too many inherited descriptors"),
        }
    }
}

impl std::error::Error for RbOuterOmpPreparationError {}

/// Compiles the dedicated deny-default outer OMP profile.
///
/// This deliberately does not route through Codex's stock process or minimal
/// profile. The returned preference is always `Require`; callers must never
/// retry the command without the wrapper.
pub fn create_rb_outer_omp_seatbelt_command(
    request: RbOuterOmpSeatbeltRequest<'_>,
) -> Result<RbOuterOmpSeatbeltCommand, RbOuterOmpPreparationError> {
    if !cfg!(target_os = "macos") {
        return Err(RbOuterOmpPreparationError::UnsupportedPlatform);
    }
    if !cfg!(any(target_arch = "aarch64", target_arch = "x86_64")) {
        return Err(RbOuterOmpPreparationError::UnsupportedArchitecture);
    }

    validate_sandbox_executable()?;
    let macos_build = validate_macos_build(request.expected_macos_build)?;
    let arch = validate_arch(request.expected_arch)?;
    let template_sha256 = validate_profile_seal()?;

    let Some(command_executable) = request.command.first() else {
        return Err(RbOuterOmpPreparationError::MissingCommand);
    };
    let executable = canonical_file(request.verified_executable.as_path())
        .map_err(RbOuterOmpPreparationError::InvalidExecutable)?;
    if Path::new(command_executable) != executable.as_path() {
        return Err(RbOuterOmpPreparationError::ExecutableMismatch);
    }

    let runtime_roots = validate_roots(
        "signed-runtime read",
        request.signed_runtime_read_roots,
        true,
    )?;
    let session_roots =
        validate_roots("session read-write", request.session_read_write_roots, true)?;
    let forbidden_roots = validate_roots("forbidden", request.forbidden_roots, false)?;
    if !runtime_roots
        .iter()
        .any(|root| executable.as_path().starts_with(root.as_path()))
    {
        return Err(RbOuterOmpPreparationError::InvalidExecutable(
            "executable is outside every signed runtime root".to_string(),
        ));
    }
    validate_disjoint(&runtime_roots, &session_roots)?;
    validate_disjoint(&runtime_roots, &forbidden_roots)?;
    validate_disjoint(&session_roots, &forbidden_roots)?;

    let inherited_fds = validate_inherited_fds(request.inherited_fds)?;
    let mut policy = RB_OUTER_OMP_POLICY.to_string();
    let executable_definition = executable
        .as_path()
        .to_str()
        .ok_or_else(|| {
            RbOuterOmpPreparationError::InvalidExecutable("path is not valid UTF-8".to_string())
        })?
        .to_string();
    let mut definitions = vec![("RB_EXECUTABLE".to_string(), executable_definition)];
    append_root_policy(
        &mut policy,
        &mut definitions,
        "RB_RUNTIME_READ_ROOT",
        &runtime_roots,
        "file-read* file-test-existence",
    )?;
    if let RbOuterOmpRendezvous::ConnectExact(socket_path) = request.rendezvous {
        let socket_path = validate_rendezvous_socket(socket_path)?;
        policy.push_str(
            "\n(allow system-socket (socket-domain AF_UNIX))\n\
             (allow network-outbound (remote unix-socket (literal (param \"RB_RENDEZVOUS_SOCKET\"))))\n",
        );
        definitions.push(("RB_RENDEZVOUS_SOCKET".to_string(), socket_path));
    }
    append_root_policy(
        &mut policy,
        &mut definitions,
        "RB_SESSION_RW_ROOT",
        &session_roots,
        "file-read* file-test-existence file-write*",
    )?;

    let concrete_policy_sha256 = digest_parts(
        [
            b"rb.outer-omp.concrete-policy.v1".as_slice(),
            macos_build.as_bytes(),
            arch.as_bytes(),
            policy.as_bytes(),
        ]
        .into_iter()
        .chain(
            definitions
                .iter()
                .flat_map(|(key, value)| [key.as_bytes(), value.as_bytes()]),
        ),
    );
    let mut args = vec!["-p".to_string(), policy];
    args.extend(
        definitions
            .into_iter()
            .map(|(key, value)| format!("-D{key}={value}")),
    );
    args.push("--".to_string());
    args.extend(request.command.iter().cloned());
    let program = PathBuf::from(crate::seatbelt::MACOS_PATH_TO_SEATBELT_EXECUTABLE);
    let compiled_launch_sha256 = digest_parts(
        std::iter::once(b"rb.outer-omp.compiled-launch.v1".as_slice())
            .chain(std::iter::once(
                program
                    .to_str()
                    .ok_or_else(|| {
                        RbOuterOmpPreparationError::SandboxExecutableUnavailable(
                            "path is not valid UTF-8".to_string(),
                        )
                    })?
                    .as_bytes(),
            ))
            .chain(args.iter().map(String::as_bytes)),
    );

    Ok(RbOuterOmpSeatbeltCommand {
        program,
        args,
        sandbox_preference: SandboxablePreference::Require,
        inherited_fds,
        profile_seal: RbOuterOmpProfileSeal {
            macos_build,
            arch,
            template_sha256,
            lg5_provenance_evidence_sha256: RB_OUTER_OMP_LG5_PROVENANCE_EVIDENCE_SHA256.to_string(),
            concrete_policy_sha256,
            compiled_launch_sha256,
        },
    })
}

#[cfg(unix)]
fn validate_rendezvous_socket(
    path: &AbsolutePathBuf,
) -> Result<String, RbOuterOmpPreparationError> {
    use std::os::unix::fs::FileTypeExt;

    let path = path.as_path();
    let parent = path.parent().ok_or_else(|| {
        RbOuterOmpPreparationError::InvalidRoot(
            "rendezvous socket has no parent directory".to_string(),
        )
    })?;
    let canonical_parent = parent.canonicalize().map_err(|error| {
        RbOuterOmpPreparationError::InvalidRoot(format!(
            "cannot canonicalize rendezvous parent: {error}"
        ))
    })?;
    if canonical_parent != parent {
        return Err(RbOuterOmpPreparationError::InvalidRoot(
            "rendezvous parent is not canonical".to_string(),
        ));
    }
    let metadata = path.symlink_metadata().map_err(|error| {
        RbOuterOmpPreparationError::InvalidRoot(format!(
            "cannot inspect rendezvous socket: {error}"
        ))
    })?;
    if metadata.file_type().is_symlink() || !metadata.file_type().is_socket() {
        return Err(RbOuterOmpPreparationError::InvalidRoot(
            "rendezvous path is not a non-symlink Unix socket".to_string(),
        ));
    }
    path.to_str().map(str::to_string).ok_or_else(|| {
        RbOuterOmpPreparationError::InvalidRoot("rendezvous path is not UTF-8".to_string())
    })
}

#[cfg(not(unix))]
fn validate_rendezvous_socket(_: &AbsolutePathBuf) -> Result<String, RbOuterOmpPreparationError> {
    Err(RbOuterOmpPreparationError::UnsupportedPlatform)
}

fn digest_parts<'a>(parts: impl Iterator<Item = &'a [u8]>) -> String {
    let mut digest = Sha256::new();
    for part in parts {
        digest.update((part.len() as u64).to_be_bytes());
        digest.update(part);
    }
    format!("{:x}", digest.finalize())
}

fn validate_profile_seal() -> Result<String, RbOuterOmpPreparationError> {
    let actual = format!("{:x}", Sha256::digest(RB_OUTER_OMP_POLICY.as_bytes()));
    if actual != RB_OUTER_OMP_TEMPLATE_SHA256 {
        return Err(RbOuterOmpPreparationError::ProfileSealMismatch {
            expected: RB_OUTER_OMP_TEMPLATE_SHA256.to_string(),
            actual,
        });
    }
    Ok(actual)
}

fn validate_arch(expected: &str) -> Result<String, RbOuterOmpPreparationError> {
    let actual = rb_outer_omp_current_arch()?.to_string();
    if expected != RB_OUTER_OMP_SUPPORTED_ARCH || actual != RB_OUTER_OMP_SUPPORTED_ARCH {
        return Err(RbOuterOmpPreparationError::ArchitectureMismatch {
            expected: expected.to_string(),
            actual,
        });
    }
    Ok(actual)
}

fn append_root_policy(
    policy: &mut String,
    definitions: &mut Vec<(String, String)>,
    key_prefix: &str,
    roots: &[AbsolutePathBuf],
    operations: &str,
) -> Result<(), RbOuterOmpPreparationError> {
    for (index, root) in roots.iter().enumerate() {
        let key = format!("{key_prefix}_{index}");
        policy.push_str(&format!(
            "\n(allow {operations} (subpath (param \"{key}\")))"
        ));
        let root = root.as_path().to_str().ok_or_else(|| {
            RbOuterOmpPreparationError::InvalidRoot("path is not valid UTF-8".to_string())
        })?;
        definitions.push((key, root.to_string()));
    }
    Ok(())
}

fn validate_sandbox_executable() -> Result<(), RbOuterOmpPreparationError> {
    #[cfg(target_os = "macos")]
    {
        use std::os::unix::fs::PermissionsExt;

        let path = Path::new(crate::seatbelt::MACOS_PATH_TO_SEATBELT_EXECUTABLE);
        let canonical = path.canonicalize().map_err(|err| {
            RbOuterOmpPreparationError::SandboxExecutableUnavailable(err.to_string())
        })?;
        if canonical != path {
            return Err(RbOuterOmpPreparationError::SandboxExecutableUnavailable(
                "path is not canonical".to_string(),
            ));
        }
        let metadata = path.metadata().map_err(|err| {
            RbOuterOmpPreparationError::SandboxExecutableUnavailable(err.to_string())
        })?;
        if !metadata.is_file() || metadata.permissions().mode() & 0o111 == 0 {
            return Err(RbOuterOmpPreparationError::SandboxExecutableUnavailable(
                "path is not an executable regular file".to_string(),
            ));
        }
    }
    Ok(())
}

fn validate_macos_build(expected: &str) -> Result<String, RbOuterOmpPreparationError> {
    if expected.is_empty() || expected.len() > 64 || !expected.is_ascii() {
        return Err(RbOuterOmpPreparationError::MacosBuildMismatch {
            expected: expected.to_string(),
            actual: "invalid expected build".to_string(),
        });
    }
    let actual = rb_outer_omp_current_macos_build()?;
    if expected != RB_OUTER_OMP_SUPPORTED_MACOS_BUILD
        || actual != RB_OUTER_OMP_SUPPORTED_MACOS_BUILD
    {
        return Err(RbOuterOmpPreparationError::MacosBuildMismatch {
            expected: expected.to_string(),
            actual,
        });
    }
    Ok(actual)
}

/// Returns the architecture spelling used in an RB outer OMP profile seal.
pub fn rb_outer_omp_current_arch() -> Result<&'static str, RbOuterOmpPreparationError> {
    #[cfg(target_arch = "aarch64")]
    {
        Ok("arm64")
    }
    #[cfg(target_arch = "x86_64")]
    {
        Ok("x86_64")
    }
    #[cfg(not(any(target_arch = "aarch64", target_arch = "x86_64")))]
    {
        Err(RbOuterOmpPreparationError::UnsupportedArchitecture)
    }
}

#[cfg(target_os = "macos")]
/// Returns the current macOS build identifier used by the signed bundle seal.
pub fn rb_outer_omp_current_macos_build() -> Result<String, RbOuterOmpPreparationError> {
    let name = c"kern.osversion";
    let mut length = 0usize;
    // SAFETY: the first call only asks the kernel for the output length.
    if unsafe {
        libc::sysctlbyname(
            name.as_ptr(),
            std::ptr::null_mut(),
            &raw mut length,
            std::ptr::null_mut(),
            0,
        )
    } != 0
    {
        return Err(RbOuterOmpPreparationError::MacosBuildUnavailable(
            std::io::Error::last_os_error().to_string(),
        ));
    }
    if length == 0 || length > 256 {
        return Err(RbOuterOmpPreparationError::MacosBuildUnavailable(
            "unexpected sysctl output length".to_string(),
        ));
    }
    let mut bytes = vec![0u8; length];
    // SAFETY: `bytes` owns `length` writable bytes and the kernel updates the
    // length with the number of bytes written.
    if unsafe {
        libc::sysctlbyname(
            name.as_ptr(),
            bytes.as_mut_ptr().cast(),
            &raw mut length,
            std::ptr::null_mut(),
            0,
        )
    } != 0
    {
        return Err(RbOuterOmpPreparationError::MacosBuildUnavailable(
            std::io::Error::last_os_error().to_string(),
        ));
    }
    let value = CStr::from_bytes_until_nul(&bytes)
        .map_err(|err| RbOuterOmpPreparationError::MacosBuildUnavailable(err.to_string()))?;
    value
        .to_str()
        .map(str::to_owned)
        .map_err(|err| RbOuterOmpPreparationError::MacosBuildUnavailable(err.to_string()))
}

#[cfg(not(target_os = "macos"))]
/// Fails closed because the outer OMP Seatbelt profile is macOS-only.
pub fn rb_outer_omp_current_macos_build() -> Result<String, RbOuterOmpPreparationError> {
    Err(RbOuterOmpPreparationError::UnsupportedPlatform)
}

fn canonical_file(path: &Path) -> Result<AbsolutePathBuf, String> {
    let path_utf8 = path
        .to_str()
        .ok_or_else(|| "path is not valid UTF-8".to_string())?;
    let canonical = path.canonicalize().map_err(|err| err.to_string())?;
    if canonical != path {
        return Err(format!("{path_utf8} is not canonical"));
    }
    canonical
        .to_str()
        .ok_or_else(|| "canonical path is not valid UTF-8".to_string())?;
    let metadata = canonical.metadata().map_err(|err| err.to_string())?;
    if !metadata.is_file() {
        return Err(format!("{path_utf8} is not a regular file"));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        if metadata.permissions().mode() & 0o111 == 0 {
            return Err(format!("{path_utf8} is not executable"));
        }
    }
    AbsolutePathBuf::from_absolute_path(canonical).map_err(|err| err.to_string())
}

fn validate_roots(
    access_class: &'static str,
    roots: &[AbsolutePathBuf],
    reject_broad_roots: bool,
) -> Result<Vec<AbsolutePathBuf>, RbOuterOmpPreparationError> {
    if roots.len() > MAX_ROOTS_PER_ACCESS_CLASS {
        return Err(RbOuterOmpPreparationError::TooManyRoots { access_class });
    }
    let mut validated = Vec::with_capacity(roots.len());
    let mut seen = BTreeSet::new();
    for root in roots {
        let path = root.as_path();
        let path_utf8 = path.to_str().ok_or_else(|| {
            RbOuterOmpPreparationError::InvalidRoot("path is not valid UTF-8".to_string())
        })?;
        let canonical = path.canonicalize().map_err(|err| {
            RbOuterOmpPreparationError::InvalidRoot(format!("{path_utf8}: {err}"))
        })?;
        if canonical != path {
            return Err(RbOuterOmpPreparationError::InvalidRoot(format!(
                "{path_utf8} is not canonical"
            )));
        }
        let canonical_utf8 = canonical.to_str().ok_or_else(|| {
            RbOuterOmpPreparationError::InvalidRoot("canonical path is not valid UTF-8".to_string())
        })?;
        if !canonical
            .metadata()
            .map_err(|err| RbOuterOmpPreparationError::InvalidRoot(err.to_string()))?
            .is_dir()
        {
            return Err(RbOuterOmpPreparationError::InvalidRoot(format!(
                "{path_utf8} is not a directory"
            )));
        }
        if reject_broad_roots
            && BROAD_ROOTS
                .iter()
                .any(|broad| canonical == Path::new(broad))
        {
            return Err(RbOuterOmpPreparationError::BroadRoot(
                canonical_utf8.to_string(),
            ));
        }
        let canonical = AbsolutePathBuf::from_absolute_path(canonical)
            .map_err(|err| RbOuterOmpPreparationError::InvalidRoot(err.to_string()))?;
        if seen.insert(canonical.clone()) {
            validated.push(canonical);
        }
    }
    validate_disjoint(&validated, &validated)?;
    Ok(validated)
}

fn validate_disjoint(
    left: &[AbsolutePathBuf],
    right: &[AbsolutePathBuf],
) -> Result<(), RbOuterOmpPreparationError> {
    for (left_index, left_root) in left.iter().enumerate() {
        for (right_index, right_root) in right.iter().enumerate() {
            if std::ptr::eq(left, right) && left_index == right_index {
                continue;
            }
            if roots_overlap(left_root.as_path(), right_root.as_path())? {
                let left = left_root.as_path().to_str().ok_or_else(|| {
                    RbOuterOmpPreparationError::InvalidRoot("path is not valid UTF-8".to_string())
                })?;
                let right = right_root.as_path().to_str().ok_or_else(|| {
                    RbOuterOmpPreparationError::InvalidRoot("path is not valid UTF-8".to_string())
                })?;
                return Err(RbOuterOmpPreparationError::OverlappingRoots {
                    left: left.to_string(),
                    right: right.to_string(),
                });
            }
        }
    }
    Ok(())
}

fn roots_overlap(left: &Path, right: &Path) -> Result<bool, RbOuterOmpPreparationError> {
    if left.starts_with(right) || right.starts_with(left) {
        return Ok(true);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;

        let left_metadata = left
            .metadata()
            .map_err(|err| RbOuterOmpPreparationError::InvalidRoot(err.to_string()))?;
        let right_metadata = right
            .metadata()
            .map_err(|err| RbOuterOmpPreparationError::InvalidRoot(err.to_string()))?;
        Ok(left_metadata.dev() == right_metadata.dev()
            && left_metadata.ino() == right_metadata.ino())
    }
    #[cfg(not(unix))]
    Ok(false)
}

fn validate_inherited_fds(inherited_fds: &[i32]) -> Result<Vec<i32>, RbOuterOmpPreparationError> {
    if inherited_fds.len() > MAX_INHERITED_FDS {
        return Err(RbOuterOmpPreparationError::TooManyInheritedFds);
    }
    let mut seen = BTreeSet::new();
    for &fd in inherited_fds {
        if fd <= libc::STDERR_FILENO || !seen.insert(fd) {
            return Err(RbOuterOmpPreparationError::InvalidInheritedFd(fd));
        }
        #[cfg(unix)]
        if unsafe { libc::fcntl(fd, libc::F_GETFD) } < 0 {
            return Err(RbOuterOmpPreparationError::InvalidInheritedFd(fd));
        }
    }
    Ok(seen.into_iter().collect())
}

#[cfg(test)]
#[path = "rb_outer_omp_tests.rs"]
mod tests;
