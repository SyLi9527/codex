use super::*;
use pretty_assertions::assert_eq;
use std::fs;
use tempfile::TempDir;

fn absolute(path: impl AsRef<Path>) -> AbsolutePathBuf {
    let path = path
        .as_ref()
        .canonicalize()
        .expect("canonical fixture path");
    AbsolutePathBuf::from_absolute_path(path).expect("absolute fixture path")
}

fn absolute_without_canonicalizing(path: impl AsRef<Path>) -> AbsolutePathBuf {
    AbsolutePathBuf::from_absolute_path(path).expect("absolute fixture path")
}

fn current_build() -> String {
    rb_outer_omp_current_macos_build().expect("current macOS build")
}

struct CompilerFixture {
    runtime_root: AbsolutePathBuf,
    session_root: AbsolutePathBuf,
    workspace_root: AbsolutePathBuf,
    executable: AbsolutePathBuf,
    command: Vec<String>,
    build: String,
    _runtime: TempDir,
    _session: TempDir,
    _workspace: TempDir,
}

impl CompilerFixture {
    fn new() -> Self {
        let runtime = TempDir::new().expect("runtime root");
        let session = TempDir::new().expect("session root");
        let workspace = TempDir::new().expect("workspace root");
        let executable_path = runtime.path().join("omp-runtime");
        fs::write(&executable_path, "signed runtime fixture").expect("runtime executable");
        let mut permissions = fs::metadata(&executable_path)
            .expect("runtime executable metadata")
            .permissions();
        std::os::unix::fs::PermissionsExt::set_mode(&mut permissions, 0o700);
        fs::set_permissions(&executable_path, permissions).expect("runtime executable mode");
        let executable = absolute(&executable_path);
        Self {
            runtime_root: absolute(runtime.path()),
            session_root: absolute(session.path()),
            workspace_root: absolute(workspace.path()),
            command: vec![
                executable
                    .as_path()
                    .to_str()
                    .expect("UTF-8 executable fixture")
                    .to_string(),
                "--managed".to_string(),
            ],
            executable,
            build: current_build(),
            _runtime: runtime,
            _session: session,
            _workspace: workspace,
        }
    }

    fn request(&self) -> RbOuterOmpSeatbeltRequest<'_> {
        RbOuterOmpSeatbeltRequest {
            command: &self.command,
            verified_executable: &self.executable,
            signed_runtime_read_roots: std::slice::from_ref(&self.runtime_root),
            session_read_write_roots: std::slice::from_ref(&self.session_root),
            forbidden_roots: std::slice::from_ref(&self.workspace_root),
            inherited_fds: &[],
            rendezvous: RbOuterOmpRendezvous::DenyAll,
            expected_macos_build: &self.build,
            expected_arch: rb_outer_omp_current_arch().expect("current architecture"),
        }
    }
}

#[test]
fn rb_outer_omp_compiler_emits_only_the_dedicated_require_profile() {
    let fixture = CompilerFixture::new();
    let command = create_rb_outer_omp_seatbelt_command(fixture.request())
        .expect("compile dedicated outer profile");

    assert_eq!(
        command.program,
        PathBuf::from(crate::seatbelt::MACOS_PATH_TO_SEATBELT_EXECUTABLE)
    );
    assert_eq!(command.sandbox_preference, SandboxablePreference::Require);
    let policy = command
        .args
        .windows(2)
        .find_map(|pair| (pair[0] == "-p").then_some(pair[1].as_str()))
        .expect("compiled policy argument");
    assert!(policy.starts_with("(version 1)\n\n; ResearchBuddy"));
    assert!(policy.contains("(deny default (with message \"RB-LG5-DENY\"))"));
    assert!(policy.contains("(allow process-exec (literal (param \"RB_EXECUTABLE\")))"));
    assert!(policy.contains("RB_RUNTIME_READ_ROOT_0"));
    assert!(policy.contains("RB_SESSION_RW_ROOT_0"));
    assert!(!policy.contains("(allow process-fork"));
    assert!(!policy.contains("(allow network"));
    assert!(!policy.contains("(allow mach-"));
    assert!(!policy.contains("(allow pseudo-tty"));
    assert!(!policy.contains("(subpath \"/private/tmp\")"));
    assert!(!policy.contains("/Library/Preferences"));
    assert!(!policy.contains("/opt/homebrew"));
    assert!(!policy.contains("/usr/local"));
    assert!(!policy.contains("/System/Library/Frameworks"));
    assert!(!policy.contains("(subpath \"/var/db\")"));
    assert_eq!(
        command.profile_seal,
        RbOuterOmpProfileSeal {
            macos_build: fixture.build,
            arch: rb_outer_omp_current_arch()
                .expect("current architecture")
                .to_string(),
            template_sha256: RB_OUTER_OMP_TEMPLATE_SHA256.to_string(),
            lg5_provenance_evidence_sha256: RB_OUTER_OMP_LG5_PROVENANCE_EVIDENCE_SHA256.to_string(),
            concrete_policy_sha256: command.profile_seal.concrete_policy_sha256.clone(),
            compiled_launch_sha256: command.profile_seal.compiled_launch_sha256.clone(),
        }
    );
    assert_ne!(
        command.profile_seal.concrete_policy_sha256, RB_OUTER_OMP_LG5_PROVENANCE_EVIDENCE_SHA256,
        "LG5 evidence hash is provenance, not the concrete compiled policy seal"
    );
}

#[test]
fn rb_outer_omp_concrete_seal_changes_with_roots_and_complete_argv() {
    let fixture = CompilerFixture::new();
    let baseline =
        create_rb_outer_omp_seatbelt_command(fixture.request()).expect("baseline compiled profile");

    let alternate_session = TempDir::new().expect("alternate session root");
    let alternate_session_root = absolute(alternate_session.path());
    let changed_root = create_rb_outer_omp_seatbelt_command(RbOuterOmpSeatbeltRequest {
        session_read_write_roots: std::slice::from_ref(&alternate_session_root),
        ..fixture.request()
    })
    .expect("changed-root compiled profile");
    assert_ne!(
        baseline.profile_seal.concrete_policy_sha256,
        changed_root.profile_seal.concrete_policy_sha256
    );
    assert_ne!(
        baseline.profile_seal.compiled_launch_sha256,
        changed_root.profile_seal.compiled_launch_sha256
    );

    let changed_command = vec![
        fixture.command[0].clone(),
        "--different-signed-entry".to_string(),
    ];
    let changed_argv = create_rb_outer_omp_seatbelt_command(RbOuterOmpSeatbeltRequest {
        command: &changed_command,
        ..fixture.request()
    })
    .expect("changed-argv compiled profile");
    assert_eq!(
        baseline.profile_seal.concrete_policy_sha256,
        changed_argv.profile_seal.concrete_policy_sha256
    );
    assert_ne!(
        baseline.profile_seal.compiled_launch_sha256,
        changed_argv.profile_seal.compiled_launch_sha256
    );
}

#[test]
fn rb_outer_omp_compiler_fails_closed_on_build_path_and_authority_drift() {
    let fixture = CompilerFixture::new();

    let wrong_build = RbOuterOmpSeatbeltRequest {
        expected_macos_build: "definitely-not-this-build",
        ..fixture.request()
    };
    assert!(matches!(
        create_rb_outer_omp_seatbelt_command(wrong_build),
        Err(RbOuterOmpPreparationError::MacosBuildMismatch { .. })
    ));

    let wrong_arch = RbOuterOmpSeatbeltRequest {
        expected_arch: "not-this-architecture",
        ..fixture.request()
    };
    assert!(matches!(
        create_rb_outer_omp_seatbelt_command(wrong_arch),
        Err(RbOuterOmpPreparationError::ArchitectureMismatch { .. })
    ));

    let wrong_command = vec!["/usr/bin/true".to_string()];
    let executable_drift = RbOuterOmpSeatbeltRequest {
        command: &wrong_command,
        ..fixture.request()
    };
    assert_eq!(
        create_rb_outer_omp_seatbelt_command(executable_drift),
        Err(RbOuterOmpPreparationError::ExecutableMismatch)
    );

    let overlapping_session = RbOuterOmpSeatbeltRequest {
        session_read_write_roots: std::slice::from_ref(&fixture.workspace_root),
        ..fixture.request()
    };
    assert!(matches!(
        create_rb_outer_omp_seatbelt_command(overlapping_session),
        Err(RbOuterOmpPreparationError::OverlappingRoots { .. })
    ));

    let broad_root = absolute(Path::new("/private/tmp"));
    let broad_session = RbOuterOmpSeatbeltRequest {
        session_read_write_roots: std::slice::from_ref(&broad_root),
        ..fixture.request()
    };
    assert_eq!(
        create_rb_outer_omp_seatbelt_command(broad_session),
        Err(RbOuterOmpPreparationError::BroadRoot(
            "/private/tmp".to_string()
        ))
    );

    let symlink = fixture._workspace.path().join("session-alias");
    std::os::unix::fs::symlink(fixture._session.path(), &symlink).expect("session symlink");
    let symlink_root = absolute_without_canonicalizing(&symlink);
    let symlink_session = RbOuterOmpSeatbeltRequest {
        session_read_write_roots: std::slice::from_ref(&symlink_root),
        ..fixture.request()
    };
    assert!(matches!(
        create_rb_outer_omp_seatbelt_command(symlink_session),
        Err(RbOuterOmpPreparationError::InvalidRoot(_))
    ));

    let broad_forbidden_root = absolute(Path::new("/Users"));
    let broad_forbidden = RbOuterOmpSeatbeltRequest {
        forbidden_roots: std::slice::from_ref(&broad_forbidden_root),
        ..fixture.request()
    };
    create_rb_outer_omp_seatbelt_command(broad_forbidden)
        .expect("broad deny roots must not be mistaken for broad grants");
}

#[cfg(unix)]
#[test]
fn rb_outer_omp_compiler_rejects_non_utf8_paths_before_replacement_can_collide() {
    use std::ffi::OsString;
    use std::os::unix::ffi::OsStringExt;

    let fixture = CompilerFixture::new();
    let invalid_root_path = fixture
        ._session
        .path()
        .canonicalize()
        .expect("canonical session fixture")
        .join(OsString::from_vec(b"collision-\xff".to_vec()));
    let replacement_root_path = fixture._session.path().join("collision-\u{fffd}");
    fs::create_dir(&replacement_root_path).expect("replacement root fixture");
    let invalid_root = absolute_without_canonicalizing(&invalid_root_path);
    let replacement_root = absolute(&replacement_root_path);
    assert_eq!(
        invalid_root.as_path().to_string_lossy(),
        replacement_root.as_path().to_string_lossy(),
        "fixture must reproduce the lossy replacement collision"
    );

    let invalid_session = RbOuterOmpSeatbeltRequest {
        session_read_write_roots: std::slice::from_ref(&invalid_root),
        ..fixture.request()
    };
    assert_eq!(
        create_rb_outer_omp_seatbelt_command(invalid_session),
        Err(RbOuterOmpPreparationError::InvalidRoot(
            "path is not valid UTF-8".to_string()
        ))
    );

    let invalid_executable_path = fixture
        ._runtime
        .path()
        .canonicalize()
        .expect("canonical runtime fixture")
        .join(OsString::from_vec(b"omp-\xff".to_vec()));
    let invalid_executable = absolute_without_canonicalizing(&invalid_executable_path);
    let replacement_command = vec![
        fixture
            ._runtime
            .path()
            .join("omp-\u{fffd}")
            .to_str()
            .expect("replacement command")
            .to_string(),
    ];
    let invalid_executable_request = RbOuterOmpSeatbeltRequest {
        command: &replacement_command,
        verified_executable: &invalid_executable,
        ..fixture.request()
    };
    assert_eq!(
        create_rb_outer_omp_seatbelt_command(invalid_executable_request),
        Err(RbOuterOmpPreparationError::InvalidExecutable(
            "path is not valid UTF-8".to_string()
        ))
    );
}
