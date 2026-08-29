use super::*;
use codex_sandboxing::RB_OUTER_OMP_LG5_PROVENANCE_EVIDENCE_SHA256;
use codex_sandboxing::RB_OUTER_OMP_TEMPLATE_SHA256;
use sha2::Digest;
use sha2::Sha256;
use std::fs;
use std::os::unix::fs::MetadataExt;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::path::PathBuf;
use std::time::Duration;
use tempfile::TempDir;

struct AuthorityFixture {
    policy: LaunchPolicyCandidateV1,
    _root: TempDir,
}

#[cfg(target_os = "macos")]
fn spawn_window_exclusion() -> std::sync::MutexGuard<'static, ()> {
    // Spawn syscalls transiently duplicate every flocked descriptor into the
    // child until exec applies O_CLOEXEC; hold the exclusion for each spawn
    // so lock-lifecycle tests never drop-then-reopen inside that window.
    crate::test_spawn_exclusion::acquire()
}

#[cfg(target_os = "macos")]
fn current_test_designated_requirement() -> String {
    use std::process::Command;

    let executable = std::env::current_exe().expect("current test executable");
    let output = {
        let _spawn_window = spawn_window_exclusion();
        Command::new("/usr/bin/codesign")
            .args(["-d", "-r-"])
            .arg(&executable)
            .output()
            .expect("inspect current test designated requirement")
    };
    assert!(output.status.success(), "codesign inspection failed");
    let output_text = format!(
        "{}\n{}",
        String::from_utf8(output.stdout).expect("UTF-8 codesign stdout"),
        String::from_utf8(output.stderr).expect("UTF-8 codesign stderr")
    );
    output_text
        .lines()
        .find_map(|line| line.split_once("designated => ").map(|(_, value)| value))
        .unwrap_or_else(|| panic!("codesign designated requirement missing: {output_text}"))
        .to_string()
}

#[cfg(target_os = "macos")]
struct LiveLaunchFixture {
    reserved_attempt: GuardReservedLaunchAttempt,
    session_cwd: PathBuf,
    launch_guard_root: PathBuf,
    _root: TempDir,
}

#[cfg(target_os = "macos")]
impl LiveLaunchFixture {
    fn new(generation: u64, test_name: &str) -> Self {
        let root = tempfile::Builder::new()
            .prefix("rblg7-")
            .tempdir_in("/private/tmp")
            .expect("short live fixture root");
        let session = root.path().join("s");
        let launch_guard = root.path().join("g");
        let forbidden = root.path().join("w");
        fs::create_dir(&session).expect("live session");
        fs::create_dir(&launch_guard).expect("live launch guard");
        fs::create_dir(&forbidden).expect("live forbidden");
        fs::set_permissions(&session, fs::Permissions::from_mode(0o700))
            .expect("live session mode");
        fs::set_permissions(&launch_guard, fs::Permissions::from_mode(0o700))
            .expect("live launch guard mode");
        let session = session.canonicalize().expect("canonical live session");
        let launch_guard = launch_guard
            .canonicalize()
            .expect("canonical live launch guard");
        let forbidden = forbidden.canonicalize().expect("canonical live forbidden");
        let executable = std::env::current_exe()
            .expect("live executable")
            .canonicalize()
            .expect("canonical live executable");
        let runtime = executable
            .parent()
            .expect("live executable parent")
            .canonicalize()
            .expect("canonical live runtime");
        let session_metadata = session.metadata().expect("live session metadata");
        let launch_guard_metadata = launch_guard.metadata().expect("live guard metadata");
        let policy = ValidatedLaunchPolicy {
            expected_macos_build: codex_sandboxing::rb_outer_omp_current_macos_build()
                .expect("macOS build"),
            expected_arch: codex_sandboxing::rb_outer_omp_current_arch()
                .expect("architecture")
                .to_string(),
            executable_sha256: sha256_path(&executable),
            argv: vec![
                executable
                    .to_str()
                    .expect("UTF-8 live executable")
                    .to_string(),
                "--exact".to_string(),
                test_name.to_string(),
                "--nocapture".to_string(),
            ],
            executable,
            signed_runtime_root: runtime,
            session_cwd: session.clone(),
            session_cwd_device: session_metadata.dev(),
            session_cwd_inode: session_metadata.ino(),
            launch_guard_root: launch_guard.clone(),
            launch_guard_root_device: launch_guard_metadata.dev(),
            launch_guard_root_inode: launch_guard_metadata.ino(),
            forbidden_roots: vec![forbidden],
            designated_requirement: current_test_designated_requirement(),
        };
        Self {
            reserved_attempt: GuardReservedLaunchAttempt::new_for_test(
                policy,
                17,
                generation,
                "d".repeat(64),
            ),
            session_cwd: session,
            launch_guard_root: launch_guard,
            _root: root,
        }
    }
}

#[cfg(target_os = "macos")]
fn sha256_path(path: &Path) -> String {
    format!(
        "{:x}",
        Sha256::digest(fs::read(path).expect("read executable for digest"))
    )
}

#[cfg(target_os = "macos")]
fn wait_for_test_marker(path: &Path) {
    for _ in 0..500 {
        if path.exists() {
            return;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    panic!("timed out waiting for child stage marker");
}

impl AuthorityFixture {
    fn new() -> Self {
        let root = tempfile::Builder::new()
            .prefix("rba-")
            .tempdir_in("/private/tmp")
            .expect("short fixture root");
        let runtime_path = root.path().join("r");
        let session_path = root.path().join("s");
        let forbidden_path = root.path().join("w");
        let launch_guard_path = root.path().join("g");
        fs::create_dir(&runtime_path).expect("runtime root");
        fs::create_dir(&session_path).expect("session root");
        fs::create_dir(&forbidden_path).expect("forbidden root");
        fs::create_dir(&launch_guard_path).expect("launch guard root");
        fs::set_permissions(&session_path, fs::Permissions::from_mode(0o700))
            .expect("session mode");
        fs::set_permissions(&launch_guard_path, fs::Permissions::from_mode(0o700))
            .expect("launch guard mode");
        let executable_path = runtime_path.join("omp-runtime");
        fs::write(&executable_path, b"signed probe").expect("probe binary");
        fs::set_permissions(&executable_path, fs::Permissions::from_mode(0o700))
            .expect("probe mode");
        let runtime = runtime_path.canonicalize().expect("canonical runtime");
        let session = session_path.canonicalize().expect("canonical session");
        let forbidden = forbidden_path.canonicalize().expect("canonical forbidden");
        let launch_guard_root = launch_guard_path
            .canonicalize()
            .expect("canonical launch guard root");
        let executable = executable_path
            .canonicalize()
            .expect("canonical executable");
        let metadata = session.metadata().expect("session metadata");
        let launch_guard_metadata = launch_guard_root.metadata().expect("launch guard metadata");
        let executable_sha256 = format!("{:x}", Sha256::digest(b"signed probe"));
        Self {
            policy: LaunchPolicyCandidateV1 {
                schema: "rb.launch-policy-candidate.v1".to_string(),
                expected_macos_build: codex_sandboxing::rb_outer_omp_current_macos_build()
                    .expect("macOS build"),
                expected_arch: codex_sandboxing::rb_outer_omp_current_arch()
                    .expect("architecture")
                    .to_string(),
                expected_profile_template_sha256: RB_OUTER_OMP_TEMPLATE_SHA256.to_string(),
                expected_lg5_provenance_evidence_sha256:
                    RB_OUTER_OMP_LG5_PROVENANCE_EVIDENCE_SHA256.to_string(),
                executable,
                executable_sha256,
                argv: vec![
                    executable_path
                        .canonicalize()
                        .expect("canonical argv executable")
                        .to_str()
                        .expect("UTF-8 argv executable")
                        .to_string(),
                    "--managed-signed-entry".to_string(),
                ],
                signed_runtime_root: runtime,
                session_cwd: session,
                session_cwd_device: metadata.dev(),
                session_cwd_inode: metadata.ino(),
                launch_guard_root,
                launch_guard_root_device: launch_guard_metadata.dev(),
                launch_guard_root_inode: launch_guard_metadata.ino(),
                forbidden_roots: vec![forbidden],
                designated_requirement: concat!(
                    "identifier \"com.researchbuddy.omp\" and ",
                    "certificate leaf[subject.OU] = \"TEAMID1234\" and ",
                    "cdhash H\"0123456789012345678901234567890123456789\""
                )
                .to_string(),
            },
            _root: root,
        }
    }
}

#[test]
fn policy_validation_binds_identity_profile_and_model_invisible_roots() {
    let fixture = AuthorityFixture::new();
    let validated =
        validate_launch_policy(fixture.policy.clone()).expect("validated launch policy");
    assert_eq!(
        validated.session_cwd_device,
        fixture.policy.session_cwd_device
    );
    assert_eq!(
        validated.session_cwd_inode,
        fixture.policy.session_cwd_inode
    );
}

#[test]
fn policy_rejects_executable_profile_session_and_root_drift() {
    let mut digest_drift = AuthorityFixture::new();
    digest_drift.policy.executable_sha256 = "b".repeat(64);
    assert!(matches!(
        validate_launch_policy(digest_drift.policy),
        Err(LaunchGuardError::DigestMismatch {
            field: "executable",
            ..
        })
    ));

    let mut profile_drift = AuthorityFixture::new();
    profile_drift.policy.expected_profile_template_sha256 = "c".repeat(64);
    assert!(matches!(
        validate_launch_policy(profile_drift.policy),
        Err(LaunchGuardError::DigestMismatch {
            field: "profileTemplate",
            ..
        })
    ));

    let mut identity_drift = AuthorityFixture::new();
    identity_drift.policy.session_cwd_inode += 1;
    assert!(matches!(
        validate_launch_policy(identity_drift.policy),
        Err(LaunchGuardError::IdentityDrift(_))
    ));

    let mut overlap = AuthorityFixture::new();
    overlap.policy.forbidden_roots = vec![overlap.policy.session_cwd.clone()];
    assert!(matches!(
        validate_launch_policy(overlap.policy),
        Err(LaunchGuardError::InvalidPath(_))
    ));

    let mut argv_drift = AuthorityFixture::new();
    argv_drift.policy.argv[0] = "/usr/bin/true".to_string();
    assert!(matches!(
        validate_launch_policy(argv_drift.policy),
        Err(LaunchGuardError::InvalidAuthority(_))
    ));
}

#[test]
fn executable_drift_after_policy_validation_fails_before_spawn() {
    let fixture = AuthorityFixture::new();
    let validated =
        validate_launch_policy(fixture.policy.clone()).expect("validated launch policy");
    fs::write(&fixture.policy.executable, b"replaced after approval")
        .expect("replace executable fixture");
    assert!(matches!(
        validated.revalidate_for_exec(),
        Err(LaunchGuardError::DigestMismatch {
            field: "executable",
            ..
        })
    ));
}

#[test]
fn validated_policy_owns_the_exact_argv_snapshot() {
    let mut fixture = AuthorityFixture::new();
    let validated =
        validate_launch_policy(fixture.policy.clone()).expect("validated launch policy");
    fixture.policy.argv[1] = "--unapproved-hidden-selector".to_string();
    assert_eq!(
        validated.argv(),
        vec![
            validated
                .executable
                .to_str()
                .expect("UTF-8 verified executable")
                .to_string(),
            "--managed-signed-entry".to_string(),
        ]
    );
}

#[cfg(target_os = "macos")]
#[test]
fn rendezvous_launch_preparation_exposes_no_authority_channel() {
    let fixture = AuthorityFixture::new();
    let policy = validate_launch_policy(fixture.policy).expect("validated launch policy");
    let reserved = GuardReservedLaunchAttempt::new_for_test(policy, 7, 11, "a".repeat(64));
    let prepared = prepare_rendezvous_launch(reserved).expect("prepare rendezvous launch");
    drop(prepared);
}

#[cfg(target_os = "macos")]
#[test]
fn pre_exec_rejects_session_mode_drift_after_parent_revalidation() {
    let fixture = AuthorityFixture::new();
    let session = fixture.policy.session_cwd.clone();
    let policy = validate_launch_policy(fixture.policy).expect("validated launch policy");
    let reserved = GuardReservedLaunchAttempt::new_for_test(policy, 7, 11, "a".repeat(64));
    let prepared = prepare_rendezvous_launch(reserved).expect("prepare rendezvous launch");
    let changed_session = session.clone();
    let result = prepared.spawn_after_test_mutation(move || {
        fs::set_permissions(&changed_session, fs::Permissions::from_mode(0o755))
            .expect("mutate session mode after parent revalidation");
    });
    fs::set_permissions(&session, fs::Permissions::from_mode(0o700)).expect("restore session mode");
    assert!(matches!(result, Err(LaunchGuardError::IdentityDrift(_))));
}

#[cfg(target_os = "macos")]
#[test]
fn real_kqueue_note_exec_is_kernel_sourced() {
    use std::os::unix::process::CommandExt;
    use std::process::Command;
    use std::time::Duration;

    const CHILD: &str = "RB_LG_NOTE_EXEC_TEST_CHILD";
    match std::env::var(CHILD).as_deref() {
        Ok("before") => {
            std::thread::sleep(Duration::from_millis(300));
            let error = Command::new(std::env::current_exe().expect("test executable"))
                .arg("--exact")
                .arg("tests::real_kqueue_note_exec_is_kernel_sourced")
                .arg("--nocapture")
                .env(CHILD, "after")
                .exec();
            panic!("self exec failed: {error}");
        }
        Ok("after") => {
            std::thread::sleep(Duration::from_millis(500));
            return;
        }
        _ => {}
    }

    let mut child = {
        let _spawn_window = spawn_window_exclusion();
        Command::new(std::env::current_exe().expect("test executable"))
            .arg("--exact")
            .arg("tests::real_kqueue_note_exec_is_kernel_sourced")
            .arg("--nocapture")
            .env(CHILD, "before")
            .spawn()
            .expect("spawn self-exec probe")
    };
    let watcher = MacProcessEventWatcher::new(child.id()).expect("NOTE_EXEC watcher");
    let event = watcher
        .wait(Duration::from_secs(2))
        .expect("NOTE_EXEC wait")
        .expect("NOTE_EXEC event");
    assert!(matches!(
        event,
        MacProcessEvent::Exec | MacProcessEvent::ExecAndExit
    ));
    let status = child.wait().expect("self-exec probe exit");
    assert!(status.success());
}

#[cfg(target_os = "macos")]
fn exact_rendezvous_authenticates_owned_frame_batch(
    test_name: &'static str,
    generations: std::ops::Range<u64>,
) {
    use std::io::Read;
    use std::io::Write;
    use std::os::unix::net::UnixStream;

    if let Ok(path) = std::env::var("RB_RENDEZVOUS_PATH") {
        let mut stream = UnixStream::connect(path).expect("connect exact rendezvous");
        let session = std::env::current_dir().expect("frame session cwd");
        wait_for_test_marker(&session.join("host-authenticated"));
        stream
            .write_all(b"{\"kind\":\"capability-proposal\"}\n")
            .expect("write owned frame");
        let mut discarded = Vec::new();
        let _ = stream.read_to_end(&mut discarded);
        return;
    }

    for generation in generations {
        let fixture = LiveLaunchFixture::new(generation, test_name);
        let authenticated_marker = fixture.session_cwd.join("host-authenticated");
        let prepared =
            prepare_rendezvous_launch(fixture.reserved_attempt).expect("prepare exact rendezvous");
        let rendezvous_path = prepared.rendezvous_path().to_path_buf();
        assert!(rendezvous_path.exists());
        let spawned = prepared.spawn().expect("spawn exact rendezvous child");
        let mut authenticated = spawned
            .authenticate_unreachable(Duration::from_secs(3))
            .expect("authenticate single transport");
        fs::write(&authenticated_marker, b"ready").expect("release frame writer");
        let frame = authenticated.read_owned_frame().expect("owned frame");
        assert_eq!(frame.sequence(), 1);
        assert_eq!(frame.bytes(), b"{\"kind\":\"capability-proposal\"}");
        assert_eq!(frame.sha256().len(), 64);
        assert!(!rendezvous_path.exists());
        assert!(UnixStream::connect(&rendezvous_path).is_err());
        assert_eq!(
            fs::read_dir(&fixture.launch_guard_root)
                .expect("read launch guard root")
                .count(),
            0
        );
        let _ = authenticated.terminate().expect("terminate probe child");
    }
}

#[cfg(target_os = "macos")]
#[test]
fn exact_rendezvous_authenticates_owned_frame_batch_1() {
    exact_rendezvous_authenticates_owned_frame_batch(
        "tests::exact_rendezvous_authenticates_owned_frame_batch_1",
        18..28,
    );
}

#[cfg(target_os = "macos")]
#[test]
fn exact_rendezvous_authenticates_owned_frame_batch_2() {
    exact_rendezvous_authenticates_owned_frame_batch(
        "tests::exact_rendezvous_authenticates_owned_frame_batch_2",
        28..38,
    );
}

#[cfg(target_os = "macos")]
#[test]
fn exact_rendezvous_authenticates_owned_frame_batch_3() {
    exact_rendezvous_authenticates_owned_frame_batch(
        "tests::exact_rendezvous_authenticates_owned_frame_batch_3",
        38..48,
    );
}

#[cfg(target_os = "macos")]
#[test]
fn exact_rendezvous_authenticates_owned_frame_batch_4() {
    exact_rendezvous_authenticates_owned_frame_batch(
        "tests::exact_rendezvous_authenticates_owned_frame_batch_4",
        48..58,
    );
}

#[cfg(target_os = "macos")]
#[test]
fn exact_rendezvous_authenticates_owned_frame_batch_5() {
    exact_rendezvous_authenticates_owned_frame_batch(
        "tests::exact_rendezvous_authenticates_owned_frame_batch_5",
        58..68,
    );
}

#[cfg(target_os = "macos")]
#[test]
fn unrelated_exec_noise_does_not_change_authenticated_execution_identity() {
    use std::io::Read;
    use std::io::Write;
    use std::os::unix::net::UnixStream;
    use std::process::Command;

    const TEST_NAME: &str =
        "tests::unrelated_exec_noise_does_not_change_authenticated_execution_identity";
    if let Ok(path) = std::env::var("RB_RENDEZVOUS_PATH") {
        let mut stream = UnixStream::connect(path).expect("connect noisy rendezvous");
        let session = std::env::current_dir().expect("noise session cwd");
        wait_for_test_marker(&session.join("host-authenticated"));
        stream
            .write_all(b"{\"kind\":\"noise-safe\"}\n")
            .expect("write noisy frame");
        let mut discarded = Vec::new();
        let _ = stream.read_to_end(&mut discarded);
        return;
    }

    for generation in 301..309 {
        let fixture = LiveLaunchFixture::new(generation, TEST_NAME);
        let authenticated_marker = fixture.session_cwd.join("host-authenticated");
        let prepared =
            prepare_rendezvous_launch(fixture.reserved_attempt).expect("prepare noisy launch");
        let spawned = prepared
            .spawn_with_test_after_baseline(|| {
                let _spawn_window = spawn_window_exclusion();
                for _ in 0..64 {
                    assert!(
                        Command::new("/usr/bin/true")
                            .status()
                            .expect("exec noise")
                            .success()
                    );
                }
            })
            .expect("spawn noisy launch");
        let mut transport = spawned
            .authenticate_unreachable(Duration::from_secs(3))
            .expect("unrelated exec noise must not reject valid child");
        fs::write(authenticated_marker, b"ready").expect("release noisy frame");
        let frame = transport.read_owned_frame().expect("noise-safe frame");
        assert_eq!(frame.bytes(), b"{\"kind\":\"noise-safe\"}");
        let _ = transport.terminate().expect("terminate noisy child");
    }
}

#[cfg(target_os = "macos")]
#[test]
fn invalid_physical_frames_revoke_the_whole_authenticated_transport() {
    use std::io::Read;
    use std::io::Write;
    use std::net::Shutdown;
    use std::os::unix::net::UnixStream;

    const TEST_NAME: &str =
        "tests::invalid_physical_frames_revoke_the_whole_authenticated_transport";
    if let Ok(path) = std::env::var("RB_RENDEZVOUS_PATH") {
        let generation = std::env::var("RB_GENERATION")
            .expect("generation environment")
            .parse::<u64>()
            .expect("numeric generation");
        let mut stream = UnixStream::connect(path).expect("connect frame rendezvous");
        let session = std::env::current_dir().expect("frame session cwd");
        wait_for_test_marker(&session.join("host-authenticated"));
        match generation {
            101 => stream.write_all(b"{}").expect("write partial frame"),
            102 => stream.write_all(b"\xff\n").expect("write invalid UTF-8"),
            103 => stream.write_all(b"[]\n").expect("write non-object frame"),
            104 => stream.write_all(b" \n").expect("write whitespace frame"),
            105 => {
                let mut oversized = vec![b'a'; RB_OMP_MAX_PHYSICAL_FRAME_BYTES];
                oversized.push(b'\n');
                stream.write_all(&oversized).expect("write oversized frame");
            }
            106 => {}
            107 => stream
                .write_all(b"{invalid}\n")
                .expect("write malformed JSON"),
            108 => stream.write_all(b"{}\n").expect("write overflow frame"),
            _ => panic!("unexpected frame generation"),
        }
        stream
            .shutdown(Shutdown::Write)
            .expect("finish frame stream");
        let mut discarded = Vec::new();
        let _ = stream.read_to_end(&mut discarded);
        return;
    }

    for generation in 101..=108 {
        let fixture = LiveLaunchFixture::new(generation, TEST_NAME);
        let authenticated_marker = fixture.session_cwd.join("host-authenticated");
        let prepared =
            prepare_rendezvous_launch(fixture.reserved_attempt).expect("prepare frame case");
        let spawned = prepared.spawn().expect("spawn frame case");
        let mut transport = spawned
            .authenticate_unreachable(Duration::from_secs(3))
            .expect("authenticate frame case");
        if generation == 108 {
            transport.set_sequence_for_test(u64::MAX);
        }
        fs::write(authenticated_marker, b"ready").expect("release frame case");
        let error = transport
            .read_owned_frame()
            .expect_err("invalid frame must be terminal");
        match generation {
            101 => assert_eq!(error, LaunchGuardError::PartialFrameAtEof),
            102 => assert_eq!(error, LaunchGuardError::InvalidFrameUtf8),
            103 => assert_eq!(error, LaunchGuardError::FrameMustBeObject),
            104 => assert_eq!(error, LaunchGuardError::EmptyFrame),
            105 => assert_eq!(
                error,
                LaunchGuardError::FrameTooLong {
                    max_physical_bytes: RB_OMP_MAX_PHYSICAL_FRAME_BYTES,
                }
            ),
            106 => assert_eq!(error, LaunchGuardError::TransportEof),
            107 => assert_eq!(error, LaunchGuardError::InvalidFrameJson),
            108 => assert_eq!(error, LaunchGuardError::FrameSequenceOverflow),
            _ => unreachable!(),
        }
        assert_eq!(
            transport.read_owned_frame(),
            Err(LaunchGuardError::TransportRevoked)
        );
    }
}

#[cfg(target_os = "macos")]
#[test]
fn frame_spanning_exec_and_child_exit_both_stickily_revoke_transport() {
    use std::io::Read;
    use std::io::Write;
    use std::os::fd::AsRawFd;
    use std::os::fd::FromRawFd;
    use std::os::unix::net::UnixStream;
    use std::os::unix::process::CommandExt;
    use std::process::Command;

    const TEST_NAME: &str =
        "tests::frame_spanning_exec_and_child_exit_both_stickily_revoke_transport";
    if let Ok(retained_fd) = std::env::var("RB_LG8_EXEC_FRAME_FD") {
        let mut stream = unsafe {
            UnixStream::from_raw_fd(retained_fd.parse::<i32>().expect("numeric retained fd"))
        };
        fs::write(
            std::env::current_dir()
                .expect("exec frame cwd")
                .join("exec-complete"),
            b"ready",
        )
        .expect("write exec-complete marker");
        stream
            .write_all(b"true}\n")
            .expect("complete frame after exec");
        let mut discarded = Vec::new();
        let _ = stream.read_to_end(&mut discarded);
        return;
    }
    if let Ok(path) = std::env::var("RB_RENDEZVOUS_PATH") {
        let generation = std::env::var("RB_GENERATION")
            .expect("generation environment")
            .parse::<u64>()
            .expect("numeric generation");
        let mut stream = UnixStream::connect(path).expect("connect lifecycle rendezvous");
        let session = std::env::current_dir().expect("lifecycle session cwd");
        wait_for_test_marker(&session.join("host-authenticated"));
        if generation == 201 {
            stream
                .write_all(b"{\"spansExec\":")
                .expect("write pre-exec partial frame");
            fs::write(session.join("partial-ready"), b"ready").expect("write partial-ready marker");
            wait_for_test_marker(&session.join("exec-go"));
            let fd = stream.as_raw_fd();
            assert_ne!(unsafe { libc::fcntl(fd, libc::F_SETFD, 0) }, -1);
            let error = Command::new(std::env::current_exe().expect("selfexec executable"))
                .arg("--exact")
                .arg(TEST_NAME)
                .arg("--nocapture")
                .arg("--test-threads=1")
                .env("RB_LG8_EXEC_FRAME_FD", fd.to_string())
                .exec();
            panic!("frame selfexec failed: {error}");
        }
        fs::write(session.join("exit-now"), b"ready").expect("write exit marker");
        return;
    }

    for generation in [201, 202] {
        let fixture = LiveLaunchFixture::new(generation, TEST_NAME);
        let session = fixture.session_cwd.clone();
        let prepared =
            prepare_rendezvous_launch(fixture.reserved_attempt).expect("prepare lifecycle case");
        let spawned = prepared.spawn().expect("spawn lifecycle case");
        let mut transport = spawned
            .authenticate_unreachable(Duration::from_secs(3))
            .expect("authenticate lifecycle case");
        fs::write(session.join("host-authenticated"), b"ready").expect("release lifecycle child");
        if generation == 201 {
            wait_for_test_marker(&session.join("partial-ready"));
            let error = transport
                .read_owned_frame_with_test_after_precheck(|| {
                    fs::write(session.join("exec-go"), b"go").expect("release cross-exec frame");
                })
                .expect_err("cross-exec frame must be rejected");
            assert!(
                matches!(
                    error,
                    LaunchGuardError::AuthenticatedExecGenerationDrift { .. }
                ),
                "post-read identity check returned unexpected error: {error:?}"
            );
            assert!(session.join("exec-complete").exists());
        } else {
            wait_for_test_marker(&session.join("exit-now"));
            let error = transport
                .read_owned_frame()
                .expect_err("child exit must revoke transport");
            assert!(matches!(
                error,
                LaunchGuardError::ProcessExitObserved | LaunchGuardError::TransportEof
            ));
        }
        assert_eq!(
            transport.read_owned_frame(),
            Err(LaunchGuardError::TransportRevoked)
        );
    }
}

#[cfg(target_os = "macos")]
#[test]
fn pre_identity_bytes_are_terminal_before_any_channel_transfer() {
    use std::io::Write;
    use std::os::unix::net::UnixStream;

    const TEST_NAME: &str = "tests::pre_identity_bytes_are_terminal_before_any_channel_transfer";
    if let Ok(path) = std::env::var("RB_RENDEZVOUS_PATH") {
        let mut stream = UnixStream::connect(path).expect("connect exact rendezvous");
        stream
            .write_all(b"forbidden-pre-identity")
            .expect("write early bytes");
        std::thread::sleep(Duration::from_secs(2));
        return;
    }

    let fixture = LiveLaunchFixture::new(19, TEST_NAME);
    let prepared =
        prepare_rendezvous_launch(fixture.reserved_attempt).expect("prepare early-byte probe");
    let rendezvous_path = prepared.rendezvous_path().to_path_buf();
    let spawned = prepared.spawn().expect("spawn early-byte child");
    std::thread::sleep(Duration::from_millis(100));
    let error = match spawned.authenticate_unreachable(Duration::from_secs(2)) {
        Err(error) => error,
        Ok(launch) => {
            let _ = launch.terminate();
            panic!("pre-identity payload unexpectedly armed the launch");
        }
    };
    assert!(matches!(
        error,
        LaunchGuardError::LiveIdentity(message) if message == "peer sent bytes before live identity"
    ));
    assert!(!rendezvous_path.exists());
    assert_eq!(
        fs::read_dir(&fixture.launch_guard_root)
            .expect("read launch guard root")
            .count(),
        0
    );
}

#[cfg(target_os = "macos")]
#[test]
fn preconnected_wrong_peer_is_rejected_without_consuming_authenticated_transfer() {
    use std::os::unix::net::UnixStream;

    const TEST_NAME: &str =
        "tests::preconnected_wrong_peer_is_rejected_without_consuming_authenticated_transfer";
    if let Ok(path) = std::env::var("RB_RENDEZVOUS_PATH") {
        std::thread::sleep(Duration::from_secs(2));
        let _ = UnixStream::connect(path);
        return;
    }

    let fixture = LiveLaunchFixture::new(20, TEST_NAME);
    let prepared =
        prepare_rendezvous_launch(fixture.reserved_attempt).expect("prepare wrong-peer probe");
    let rendezvous_path = prepared.rendezvous_path().to_path_buf();
    let attacker = UnixStream::connect(&rendezvous_path).expect("preconnect attacker");
    let spawned = prepared.spawn().expect("spawn delayed signed child");
    let spawned_pid = spawned.child_id().expect("spawned pid");
    let error = match spawned.authenticate_unreachable(Duration::from_secs(2)) {
        Err(error) => error,
        Ok(launch) => {
            let _ = launch.terminate();
            panic!("wrong peer unexpectedly armed the launch");
        }
    };
    assert!(matches!(
        error,
        LaunchGuardError::PeerPidMismatch {
            spawned_pid: actual,
            ..
        } if actual == spawned_pid
    ));
    drop(attacker);
    assert!(!rendezvous_path.exists());
}

#[cfg(target_os = "macos")]
#[test]
fn inherited_socketpair_is_not_accepted_as_spawned_child_identity() {
    use std::os::fd::AsRawFd;
    use std::os::unix::net::UnixStream;
    use std::os::unix::process::CommandExt;
    use std::process::Command;
    use std::time::Duration;

    const CHILD: &str = "RB_LG_PEER_TEST_CHILD";
    if std::env::var(CHILD).as_deref() == Ok("1") {
        std::thread::sleep(Duration::from_millis(500));
        return;
    }

    let launcher_pid = unsafe { libc::getpid() };
    let (host, child_endpoint) = UnixStream::pair().expect("socketpair");
    let source_fd = child_endpoint.as_raw_fd();
    let mut command = Command::new(std::env::current_exe().expect("test executable"));
    command
        .arg("--exact")
        .arg("tests::inherited_socketpair_is_not_accepted_as_spawned_child_identity")
        .arg("--nocapture")
        .env(CHILD, "1");
    unsafe {
        command.pre_exec(move || {
            if libc::dup2(source_fd, 20) < 0 || libc::fcntl(20, libc::F_SETFD, 0) < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let mut child = {
        let _spawn_window = spawn_window_exclusion();
        command.spawn().expect("spawn inherited socket probe")
    };
    drop(child_endpoint);
    let error =
        verify_macos_live_peer_identity(&host, child.id(), "identifier \"invalid.test.only\"")
            .expect_err("inherited socketpair must not be accepted as child identity");
    match error {
        LaunchGuardError::PeerPidMismatch {
            socket_pid,
            token_pid,
            spawned_pid,
        } => {
            assert_eq!(socket_pid, launcher_pid);
            assert_eq!(token_pid, launcher_pid);
            assert_eq!(spawned_pid, child.id());
            assert_ne!(spawned_pid as i32, launcher_pid);
        }
        other => panic!("expected exact inherited-peer PID mismatch, got {other}"),
    }
    let status = child.wait().expect("peer probe exit");
    assert!(status.success());
}

#[cfg(target_os = "macos")]
#[test]
fn current_process_owned_socket_reaches_and_passes_seccode_validation() {
    use std::os::unix::net::UnixStream;

    let (host, peer) = UnixStream::pair().expect("current-process socketpair");
    let identity = verify_macos_live_peer_identity(
        &host,
        std::process::id(),
        &current_test_designated_requirement(),
    )
    .expect("live current process satisfies its own designated requirement");
    assert_eq!(identity.pid, std::process::id());
    assert!(identity.pid_version > 0);
    assert_eq!(identity.audit_token_sha256.len(), 64);
    drop(peer);
}

#[cfg(target_os = "macos")]
#[test]
fn current_process_owned_socket_reports_seccode_requirement_failure_exactly() {
    use std::os::unix::net::UnixStream;

    let (host, peer) = UnixStream::pair().expect("current-process socketpair");
    let error = verify_macos_live_peer_identity(
        &host,
        std::process::id(),
        "identifier \"definitely.not.the.current.test\"",
    )
    .expect_err("wrong designated requirement must fail in Security.framework");
    assert!(matches!(error, LaunchGuardError::SecCodeInvalid(_)));
    drop(peer);
}
