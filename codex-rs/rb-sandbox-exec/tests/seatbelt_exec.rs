//! End-to-end tests for the `rb-sandbox-exec` runner on macOS.
//!
//! These tests execute the real `/usr/bin/sandbox-exec` through the built
//! binary, so they only run on macOS hosts.

#![cfg(target_os = "macos")]

use std::process::Command;
use std::process::Output;
use std::time::Duration;
use std::time::Instant;

const RUNNER_FAILURE_EXIT_CODE: i32 = 250;
const TIMEOUT_EXIT_CODE: i32 = 124;

fn runner() -> &'static str {
    env!("CARGO_BIN_EXE_rb-sandbox-exec")
}

fn run_runner(args: &[&str]) -> std::io::Result<Output> {
    Command::new(runner()).args(args).output()
}

fn temp_workspace() -> std::io::Result<tempfile::TempDir> {
    tempfile::tempdir()
}

#[test]
fn echo_passthrough_exits_zero() {
    let workspace = temp_workspace().unwrap();
    let output = run_runner(&[
        "--workspace-root",
        workspace.path().to_str().unwrap(),
        "--",
        "/bin/echo",
        "ok",
    ])
    .unwrap();
    assert!(
        output.status.success(),
        "runner exited with {:?}; stderr: {}",
        output.status.code(),
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(String::from_utf8_lossy(&output.stdout).trim(), "ok");
}

#[test]
fn write_inside_workspace_succeeds() {
    let workspace = temp_workspace().unwrap();
    let output = run_runner(&[
        "--workspace-root",
        workspace.path().to_str().unwrap(),
        "--",
        "/usr/bin/touch",
        "inside.txt",
    ])
    .unwrap();
    assert!(
        output.status.success(),
        "runner exited with {:?}; stderr: {}",
        output.status.code(),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(workspace.path().join("inside.txt").exists());
}

#[test]
fn write_outside_workspace_is_denied_by_seatbelt() {
    let workspace = temp_workspace().unwrap();
    let home = std::env::var("HOME").expect("HOME must be set");
    let outside_path = std::path::Path::new(&home).join("rb-sandbox-exec-outside-test");
    // A previous failed run must not leave a file that would mask the denial.
    let _ = std::fs::remove_file(&outside_path);

    let output = run_runner(&[
        "--workspace-root",
        workspace.path().to_str().unwrap(),
        "--",
        "/usr/bin/touch",
        outside_path.to_str().unwrap(),
    ])
    .unwrap();
    let exit_code = output.status.code().expect("exit code must be set");
    assert_ne!(
        exit_code, RUNNER_FAILURE_EXIT_CODE,
        "the runner must not report its own failure for a sandboxed denial"
    );
    assert_ne!(exit_code, 0, "the outside write must fail");
    assert!(
        !outside_path.exists(),
        "no file may be created outside the workspace root"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.to_lowercase().contains("not permitted")
            || stderr.to_lowercase().contains("operation not allowed")
            || stderr.to_lowercase().contains("permission denied"),
        "expected a Seatbelt denial on stderr, got: {stderr}"
    );
}

#[test]
fn read_outside_workspace_succeeds() {
    // Codex-standard workspace-write grants full-disk read, so files outside
    // the workspace root must be readable.
    let workspace = temp_workspace().unwrap();
    let outside = temp_workspace().unwrap();
    std::fs::write(outside.path().join("secret.txt"), "outside-read-ok").unwrap();

    let output = run_runner(&[
        "--workspace-root",
        workspace.path().to_str().unwrap(),
        "--",
        "/bin/cat",
        outside.path().join("secret.txt").to_str().unwrap(),
    ])
    .unwrap();
    assert!(
        output.status.success(),
        "reading outside the workspace must succeed; stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        String::from_utf8_lossy(&output.stdout).trim(),
        "outside-read-ok"
    );
}

#[test]
fn scratch_directory_write_succeeds() {
    // Codex-standard workspace-write keeps the system scratch directories
    // writable; the compiled profile covers them via the explicit entries,
    // not the process platform defaults.
    let workspace = temp_workspace().unwrap();
    let target = std::env::temp_dir().join(format!(
        "rb-sandbox-exec-scratch-write-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_file(&target);

    let output = run_runner(&[
        "--workspace-root",
        workspace.path().to_str().unwrap(),
        "--",
        "/usr/bin/touch",
        target.to_str().unwrap(),
    ])
    .unwrap();
    assert!(
        output.status.success(),
        "writing to the scratch directory must succeed; stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(target.exists(), "the scratch file must have been created");
    let _ = std::fs::remove_file(&target);
}

#[test]
fn workspace_git_metadata_stays_read_only() {
    // Codex-standard workspace-write protects top-level `.git` metadata of an
    // existing repository while ordinary workspace writes keep working.
    let workspace = temp_workspace().unwrap();
    std::fs::create_dir(workspace.path().join(".git")).unwrap();

    let denied = run_runner(&[
        "--workspace-root",
        workspace.path().to_str().unwrap(),
        "--",
        "/usr/bin/touch",
        workspace
            .path()
            .join(".git")
            .join("touched")
            .to_str()
            .unwrap(),
    ])
    .unwrap();
    let exit_code = denied.status.code().expect("exit code must be set");
    assert_ne!(
        exit_code, RUNNER_FAILURE_EXIT_CODE,
        "the runner must not report its own failure for a sandboxed denial"
    );
    assert_ne!(exit_code, 0, "the .git write must fail");
    assert!(
        !workspace.path().join(".git").join("touched").exists(),
        "no file may be created inside .git"
    );

    let allowed = run_runner(&[
        "--workspace-root",
        workspace.path().to_str().unwrap(),
        "--",
        "/usr/bin/touch",
        workspace.path().join("inside.txt").to_str().unwrap(),
    ])
    .unwrap();
    assert!(
        allowed.status.success(),
        "ordinary workspace writes must keep working; stderr: {}",
        String::from_utf8_lossy(&allowed.stderr)
    );
}

#[test]
fn network_access_is_denied() {
    let workspace = temp_workspace().unwrap();
    let output = run_runner(&[
        "--workspace-root",
        workspace.path().to_str().unwrap(),
        "--timeout-ms",
        "15000",
        "--",
        "/usr/bin/curl",
        "--max-time",
        "2",
        "https://example.com",
    ])
    .unwrap();
    let exit_code = output.status.code().expect("exit code must be set");
    assert_ne!(
        exit_code, RUNNER_FAILURE_EXIT_CODE,
        "the runner must not report its own failure for a sandboxed network denial"
    );
    assert_ne!(exit_code, 0, "network access must fail");
}

#[test]
fn timeout_kills_the_process_group() {
    let workspace = temp_workspace().unwrap();
    let started = Instant::now();
    let output = run_runner(&[
        "--workspace-root",
        workspace.path().to_str().unwrap(),
        "--timeout-ms",
        "300",
        "--",
        "/bin/sleep",
        "5",
    ])
    .unwrap();
    let elapsed = started.elapsed();
    assert_eq!(
        output.status.code(),
        Some(TIMEOUT_EXIT_CODE),
        "the runner must report the timeout with exit code {TIMEOUT_EXIT_CODE}"
    );
    assert!(
        elapsed < Duration::from_millis(4500),
        "the timeout must fire well before the command finishes on its own; took {elapsed:?}"
    );
    // The killed `sleep` must not linger.
    std::thread::sleep(Duration::from_millis(100));
    assert!(
        !std::process::Command::new("/usr/bin/pgrep")
            .args(["-f", "sleep 5$"])
            .output()
            .map(|output| output.status.success())
            .unwrap_or(false),
        "no orphaned `sleep 5` may survive the timeout kill"
    );
}

#[test]
fn print_profile_shows_compiled_policy_without_executing() {
    let workspace = temp_workspace().unwrap();
    let output = run_runner(&[
        "--workspace-root",
        workspace.path().to_str().unwrap(),
        "--print-profile",
        "--",
        // The command must only be echoed into the argv dump, never run: a
        // real execution would create this file.
        "/usr/bin/touch",
        "command-ran-proof.txt",
    ])
    .unwrap();
    assert!(
        output.status.success(),
        "print-profile must exit 0; stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("RB_SANDBOX_EXEC_PROFILE_BEGIN"));
    // Default-deny base policy must be present in the compiled SBPL.
    assert!(stdout.contains("(deny default)"));
    // Codex-standard workspace-write grants full-disk read in the compiled
    // profile and keeps the workspace root as a writable root parameter.
    assert!(stdout.contains("(allow file-read*)"));
    assert!(stdout.contains("WRITABLE_ROOT_0"));
    // IP network stays denied. The shared defaults intentionally keep a narrow
    // unix-socket allowance for syslog; no IP-based outbound or any inbound
    // allowance may appear.
    assert!(!stdout.contains("remote ip"));
    assert!(!stdout.contains("allow network-inbound"));
    assert!(!stdout.contains("(allow network-outbound)\n"));
    // Diagnostic mode must not execute the command.
    assert!(
        !workspace.path().join("command-ran-proof.txt").exists(),
        "--print-profile must never execute the command"
    );
}

#[test]
fn command_exit_codes_are_forwarded() {
    let workspace = temp_workspace().unwrap();
    let output = run_runner(&[
        "--workspace-root",
        workspace.path().to_str().unwrap(),
        "--",
        "/bin/sh",
        "-c",
        "exit 126",
    ])
    .unwrap();
    assert_eq!(
        output.status.code(),
        Some(126),
        "a command's own exit code must be forwarded, not mapped to the runner failure code"
    );
}

#[test]
fn environment_is_filtered_and_explicit_sets_pass_through() {
    let workspace = temp_workspace().unwrap();
    let output = Command::new(runner())
        .args([
            "--workspace-root",
            workspace.path().to_str().unwrap(),
            "--set",
            "RB_SANDBOX_EXEC_TEST_MARKER=from-caller",
            "--",
            "/usr/bin/env",
        ])
        .env("RB_SANDBOX_EXEC_UNPRESERVED", "must-not-pass")
        // Harmless DYLD_* value: unlike DYLD_INSERT_LIBRARIES it cannot kill
        // the runner itself in the macOS loader, so the filter (not the
        // loader) is what keeps it away from the sandboxed command.
        .env("DYLD_FRAMEWORK_PATH", "/nonexistent-rb-test")
        .output()
        .expect("runner binary must spawn");
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("RB_SANDBOX_EXEC_TEST_MARKER=from-caller"),
        "explicit --set values must be forwarded; env output:\n{stdout}"
    );
    assert!(stdout.contains("PATH="), "PATH must be preserved");
    assert!(stdout.contains("HOME="), "HOME must be preserved");
    assert!(stdout.contains("TMPDIR="), "TMPDIR must be preserved");
    assert!(
        !stdout.contains("RB_SANDBOX_EXEC_UNPRESERVED"),
        "non-allowlisted caller variables must be dropped"
    );
    assert!(
        !stdout.contains("DYLD_FRAMEWORK_PATH"),
        "DYLD_* variables must always be dropped"
    );
}

#[test]
fn missing_workspace_root_fails_closed_without_running_the_command() {
    let output = run_runner(&[
        "--workspace-root",
        "/nonexistent/rb-sandbox-exec-root",
        "--",
        "/bin/echo",
        "must-not-run",
    ])
    .unwrap();
    assert_eq!(output.status.code(), Some(RUNNER_FAILURE_EXIT_CODE));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.starts_with("RB_SANDBOX_UNAVAILABLE:"),
        "expected the RB_SANDBOX_UNAVAILABLE marker, got: {stderr}"
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        !stdout.contains("must-not-run"),
        "the command must never run when the runner fails"
    );
}

#[test]
fn unsupported_network_mode_is_rejected() {
    let workspace = temp_workspace().unwrap();
    let output = run_runner(&[
        "--workspace-root",
        workspace.path().to_str().unwrap(),
        "--network",
        "enabled",
        "--",
        "/bin/echo",
        "must-not-run",
    ])
    .unwrap();
    assert_eq!(output.status.code(), Some(RUNNER_FAILURE_EXIT_CODE));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.starts_with("RB_SANDBOX_UNAVAILABLE:"));
    assert!(stderr.contains("--network"));
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(!stdout.contains("must-not-run"));
}

#[test]
fn missing_command_separator_is_rejected() {
    let workspace = temp_workspace().unwrap();
    let output = run_runner(&[
        "--workspace-root",
        workspace.path().to_str().unwrap(),
        "/bin/echo",
        "must-not-run",
    ])
    .unwrap();
    assert_eq!(output.status.code(), Some(RUNNER_FAILURE_EXIT_CODE));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.starts_with("RB_SANDBOX_UNAVAILABLE:"));
}

#[test]
fn network_mode_deny_is_accepted() {
    let workspace = temp_workspace().unwrap();
    let output = run_runner(&[
        "--workspace-root",
        workspace.path().to_str().unwrap(),
        "--network",
        "deny",
        "--",
        "/bin/echo",
        "ok",
    ])
    .unwrap();
    assert!(
        output.status.success(),
        "explicit --network deny must be accepted; stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(String::from_utf8_lossy(&output.stdout).trim(), "ok");
}

#[test]
fn timeout_and_set_flags_parse_together() {
    // Regression: `--timeout-ms` and `--set` each consumed one extra argument,
    // so any flag following either of them was misparsed as an unknown flag.
    // The OMP wiring always emits `--timeout-ms` together with `--set`.
    let workspace = temp_workspace().unwrap();
    let output = run_runner(&[
        "--workspace-root",
        workspace.path().to_str().unwrap(),
        "--timeout-ms",
        "15000",
        "--set",
        "RB_SANDBOX_EXEC_TEST_MARKER=combined",
        "--",
        "/usr/bin/env",
    ])
    .unwrap();
    assert!(
        output.status.success(),
        "runner exited with {:?}; stderr: {}",
        output.status.code(),
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("RB_SANDBOX_EXEC_TEST_MARKER=combined"),
        "the explicit --set value must pass through alongside --timeout-ms; env output:\n{stdout}"
    );
}
