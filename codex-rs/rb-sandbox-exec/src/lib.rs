//! `rb-sandbox-exec` is a thin runner shell that executes a single command
//! inside a macOS Seatbelt sandbox on behalf of ResearchBuddy's managed
//! runtime.
//!
//! The SBPL profile is always compiled by the shared `codex-sandboxing`
//! Seatbelt implementation; this crate never hand-writes policy text. Runner
//! level failures (unusable workspace root, profile compilation errors, a
//! missing `sandbox-exec`, or spawn errors) are reported as a single
//! `RB_SANDBOX_UNAVAILABLE:<reason>` line on stderr with exit code
//! [`RUNNER_FAILURE_EXIT_CODE`], and the command is never executed without a
//! sandbox.
//!
//! The same profile construction backs `--print-profile` diagnostics and real
//! execution, so a successful `--print-profile` run proves the exact policy
//! that a subsequent execution will use.

use std::path::Path;
use std::path::PathBuf;

use codex_protocol::permissions::FileSystemAccessMode;
use codex_protocol::permissions::FileSystemPath;
use codex_protocol::permissions::FileSystemSandboxEntry;
use codex_protocol::permissions::FileSystemSandboxPolicy;
use codex_protocol::permissions::FileSystemSpecialPath;

/// Exit code used exclusively for runner-own failures. A sandboxed command
/// that fails on its own forwards its real exit code instead.
pub const RUNNER_FAILURE_EXIT_CODE: i32 = 250;
/// Exit code used when the runner killed the sandboxed command because it
/// exceeded `--timeout-ms` (matching the conventional `timeout(1)` code).
pub const TIMEOUT_EXIT_CODE: i32 = 124;
/// Stderr marker prefix for runner-own failures: `RB_SANDBOX_UNAVAILABLE:<reason>`.
pub const RUNNER_FAILURE_MARKER: &str = "RB_SANDBOX_UNAVAILABLE";
/// The only network mode supported in S1.
pub const SUPPORTED_NETWORK_MODE: &str = "deny";

/// Environment variables copied from the caller into the sandboxed process.
const PRESERVED_ENV_KEYS: &[&str] = &["PATH", "HOME", "TMPDIR", "LANG", "SHELL"];
/// Environment variable prefixes copied from the caller (locale settings).
const PRESERVED_ENV_KEY_PREFIXES: &[&str] = &["LC_"];
/// Environment variable prefixes that are always stripped, including from
/// explicit `--set KEY=VALUE` overrides.
const FORBIDDEN_ENV_KEY_PREFIXES: &[&str] = &["DYLD_"];

/// Runner inputs that do not depend on the command being executed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SandboxExecOptions {
    /// Writable workspace root. It becomes the only additional writable root
    /// in the filesystem policy and the working directory of the sandboxed
    /// command. It is canonicalized before use.
    pub workspace_root: PathBuf,
    /// Optional wall-clock limit after which the runner kills the command's
    /// whole process group and exits with [`TIMEOUT_EXIT_CODE`].
    pub timeout_ms: Option<u64>,
    /// Explicit `--set KEY=VALUE` overrides applied after the preserved
    /// environment. `DYLD_*` keys are rejected here as well.
    pub extra_env: Vec<(String, String)>,
}

/// Everything the runner needs to spawn the sandboxed command.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SandboxExecPlan {
    /// Absolute path to `/usr/bin/sandbox-exec` (the shared Seatbelt constant).
    pub program: String,
    /// Argument vector for `program`, including the compiled SBPL profile, the
    /// `-D` parameter definitions, the `--` separator, and the command argv.
    pub args: Vec<String>,
    /// Canonicalized workspace root, used as the process working directory.
    pub cwd: PathBuf,
    /// Filtered environment passed to the sandboxed process.
    pub environment: Vec<(String, String)>,
}

/// Canonicalizes the workspace root so the policy never contains symlinked
/// path components (top-level aliases such as `/tmp` are normalized away).
pub fn canonical_workspace_root(workspace_root: &Path) -> Result<PathBuf, String> {
    std::fs::canonicalize(workspace_root).map_err(|err| {
        format!(
            "workspace root {} is not accessible: {err}",
            workspace_root.display()
        )
    })
}

/// Builds the restricted filesystem policy for the runner.
///
/// Base is a restricted minimal-read policy: the `Minimal` read marker keeps
/// the shared platform defaults in the compiled profile, which grant standard
/// system read access (enough to exec `/bin`, `/usr/bin`, ... plus loader
/// paths) and the explicit system scratch-directory writes
/// (`/tmp`, `/private/tmp`, `/var/tmp`, `/private/var/tmp`). On top of that:
/// - a `Write` entry for the canonicalized workspace root, which the shared
///   Seatbelt compiler turns into the only additional writable root.
///
/// This mirrors the exec-server helper pattern
/// (`add_helper_runtime_permissions`): the marker is only effective while the
/// policy has no full-disk read grant, so no broad `Root` read entry is added.
pub fn build_file_system_policy(
    canonical_workspace_root: &Path,
) -> Result<FileSystemSandboxPolicy, String> {
    let root =
        codex_utils_absolute_path::AbsolutePathBuf::from_absolute_path(canonical_workspace_root)
            .map_err(|err| {
                format!(
                    "workspace root {} is not absolute: {err}",
                    canonical_workspace_root.display()
                )
            })?;
    let entries = vec![
        // Marker entry: keeps the shared platform defaults in the compiled
        // profile (system reads plus explicit system scratch writes).
        FileSystemSandboxEntry::new(
            FileSystemPath::Special {
                value: FileSystemSpecialPath::Minimal,
            },
            FileSystemAccessMode::Read,
        ),
        FileSystemSandboxEntry::new(FileSystemPath::from(root), FileSystemAccessMode::Write),
    ];
    Ok(FileSystemSandboxPolicy::restricted(entries))
}

#[cfg(target_os = "macos")]
/// Compiles the sandbox plan for `command` under `options`.
///
/// Uses the shared `create_seatbelt_command_args` API verbatim: its returned
/// argument vector (profile via `-p`, parameters via `-D KEY=VALUE`, then
/// `--` and the command argv) is passed to `/usr/bin/sandbox-exec` unchanged.
pub fn build_sandbox_exec_plan(
    options: &SandboxExecOptions,
    command: &[String],
) -> Result<SandboxExecPlan, String> {
    if command.is_empty() {
        return Err("missing command after `--`".to_string());
    }
    let cwd = canonical_workspace_root(&options.workspace_root)?;
    let file_system_sandbox_policy = build_file_system_policy(&cwd)?;
    let seatbelt_args = codex_sandboxing::seatbelt::create_seatbelt_command_args(
        codex_sandboxing::seatbelt::CreateSeatbeltCommandArgsParams {
            command: command.to_vec(),
            file_system_sandbox_policy: &file_system_sandbox_policy,
            // S1 only supports network deny; `Restricted` keeps the compiled
            // profile without any network allowances.
            network_sandbox_policy: codex_protocol::permissions::NetworkSandboxPolicy::Restricted,
            sandbox_policy_cwd: cwd.as_path(),
            enforce_managed_network: false,
            managed_network: None,
            environment_id: None,
            network: None,
            extra_allow_unix_sockets: &[],
        },
    )?;
    Ok(SandboxExecPlan {
        program: codex_sandboxing::seatbelt::MACOS_PATH_TO_SEATBELT_EXECUTABLE.to_string(),
        args: seatbelt_args,
        cwd,
        environment: filtered_environment(&options.extra_env),
    })
}

#[cfg(not(target_os = "macos"))]
/// Seatbelt only exists on macOS; keep the API total so the crate compiles on
/// other platforms and the binary fails closed.
pub fn build_sandbox_exec_plan(
    _options: &SandboxExecOptions,
    command: &[String],
) -> Result<SandboxExecPlan, String> {
    if command.is_empty() {
        return Err("missing command after `--`".to_string());
    }
    Err("seatbelt sandbox is only available on macOS".to_string())
}

/// Filters the caller environment for the sandboxed process: keeps the
/// preserved allowlist, applies explicit overrides last, and always drops
/// `DYLD_*` keys.
pub fn filtered_environment(extra_env: &[(String, String)]) -> Vec<(String, String)> {
    filtered_environment_from(std::env::vars_os(), extra_env)
}

/// Pure variant of [`filtered_environment`] that takes the parent environment
/// as an argument so it can be tested without mutating process state.
pub fn filtered_environment_from<I, K, V>(
    parent_vars: I,
    extra_env: &[(String, String)],
) -> Vec<(String, String)>
where
    I: IntoIterator<Item = (K, V)>,
    K: AsRef<std::ffi::OsStr>,
    V: AsRef<std::ffi::OsStr>,
{
    let mut environment: Vec<(String, String)> = Vec::new();
    for (key, value) in parent_vars {
        let (Some(key), Some(value)) = (key.as_ref().to_str(), value.as_ref().to_str()) else {
            // Fail closed: drop non-UTF-8 environment entries.
            continue;
        };
        if !parent_env_key_is_preserved(key) {
            continue;
        }
        push_unique(&mut environment, key.to_string(), value.to_string());
    }
    for (key, value) in extra_env {
        // Explicit overrides may introduce arbitrary keys, but `DYLD_*` is
        // always stripped, even here.
        if env_key_is_forbidden(key) {
            continue;
        }
        // Last `--set` wins for duplicate keys.
        environment.retain(|(existing_key, _)| existing_key != key);
        environment.push((key.clone(), value.clone()));
    }
    environment
}

fn parent_env_key_is_preserved(key: &str) -> bool {
    !env_key_is_forbidden(key)
        && (PRESERVED_ENV_KEYS.contains(&key)
            || PRESERVED_ENV_KEY_PREFIXES
                .iter()
                .any(|prefix| key.starts_with(prefix)))
}

fn env_key_is_forbidden(key: &str) -> bool {
    FORBIDDEN_ENV_KEY_PREFIXES
        .iter()
        .any(|prefix| key.starts_with(prefix))
}

fn push_unique(environment: &mut Vec<(String, String)>, key: String, value: String) {
    if !environment
        .iter()
        .any(|(existing_key, _)| existing_key == &key)
    {
        environment.push((key, value));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parent_env() -> Vec<(String, String)> {
        vec![
            ("PATH".to_string(), "/usr/bin:/bin".to_string()),
            ("HOME".to_string(), "/Users/example".to_string()),
            ("TMPDIR".to_string(), "/tmp".to_string()),
            ("LANG".to_string(), "en_US.UTF-8".to_string()),
            ("SHELL".to_string(), "/bin/zsh".to_string()),
            ("LC_ALL".to_string(), "en_US.UTF-8".to_string()),
            ("RANDOM_CALLER_VAR".to_string(), "dropped".to_string()),
            (
                "DYLD_INSERT_LIBRARIES".to_string(),
                "/tmp/evil.dylib".to_string(),
            ),
        ]
    }

    #[test]
    fn env_filter_keeps_allowlist_and_drops_the_rest() {
        let environment = filtered_environment_from(parent_env(), &[]);
        assert!(environment.contains(&("PATH".to_string(), "/usr/bin:/bin".to_string())));
        assert!(environment.contains(&("HOME".to_string(), "/Users/example".to_string())));
        assert!(environment.contains(&("TMPDIR".to_string(), "/tmp".to_string())));
        assert!(environment.contains(&("LANG".to_string(), "en_US.UTF-8".to_string())));
        assert!(environment.contains(&("SHELL".to_string(), "/bin/zsh".to_string())));
        assert!(environment.contains(&("LC_ALL".to_string(), "en_US.UTF-8".to_string())));
        assert!(
            !environment
                .iter()
                .any(|(key, _)| key == "RANDOM_CALLER_VAR")
        );
        assert!(!environment.iter().any(|(key, _)| key.starts_with("DYLD_")));
    }

    #[test]
    fn env_filter_applies_explicit_sets_and_still_drops_dyld() {
        let extra_env = vec![
            ("RB_TEST_MARKER".to_string(), "value".to_string()),
            ("DYLD_LIBRARY_PATH".to_string(), "/tmp/evil".to_string()),
            ("PATH".to_string(), "/custom/path".to_string()),
        ];
        let environment = filtered_environment_from(parent_env(), &extra_env);
        assert!(environment.contains(&("RB_TEST_MARKER".to_string(), "value".to_string())));
        assert!(!environment.iter().any(|(key, _)| key.starts_with("DYLD_")));
        // Explicit override wins over the inherited value.
        assert!(environment.contains(&("PATH".to_string(), "/custom/path".to_string())));
    }

    #[test]
    fn env_filter_last_set_wins() {
        let extra_env = vec![
            ("RB_TEST_MARKER".to_string(), "first".to_string()),
            ("RB_TEST_MARKER".to_string(), "second".to_string()),
        ];
        let environment = filtered_environment_from(Vec::<(String, String)>::new(), &extra_env);
        assert_eq!(
            environment,
            vec![("RB_TEST_MARKER".to_string(), "second".to_string())]
        );
    }

    #[test]
    fn file_system_policy_grants_workspace_write_and_keeps_platform_defaults() {
        let workspace = tempfile::tempdir().unwrap();
        let canonical_root = canonical_workspace_root(workspace.path()).unwrap();
        let policy = build_file_system_policy(&canonical_root).unwrap();
        assert!(matches!(
            policy.kind,
            codex_protocol::permissions::FileSystemSandboxKind::Restricted
        ));
        // The minimal-read marker keeps the shared platform defaults (system
        // reads plus the explicit system scratch-directory writes) enabled.
        assert!(policy.include_platform_defaults());
        assert!(!policy.has_full_disk_read_access());
        assert!(!policy.has_full_disk_write_access());
        let writable_roots = policy.get_writable_roots_with_cwd(&canonical_root);
        assert!(
            writable_roots
                .iter()
                .any(|root| root.root.as_path() == canonical_root),
            "workspace root must appear among writable roots"
        );
        assert!(
            policy.can_write_path_with_cwd(&canonical_root.join("inside.txt"), &canonical_root),
            "writes inside the workspace root must be allowed"
        );
        assert!(
            policy.can_read_path_with_cwd(&canonical_root.join("inside.txt"), &canonical_root),
            "reads inside the workspace root must be allowed"
        );
        assert!(
            !policy.can_write_path_with_cwd(Path::new("/etc/passwd"), &canonical_root),
            "writes outside the workspace root must be denied"
        );
        assert!(
            !policy.can_read_path_with_cwd(Path::new("/etc/passwd"), &canonical_root),
            "policy-level reads outside the workspace root must be denied; \
             system reads come from the compiled platform defaults instead"
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn plan_uses_shared_seatbelt_args_and_filtered_env() {
        let workspace = tempfile::tempdir().unwrap();
        let options = SandboxExecOptions {
            workspace_root: workspace.path().to_path_buf(),
            timeout_ms: None,
            extra_env: vec![("RB_TEST_MARKER".to_string(), "value".to_string())],
        };
        let plan = build_sandbox_exec_plan(&options, &["/bin/echo".to_string(), "ok".to_string()])
            .unwrap();
        assert_eq!(
            plan.program,
            codex_sandboxing::seatbelt::MACOS_PATH_TO_SEATBELT_EXECUTABLE
        );
        assert_eq!(plan.args[0], "-p");
        assert!(plan.args[1].contains("(deny default)"));
        assert_eq!(plan.args.last().unwrap(), "ok");
        let separator_index = plan.args.iter().position(|arg| arg == "--").unwrap();
        assert_eq!(
            &plan.args[separator_index + 1..separator_index + 3],
            ["/bin/echo", "ok"]
        );
        assert_eq!(
            plan.cwd,
            canonical_workspace_root(workspace.path()).unwrap()
        );
        assert!(
            plan.environment
                .iter()
                .any(|(key, value)| key == "RB_TEST_MARKER" && value == "value")
        );
    }

    #[test]
    fn plan_requires_a_command() {
        let options = SandboxExecOptions {
            workspace_root: PathBuf::from("/tmp"),
            timeout_ms: None,
            extra_env: vec![],
        };
        let error = build_sandbox_exec_plan(&options, &[]).unwrap_err();
        assert!(error.contains("missing command"));
    }

    #[test]
    fn plan_fails_closed_for_missing_workspace_root() {
        let options = SandboxExecOptions {
            workspace_root: PathBuf::from("/nonexistent/rb-sandbox-exec-root"),
            timeout_ms: None,
            extra_env: vec![],
        };
        let error = build_sandbox_exec_plan(&options, &["/bin/echo".to_string()]).unwrap_err();
        assert!(error.contains("not accessible"));
    }
}
