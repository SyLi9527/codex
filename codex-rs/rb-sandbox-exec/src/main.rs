//! `rb-sandbox-exec` command line entry point.
//!
//! Usage:
//! ```text
//! rb-sandbox-exec --workspace-root <dir> [--network deny] [--timeout-ms <n>]
//!                 [--print-profile] [--set KEY=VALUE]... -- <command> [args...]
//! ```
//!
//! Runner-own failures (argument errors, unusable workspace root, profile
//! compilation errors, a missing `sandbox-exec`, or spawn errors) print a
//! single `RB_SANDBOX_UNAVAILABLE:<reason>` line to stderr and exit with 250.
//! The command is never executed without a sandbox.
//!
//! If the runner itself receives `SIGINT`/`SIGTERM`/`SIGHUP`, it kills the
//! sandboxed command's whole process group before exiting `128 + signum`, so
//! a supervisor teardown never leaves orphaned grandchildren behind.

use std::path::PathBuf;
use std::sync::atomic::AtomicI32;
use std::sync::atomic::Ordering;
use std::time::Duration;
use std::time::Instant;

use codex_protocol::protocol::SandboxPolicy;
use rb_sandbox_exec::NetworkMode;
use rb_sandbox_exec::RUNNER_FAILURE_EXIT_CODE;
use rb_sandbox_exec::RUNNER_FAILURE_MARKER;
use rb_sandbox_exec::SUPPORTED_NETWORK_MODES;
use rb_sandbox_exec::SandboxExecOptions;
use rb_sandbox_exec::TIMEOUT_EXIT_CODE;
use rb_sandbox_exec::parse_sandbox_policy;

/// Poll interval while waiting for the sandboxed command.
const POLL_INTERVAL: Duration = Duration::from_millis(5);

/// Process group id of the live sandboxed child (its pid, since it leads its
/// own group); `0` while no child is running. Written on spawn/reap and read
/// from the signal handler.
#[cfg(unix)]
static SANDBOXED_CHILD_PGID: AtomicI32 = AtomicI32::new(0);

/// Fatal-signal disposition: take the sandboxed child's whole process group
/// down with us, then exit `128 + signum` like a shell would. Only
/// async-signal-safe calls (`kill`, `_exit`) happen here.
#[cfg(unix)]
extern "C" fn kill_child_group_and_exit(signum: libc::c_int) {
    let pgid = SANDBOXED_CHILD_PGID.load(Ordering::SeqCst);
    if pgid > 0 {
        // A negative pid targets the group; ESRCH (group already gone) is
        // fine and intentionally ignored.
        unsafe {
            libc::kill(-pgid, libc::SIGKILL);
        }
    }
    unsafe { libc::_exit(128 + signum) };
}

/// Install the fatal-signal disposition for the signals a supervisor or an
/// interactive session sends on teardown. Registered before any child exists;
/// with no live child the handler only records the conventional exit code.
#[cfg(unix)]
fn install_fatal_signal_forwarding() {
    unsafe {
        let mut action: libc::sigaction = std::mem::zeroed();
        action.sa_sigaction = kill_child_group_and_exit as extern "C" fn(libc::c_int) as usize;
        action.sa_flags = libc::SA_RESTART;
        for signal in [libc::SIGINT, libc::SIGTERM, libc::SIGHUP] {
            libc::sigaction(signal, &action, std::ptr::null_mut());
        }
    }
}

#[cfg(not(unix))]
fn install_fatal_signal_forwarding() {}

struct Cli {
    workspace_root: String,
    timeout_ms: Option<u64>,
    print_profile: bool,
    sets: Vec<(String, String)>,
    network: NetworkMode,
    sandbox_policy: Option<SandboxPolicy>,
    command: Vec<String>,
}

fn main() {
    install_fatal_signal_forwarding();
    let raw_args: Vec<String> = std::env::args().skip(1).collect();
    let cli = match parse_cli(&raw_args) {
        Ok(cli) => cli,
        Err(reason) => fail_unavailable(&format!("invalid-arguments: {reason}")),
    };
    let Cli {
        workspace_root,
        timeout_ms,
        print_profile,
        sets,
        network,
        sandbox_policy,
        command,
    } = cli;
    let options = SandboxExecOptions {
        workspace_root: PathBuf::from(workspace_root),
        timeout_ms,
        extra_env: sets,
        network_mode: network,
        sandbox_policy,
    };
    let plan = match rb_sandbox_exec::build_sandbox_exec_plan(&options, &command) {
        Ok(plan) => plan,
        Err(reason) => fail_unavailable(&reason),
    };
    if print_profile {
        print_plan(&plan);
        std::process::exit(0);
    }
    if !std::path::Path::new(&plan.program).exists() {
        fail_unavailable(&format!("sandbox-exec-missing: {} not found", plan.program));
    }
    let timeout = timeout_ms.map(Duration::from_millis);
    let exit_code = run_plan(&plan, timeout);
    std::process::exit(exit_code);
}

fn parse_cli(raw_args: &[String]) -> Result<Cli, String> {
    let separator_index = raw_args
        .iter()
        .position(|arg| arg == "--")
        .ok_or_else(|| "missing `--` separator before the command".to_string())?;
    let flags = &raw_args[..separator_index];
    let command: Vec<String> = raw_args[separator_index + 1..].to_vec();
    if command.is_empty() {
        return Err("missing command after `--`".to_string());
    }

    let mut workspace_root: Option<String> = None;
    let mut network: Option<NetworkMode> = None;
    let mut sandbox_policy_json: Option<String> = None;
    let mut timeout_ms: Option<u64> = None;
    let mut print_profile = false;
    let mut sets: Vec<(String, String)> = Vec::new();

    let mut index = 0;
    while index < flags.len() {
        let flag = flags[index].as_str();
        match flag {
            "--workspace-root" => {
                let value = next_flag_value(flags, &mut index, flag)?.to_string();
                replace_once(&mut workspace_root, value, flag)?;
            }
            "--network" => {
                let value = next_flag_value(flags, &mut index, flag)?.to_string();
                let mode = NetworkMode::parse(&value).ok_or_else(|| {
                    format!("--network only supports {SUPPORTED_NETWORK_MODES:?}, got `{value}`")
                })?;
                replace_once(&mut network, mode, flag)?;
            }
            "--sandbox-policy" => {
                let value = next_flag_value(flags, &mut index, flag)?.to_string();
                replace_once(&mut sandbox_policy_json, value, flag)?;
            }
            "--timeout-ms" => {
                let value = next_flag_value(flags, &mut index, flag)?;
                let parsed = value
                    .parse::<u64>()
                    .map_err(|err| format!("invalid value for {flag}: `{value}` ({err})"))?;
                if timeout_ms.is_some() {
                    return Err(format!("duplicate flag {flag}"));
                }
                timeout_ms = Some(parsed);
            }
            "--print-profile" => {
                if print_profile {
                    return Err(format!("duplicate flag {flag}"));
                }
                print_profile = true;
                index += 1;
            }
            "--set" => {
                let value = next_flag_value(flags, &mut index, flag)?;
                let Some((key, assigned)) = value.split_once('=') else {
                    return Err(format!(
                        "invalid value for {flag}: `{value}` (expected KEY=VALUE)"
                    ));
                };
                if key.is_empty() {
                    return Err(format!("invalid value for {flag}: `{value}` (empty key)"));
                }
                sets.retain(|(existing_key, _)| existing_key != key);
                sets.push((key.to_string(), assigned.to_string()));
            }
            other => return Err(format!("unknown argument `{other}`")),
        }
    }

    let workspace_root =
        workspace_root.ok_or_else(|| "missing required flag --workspace-root <dir>".to_string())?;
    if sandbox_policy_json.is_some() && network.is_some() {
        // The policy fully determines network access; an explicit --network
        // alongside it would be ambiguous.
        return Err(
            "--sandbox-policy and --network are mutually exclusive; the policy's              `network_access` field determines network access"
                .to_string(),
        );
    }
    Ok(Cli {
        workspace_root,
        timeout_ms,
        print_profile,
        sets,
        network: network.unwrap_or(NetworkMode::Deny),
        sandbox_policy: sandbox_policy_json
            .as_deref()
            .map(parse_sandbox_policy)
            .transpose()?,
        command,
    })
}

fn next_flag_value<'a>(
    flags: &'a [String],
    index: &mut usize,
    flag: &str,
) -> Result<&'a String, String> {
    let value = flags
        .get(*index + 1)
        .ok_or_else(|| format!("missing value for {flag}"))?;
    *index += 2;
    Ok(value)
}

fn replace_once<T>(slot: &mut Option<T>, value: T, flag: &str) -> Result<(), String> {
    if slot.is_some() {
        return Err(format!("duplicate flag {flag}"));
    }
    *slot = Some(value);
    Ok(())
}

fn print_plan(plan: &rb_sandbox_exec::SandboxExecPlan) {
    println!("RB_SANDBOX_EXEC_PROGRAM {}", plan.program);
    println!("RB_SANDBOX_EXEC_CWD {}", plan.cwd.display());
    if let Some(profile_index) = plan.args.iter().position(|arg| arg == "-p")
        && let Some(profile) = plan.args.get(profile_index + 1)
    {
        println!("RB_SANDBOX_EXEC_PROFILE_BEGIN");
        println!("{profile}");
        println!("RB_SANDBOX_EXEC_PROFILE_END");
    }
    println!("RB_SANDBOX_EXEC_ARGV_BEGIN");
    for argument in std::iter::once(&plan.program).chain(plan.args.iter()) {
        println!("{argument}");
    }
    println!("RB_SANDBOX_EXEC_ARGV_END");
}

fn run_plan(plan: &rb_sandbox_exec::SandboxExecPlan, timeout: Option<Duration>) -> i32 {
    let mut command = std::process::Command::new(&plan.program);
    command.args(&plan.args).current_dir(&plan.cwd);
    command.env_clear();
    for (key, value) in &plan.environment {
        command.env(key, value);
    }
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        // Own process group so a timeout can kill the whole tree, including
        // grandchildren spawned by the sandboxed command.
        command.process_group(0);
    }

    let mut child = match command.spawn() {
        Ok(child) => child,
        Err(err) => fail_unavailable(&format!("spawn-failed: {err}")),
    };
    #[cfg(unix)]
    {
        // The child leads its own process group, so its pid is the pgid the
        // fatal-signal handler uses for the group kill.
        SANDBOXED_CHILD_PGID.store(child.id() as libc::pid_t, Ordering::SeqCst);
    }

    let started = Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                #[cfg(unix)]
                SANDBOXED_CHILD_PGID.store(0, Ordering::SeqCst);
                return exit_code_for_status(status);
            }
            Ok(None) => {}
            Err(err) => fail_unavailable(&format!("wait-failed: {err}")),
        }
        if let Some(deadline) = timeout
            && started.elapsed() >= deadline
        {
            kill_process_group(&mut child);
            // Reap the child so no zombie remains; the group kill already
            // decided the outcome.
            let _ = child.wait();
            #[cfg(unix)]
            SANDBOXED_CHILD_PGID.store(0, Ordering::SeqCst);
            return TIMEOUT_EXIT_CODE;
        }
        std::thread::sleep(POLL_INTERVAL);
    }
}

fn exit_code_for_status(status: std::process::ExitStatus) -> i32 {
    if let Some(code) = status.code() {
        return code;
    }
    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt;
        if let Some(signal) = status.signal() {
            // Follow shell convention for signal deaths of the command.
            return 128 + signal;
        }
    }
    255
}

fn kill_process_group(child: &mut std::process::Child) {
    #[cfg(unix)]
    {
        let negative_process_group_id: libc::pid_t = -(child.id() as libc::pid_t);
        // SAFETY: `kill` sends SIGKILL to the process group led by the child.
        // A negative pid targets the group; ESRCH (group already gone) is fine
        // and its return value is intentionally ignored.
        unsafe {
            libc::kill(negative_process_group_id, libc::SIGKILL);
        }
    }
    #[cfg(not(unix))]
    {
        let _ = child.kill();
    }
}

/// Single failure funnel: one stderr line, exit 250, never run the command.
fn fail_unavailable(reason: &str) -> ! {
    let reason = reason.replace(['\n', '\r'], " ");
    eprintln!("{RUNNER_FAILURE_MARKER}:{reason}");
    std::process::exit(RUNNER_FAILURE_EXIT_CODE);
}
