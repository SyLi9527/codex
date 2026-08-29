use serde::Deserialize;
use std::collections::BTreeSet;
use std::fmt;

const MAX_PROTOCOL_BYTES: usize = 65_536;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RbOuterOmpVerifiedWorld {
    pub pid: u32,
    pub actors: BTreeSet<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RbOuterOmpWorldVerificationError {
    Oversized,
    InvalidUtf8,
    UnexpectedLine {
        index: usize,
        line: String,
    },
    InvalidWorld {
        actor: &'static str,
        message: String,
    },
    InvalidPid,
    SelfExecChangedPid {
        parent: u32,
        self_exec: u32,
    },
}

impl fmt::Display for RbOuterOmpWorldVerificationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Oversized => f.write_str("RB outer OMP world protocol exceeds 65536 bytes"),
            Self::InvalidUtf8 => f.write_str("RB outer OMP world protocol is not UTF-8"),
            Self::UnexpectedLine { index, line } => {
                write!(f, "unexpected RB outer OMP world line {index}: {line}")
            }
            Self::InvalidWorld { actor, message } => {
                write!(f, "invalid RB outer OMP {actor} world result: {message}")
            }
            Self::InvalidPid => f.write_str("invalid RB outer OMP bootstrap pid"),
            Self::SelfExecChangedPid { parent, self_exec } => write!(
                f,
                "RB outer OMP self-exec changed pid: parent {parent}, self-exec {self_exec}"
            ),
        }
    }
}

impl std::error::Error for RbOuterOmpWorldVerificationError {}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct WorldEffects {
    runtime_read: bool,
    session_write: bool,
    workspace_read: bool,
    workspace_write: bool,
    home_read: bool,
    ssh_read: bool,
    keychain_read: bool,
    rb_state_read: bool,
    sibling_read: bool,
    shared_tmp_write: bool,
    tcp4: bool,
    tcp6: bool,
    udp: bool,
    dns: bool,
    named_unix: bool,
    shell: bool,
    mach_securityd: bool,
}

impl WorldEffects {
    fn validate(&self, actor: &'static str) -> Result<(), RbOuterOmpWorldVerificationError> {
        if !self.runtime_read || !self.session_write {
            return Err(RbOuterOmpWorldVerificationError::InvalidWorld {
                actor,
                message: "runtimeRead and sessionWrite must both be true".to_string(),
            });
        }
        let forbidden = [
            ("workspaceRead", self.workspace_read),
            ("workspaceWrite", self.workspace_write),
            ("homeRead", self.home_read),
            ("sshRead", self.ssh_read),
            ("keychainRead", self.keychain_read),
            ("rbStateRead", self.rb_state_read),
            ("siblingRead", self.sibling_read),
            ("sharedTmpWrite", self.shared_tmp_write),
            ("tcp4", self.tcp4),
            ("tcp6", self.tcp6),
            ("udp", self.udp),
            ("dns", self.dns),
            ("namedUnix", self.named_unix),
            ("shell", self.shell),
            ("machSecurityd", self.mach_securityd),
        ];
        if let Some((field, _)) = forbidden.into_iter().find(|(_, value)| *value) {
            return Err(RbOuterOmpWorldVerificationError::InvalidWorld {
                actor,
                message: format!("forbidden effect {field} was observed"),
            });
        }
        Ok(())
    }
}

/// Verifies the exact LG-5 world-effect marker protocol.
///
/// Missing, duplicate, extra, reordered and malformed records are rejected.
/// Both positive effects are mandatory, so a loader/apply failure cannot be
/// misclassified as a successful denial.
pub fn verify_rb_outer_omp_world_protocol(
    input: &[u8],
) -> Result<RbOuterOmpVerifiedWorld, RbOuterOmpWorldVerificationError> {
    if input.len() > MAX_PROTOCOL_BYTES {
        return Err(RbOuterOmpWorldVerificationError::Oversized);
    }
    let text =
        std::str::from_utf8(input).map_err(|_| RbOuterOmpWorldVerificationError::InvalidUtf8)?;
    let lines: Vec<&str> = text.lines().collect();
    if lines.len() != 12 {
        return Err(unexpected(lines.len(), text));
    }

    exact(&lines, 0, "LAUNCH_FD_INVENTORY|0,1,2,20")?;
    let parent_pid = parse_bootstrap(&lines, 1, false)?;
    parse_world(&lines, 2, "WORLD|actor=parent|", "parent")?;
    exact(
        &lines,
        3,
        "DIRECT|actor=parent|pty=false|shm=false|sem=false",
    )?;
    parse_world(&lines, 4, "WORKER|result=", "worker")?;
    exact(
        &lines,
        5,
        "SPAWN|status=undefined|signal=null|error=Error|stdout=null",
    )?;
    exact(&lines, 6, "SELFEXEC_CALL")?;
    let self_exec_pid = parse_bootstrap(&lines, 7, true)?;
    if self_exec_pid != parent_pid {
        return Err(RbOuterOmpWorldVerificationError::SelfExecChangedPid {
            parent: parent_pid,
            self_exec: self_exec_pid,
        });
    }
    parse_world(&lines, 8, "WORLD|actor=selfexec|", "selfexec")?;
    exact(
        &lines,
        9,
        "DIRECT|actor=selfexec|pty=false|shm=false|sem=false",
    )?;
    exact(&lines, 10, "NONEXACT_EXEC_ATTEMPT|path=/usr/bin/true")?;
    lines[11]
        .strip_prefix("NONEXACT_EXEC_DENIED|errno=")
        .and_then(|value| value.parse::<i32>().ok())
        .filter(|value| *value < 0)
        .ok_or_else(|| unexpected(11, lines[11]))?;

    Ok(RbOuterOmpVerifiedWorld {
        pid: parent_pid,
        actors: ["parent", "worker", "selfexec"]
            .into_iter()
            .map(str::to_string)
            .collect(),
    })
}

fn parse_bootstrap(
    lines: &[&str],
    index: usize,
    self_exec: bool,
) -> Result<u32, RbOuterOmpWorldVerificationError> {
    let suffix = format!("|selfexec={self_exec}");
    lines[index]
        .strip_prefix("BOOTSTRAP|pid=")
        .and_then(|line| line.strip_suffix(&suffix))
        .and_then(|value| value.parse::<u32>().ok())
        .filter(|value| *value > 0)
        .ok_or(RbOuterOmpWorldVerificationError::InvalidPid)
}

fn parse_world(
    lines: &[&str],
    index: usize,
    prefix: &str,
    actor: &'static str,
) -> Result<(), RbOuterOmpWorldVerificationError> {
    let payload = lines[index]
        .strip_prefix(prefix)
        .ok_or_else(|| unexpected(index, lines[index]))?;
    let world: WorldEffects = serde_json::from_str(payload).map_err(|error| {
        RbOuterOmpWorldVerificationError::InvalidWorld {
            actor,
            message: error.to_string(),
        }
    })?;
    world.validate(actor)
}

fn exact(
    lines: &[&str],
    index: usize,
    expected: &str,
) -> Result<(), RbOuterOmpWorldVerificationError> {
    if lines[index] != expected {
        return Err(unexpected(index, lines[index]));
    }
    Ok(())
}

fn unexpected(index: usize, line: impl Into<String>) -> RbOuterOmpWorldVerificationError {
    RbOuterOmpWorldVerificationError::UnexpectedLine {
        index,
        line: line.into(),
    }
}

#[cfg(test)]
#[path = "rb_outer_omp_world_tests.rs"]
mod tests;
