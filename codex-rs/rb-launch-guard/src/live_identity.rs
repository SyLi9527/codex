use crate::LaunchGuardError;
use core_foundation::base::TCFType;
use core_foundation::data::CFData;
use security_framework::os::macos::code_signing::Flags;
use security_framework::os::macos::code_signing::GuestAttributes;
use security_framework::os::macos::code_signing::SecCode;
use security_framework::os::macos::code_signing::SecRequirement;
use sha2::Digest;
use sha2::Sha256;
use std::mem::size_of;
use std::os::fd::AsRawFd;
use std::os::unix::net::UnixStream;

#[repr(C)]
#[derive(Clone, Copy)]
struct AuditToken {
    words: [libc::c_uint; 8],
}

#[link(name = "bsm")]
unsafe extern "C" {
    fn audit_token_to_pid(token: AuditToken) -> libc::pid_t;
    fn audit_token_to_pidversion(token: AuditToken) -> libc::c_int;
}

unsafe extern "C" {
    fn task_name_for_pid(
        target_task: libc::mach_port_t,
        pid: libc::pid_t,
        task: *mut libc::mach_port_t,
    ) -> libc::kern_return_t;
    fn mach_port_deallocate(
        task: libc::mach_port_t,
        name: libc::mach_port_t,
    ) -> libc::kern_return_t;
}

const TASK_AUDIT_TOKEN: libc::task_flavor_t = 15;
const TASK_AUDIT_TOKEN_COUNT: libc::mach_msg_type_number_t =
    (size_of::<AuditToken>() / size_of::<libc::natural_t>()) as libc::mach_msg_type_number_t;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MacLivePeerIdentity {
    pub pid: u32,
    pub pid_version: u32,
    pub audit_token_sha256: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct MacTaskAuditIdentity {
    pub pid: u32,
    pub pid_version: u32,
    pub audit_token_sha256: String,
}

pub(crate) fn read_macos_task_audit_identity(
    pid: u32,
) -> Result<MacTaskAuditIdentity, LaunchGuardError> {
    if pid == 0 || pid > libc::pid_t::MAX as u32 {
        return Err(LaunchGuardError::LiveIdentity(
            "invalid pid for TASK_AUDIT_TOKEN".to_string(),
        ));
    }
    let mut task: libc::mach_port_t = libc::MACH_PORT_NULL as libc::mach_port_t;
    #[allow(deprecated)]
    let self_task = unsafe { libc::mach_task_self() };
    let task_result = unsafe { task_name_for_pid(self_task, pid as libc::pid_t, &raw mut task) };
    if task_result != libc::KERN_SUCCESS || task == 0 {
        return Err(LaunchGuardError::LiveIdentity(format!(
            "task_name_for_pid failed for TASK_AUDIT_TOKEN: {task_result}"
        )));
    }
    let task = TaskNamePort { task, self_task };
    let mut token = AuditToken { words: [0; 8] };
    let mut count = TASK_AUDIT_TOKEN_COUNT;
    let info_result = unsafe {
        libc::task_info(
            task.task,
            TASK_AUDIT_TOKEN,
            (&raw mut token).cast(),
            &raw mut count,
        )
    };
    if info_result != libc::KERN_SUCCESS || count != TASK_AUDIT_TOKEN_COUNT {
        return Err(LaunchGuardError::LiveIdentity(format!(
            "TASK_AUDIT_TOKEN failed: result={info_result}, count={count}"
        )));
    }
    audit_identity(token, pid, "TASK_AUDIT_TOKEN")
}

pub(crate) fn authenticate_macos_exec_generation(
    channel: &UnixStream,
    spawned_pid: u32,
    baseline_pid_version: u32,
    designated_requirement: &str,
) -> Result<MacLivePeerIdentity, LaunchGuardError> {
    let (peer, token, peer_pid) = read_macos_live_peer_token(channel, spawned_pid)?;
    let current = read_macos_task_audit_identity(spawned_pid)?;
    validate_initial_exec_generation(baseline_pid_version, peer.pid_version, current.pid_version)?;
    verify_macos_seccode(peer_pid, token, designated_requirement)?;
    Ok(peer)
}

fn validate_initial_exec_generation(
    baseline_pid_version: u32,
    peer_pid_version: u32,
    current_pid_version: u32,
) -> Result<(), LaunchGuardError> {
    if peer_pid_version != current_pid_version || current_pid_version <= baseline_pid_version {
        return Err(LaunchGuardError::InitialExecGenerationInvalid {
            baseline_pid_version,
            peer_pid_version,
            current_pid_version,
        });
    }
    Ok(())
}

pub(crate) fn verify_macos_authenticated_exec_generation(
    channel: &UnixStream,
    spawned_pid: u32,
    authenticated_pid_version: u32,
    designated_requirement: &str,
) -> Result<MacLivePeerIdentity, LaunchGuardError> {
    let (peer, token, peer_pid) = read_macos_live_peer_token(channel, spawned_pid)?;
    let current = read_macos_task_audit_identity(spawned_pid)?;
    if peer.pid_version != authenticated_pid_version
        || current.pid_version != authenticated_pid_version
        || peer.pid_version != current.pid_version
    {
        return Err(LaunchGuardError::AuthenticatedExecGenerationDrift {
            authenticated_pid_version,
            peer_pid_version: peer.pid_version,
            current_pid_version: current.pid_version,
        });
    }
    verify_macos_seccode(peer_pid, token, designated_requirement)?;
    Ok(peer)
}

/// Binds a connected anonymous channel to the spawned process and validates
/// that live process with Security.framework, rather than validating only the
/// executable path on disk.
///
/// A socketpair whose peer credentials still identify the pre-fork launcher
/// fails here. Callers must not replace this with a child-supplied PID or ready
/// field; without an exact peer token, model/capability channels remain unarmed.
pub fn verify_macos_live_peer_identity(
    channel: &UnixStream,
    spawned_pid: u32,
    designated_requirement: &str,
) -> Result<MacLivePeerIdentity, LaunchGuardError> {
    let (peer, token, peer_pid) = read_macos_live_peer_token(channel, spawned_pid)?;
    verify_macos_seccode(peer_pid, token, designated_requirement)?;
    Ok(peer)
}

fn read_macos_live_peer_token(
    channel: &UnixStream,
    spawned_pid: u32,
) -> Result<(MacLivePeerIdentity, AuditToken, libc::c_int), LaunchGuardError> {
    let fd = channel.as_raw_fd();
    let mut peer_pid: libc::c_int = 0;
    let mut peer_pid_len = size_of::<libc::c_int>() as libc::socklen_t;
    let peer_pid_result = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_LOCAL,
            libc::LOCAL_PEERPID,
            (&raw mut peer_pid).cast(),
            &raw mut peer_pid_len,
        )
    };
    if peer_pid_result != 0 || peer_pid_len as usize != size_of::<libc::c_int>() {
        return Err(LaunchGuardError::LiveIdentity(format!(
            "LOCAL_PEERPID failed: {}",
            std::io::Error::last_os_error()
        )));
    }

    let mut token = AuditToken { words: [0; 8] };
    let mut token_len = size_of::<AuditToken>() as libc::socklen_t;
    let token_result = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_LOCAL,
            libc::LOCAL_PEERTOKEN,
            (&raw mut token).cast(),
            &raw mut token_len,
        )
    };
    if token_result != 0 || token_len as usize != size_of::<AuditToken>() {
        return Err(LaunchGuardError::LiveIdentity(format!(
            "LOCAL_PEERTOKEN failed: {}",
            std::io::Error::last_os_error()
        )));
    }

    let token_pid = unsafe { audit_token_to_pid(token) };
    if peer_pid < 1 || token_pid != peer_pid {
        return Err(LaunchGuardError::PeerTokenPidMismatch {
            socket_pid: peer_pid,
            token_pid,
        });
    }
    if peer_pid as u32 != spawned_pid {
        return Err(LaunchGuardError::PeerPidMismatch {
            socket_pid: peer_pid,
            token_pid,
            spawned_pid,
        });
    }
    let pid_version = unsafe { audit_token_to_pidversion(token) };
    if pid_version < 1 {
        return Err(LaunchGuardError::LiveIdentity(
            "peer audit token has no positive pidversion".to_string(),
        ));
    }

    let token_bytes = unsafe {
        std::slice::from_raw_parts((&raw const token).cast::<u8>(), size_of::<AuditToken>())
    };
    Ok((
        MacLivePeerIdentity {
            pid: spawned_pid,
            pid_version: pid_version as u32,
            audit_token_sha256: format!("{:x}", Sha256::digest(token_bytes)),
        },
        token,
        peer_pid,
    ))
}

fn verify_macos_seccode(
    peer_pid: libc::c_int,
    token: AuditToken,
    designated_requirement: &str,
) -> Result<(), LaunchGuardError> {
    let token_bytes = unsafe {
        std::slice::from_raw_parts((&raw const token).cast::<u8>(), size_of::<AuditToken>())
    };
    let token_data = CFData::from_buffer(token_bytes);
    let mut attributes = GuestAttributes::new();
    attributes.set_pid(peer_pid);
    attributes.set_audit_token(token_data.as_concrete_TypeRef());
    let live_code = SecCode::copy_guest_with_attribues(None, &attributes, Flags::NONE)
        .map_err(|error| LaunchGuardError::SecCodeInvalid(error.to_string()))?;
    let requirement: SecRequirement =
        designated_requirement
            .parse()
            .map_err(|error: security_framework::base::Error| {
                LaunchGuardError::SecCodeInvalid(error.to_string())
            })?;
    live_code
        .check_validity(
            Flags::STRICT_VALIDATE | Flags::NO_NETWORK_ACCESS,
            &requirement,
        )
        .map_err(|error| LaunchGuardError::SecCodeInvalid(error.to_string()))?;

    Ok(())
}

fn audit_identity(
    token: AuditToken,
    expected_pid: u32,
    source: &str,
) -> Result<MacTaskAuditIdentity, LaunchGuardError> {
    let token_pid = unsafe { audit_token_to_pid(token) };
    if token_pid < 1 || token_pid as u32 != expected_pid {
        return Err(LaunchGuardError::LiveIdentity(format!(
            "{source} pid mismatch: token={token_pid}, expected={expected_pid}"
        )));
    }
    let pid_version = unsafe { audit_token_to_pidversion(token) };
    if pid_version < 1 {
        return Err(LaunchGuardError::LiveIdentity(format!(
            "{source} has no positive pidversion"
        )));
    }
    let token_bytes = unsafe {
        std::slice::from_raw_parts((&raw const token).cast::<u8>(), size_of::<AuditToken>())
    };
    Ok(MacTaskAuditIdentity {
        pid: expected_pid,
        pid_version: pid_version as u32,
        audit_token_sha256: format!("{:x}", Sha256::digest(token_bytes)),
    })
}

struct TaskNamePort {
    task: libc::mach_port_t,
    self_task: libc::mach_port_t,
}

impl Drop for TaskNamePort {
    fn drop(&mut self) {
        let _ = unsafe { mach_port_deallocate(self.self_task, self.task) };
    }
}

pub(crate) fn verify_macos_live_process_argv(
    pid: u32,
    expected: &[String],
) -> Result<(), LaunchGuardError> {
    if pid == 0 || pid > libc::pid_t::MAX as u32 || expected.is_empty() {
        return Err(LaunchGuardError::LiveIdentity(
            "invalid pid or empty approved argv".to_string(),
        ));
    }
    let mut argument_max: libc::c_int = 0;
    let mut argument_max_length = size_of::<libc::c_int>();
    let mut argument_max_name = [libc::CTL_KERN, libc::KERN_ARGMAX];
    if unsafe {
        libc::sysctl(
            argument_max_name.as_mut_ptr(),
            argument_max_name.len() as libc::c_uint,
            (&raw mut argument_max).cast(),
            &raw mut argument_max_length,
            std::ptr::null_mut(),
            0,
        )
    } != 0
        || argument_max <= 0
        || argument_max as usize > 1_048_576
    {
        return Err(LaunchGuardError::LiveIdentity(format!(
            "KERN_ARGMAX failed or exceeded the 1 MiB ceiling: {}",
            std::io::Error::last_os_error()
        )));
    }

    let mut bytes = vec![0_u8; argument_max as usize];
    let mut bytes_length = bytes.len();
    let mut arguments_name = [libc::CTL_KERN, libc::KERN_PROCARGS2, pid as libc::c_int];
    if unsafe {
        libc::sysctl(
            arguments_name.as_mut_ptr(),
            arguments_name.len() as libc::c_uint,
            bytes.as_mut_ptr().cast(),
            &raw mut bytes_length,
            std::ptr::null_mut(),
            0,
        )
    } != 0
        || bytes_length < size_of::<libc::c_int>()
        || bytes_length > bytes.len()
    {
        return Err(LaunchGuardError::LiveIdentity(format!(
            "KERN_PROCARGS2 failed: {}",
            std::io::Error::last_os_error()
        )));
    }
    bytes.truncate(bytes_length);
    let argument_count = libc::c_int::from_ne_bytes(
        bytes[..size_of::<libc::c_int>()]
            .try_into()
            .map_err(|_| LaunchGuardError::LiveIdentity("short KERN_PROCARGS2".to_string()))?,
    );
    if argument_count < 1 || argument_count as usize != expected.len() {
        return Err(LaunchGuardError::LiveIdentity(
            "live argv count differs from approved authority".to_string(),
        ));
    }

    let mut cursor = size_of::<libc::c_int>();
    cursor = skip_c_string(&bytes, cursor, "executable path")?;
    while bytes.get(cursor) == Some(&0) {
        cursor += 1;
    }
    for approved in expected {
        let end = bytes[cursor..]
            .iter()
            .position(|byte| *byte == 0)
            .map(|offset| cursor + offset)
            .ok_or_else(|| {
                LaunchGuardError::LiveIdentity("unterminated live argv item".to_string())
            })?;
        if bytes[cursor..end] != *approved.as_bytes() {
            return Err(LaunchGuardError::LiveIdentity(
                "live argv differs from approved authority".to_string(),
            ));
        }
        cursor = end + 1;
    }
    Ok(())
}

fn skip_c_string(bytes: &[u8], cursor: usize, field: &str) -> Result<usize, LaunchGuardError> {
    bytes[cursor..]
        .iter()
        .position(|byte| *byte == 0)
        .map(|offset| cursor + offset + 1)
        .ok_or_else(|| LaunchGuardError::LiveIdentity(format!("unterminated live {field}")))
}

#[cfg(test)]
mod tests {
    use super::validate_initial_exec_generation;
    use crate::LaunchGuardError;

    #[test]
    fn initial_exec_generation_requires_strict_forward_progress_and_matching_tokens() {
        validate_initial_exec_generation(40, 47, 47).expect("strict forward progress");

        for (peer, current) in [(40, 40), (39, 39), (47, 46)] {
            assert!(matches!(
                validate_initial_exec_generation(40, peer, current),
                Err(LaunchGuardError::InitialExecGenerationInvalid {
                    baseline_pid_version: 40,
                    peer_pid_version,
                    current_pid_version,
                }) if peer_pid_version == peer && current_pid_version == current
            ));
        }
    }
}
