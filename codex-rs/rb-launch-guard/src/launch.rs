use crate::GuardReservedLaunchAttempt;
use crate::LaunchGuardError;
use crate::MacProcessEventWatcher;
use crate::OneShotRendezvous;
use crate::ValidatedLaunchPolicy;
use crate::live_identity::authenticate_macos_exec_generation;
use crate::live_identity::read_macos_task_audit_identity;
use crate::live_identity::verify_macos_authenticated_exec_generation;
use crate::live_identity::verify_macos_live_process_argv;
use crate::reject_buffered_pre_identity_bytes;
use crate::suspended_spawn::SuspendedChild;
use codex_sandboxing::RbOuterOmpRendezvous;
use codex_sandboxing::RbOuterOmpSeatbeltRequest;
use codex_sandboxing::create_rb_outer_omp_seatbelt_command;
use codex_utils_absolute_path::AbsolutePathBuf;
use codex_utils_bounded_lines::BoundedLineError;
use codex_utils_bounded_lines::read_bounded_utf8_line;
use sha2::Digest;
use sha2::Sha256;
use std::fs::File;
use std::io::BufReader;
use std::os::fd::FromRawFd;
use std::os::unix::fs::MetadataExt;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::time::Duration;

pub struct PreparedRendezvousLaunch {
    program: PathBuf,
    args: Vec<String>,
    environment: Vec<(String, String)>,
    session_cwd: File,
    policy: ValidatedLaunchPolicy,
    rendezvous: OneShotRendezvous,
    compiled_launch_digest: String,
    one_shot_ticket_digest: String,
}

pub struct SpawnedRendezvousLaunch {
    child: Option<SuspendedChild>,
    baseline_pid_version: u32,
    policy: ValidatedLaunchPolicy,
    rendezvous: OneShotRendezvous,
    compiled_launch_digest: String,
    watcher: Option<MacProcessEventWatcher>,
    one_shot_ticket_digest: String,
}

pub const RB_OMP_MAX_PHYSICAL_FRAME_BYTES: usize = 1024 * 1024;

/// Product-unreachable authenticated transport. It intentionally exposes no
/// writer, raw stream, parsed value, callback, or Intent admission API.
pub struct AuthenticatedUnreachableTransport {
    child: Option<SuspendedChild>,
    policy: ValidatedLaunchPolicy,
    authenticated_pid_version: u32,
    reader: Option<BufReader<UnixStream>>,
    watcher: MacProcessEventWatcher,
    sequence: u64,
    revoked: bool,
    _compiled_launch_digest: String,
    _one_shot_ticket_digest: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthenticatedInboundFrame {
    bytes: Box<[u8]>,
    sha256: String,
    sequence: u64,
}

impl AuthenticatedInboundFrame {
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub fn sha256(&self) -> &str {
        &self.sha256
    }

    pub fn sequence(&self) -> u64 {
        self.sequence
    }
}

/// Prepares the product-unreachable exact-rendezvous launch path.
pub fn prepare_rendezvous_launch(
    reserved_attempt: GuardReservedLaunchAttempt,
) -> Result<PreparedRendezvousLaunch, LaunchGuardError> {
    let (policy, epoch, generation, one_shot_ticket_digest) = reserved_attempt.into_parts();
    policy.revalidate_for_exec()?;
    let rendezvous = OneShotRendezvous::create(
        &policy.launch_guard_root,
        policy.launch_guard_root_device,
        policy.launch_guard_root_inode,
    )?;
    let session_cwd = open_session_cwd(&policy)?;

    let executable = AbsolutePathBuf::from_absolute_path(policy.executable.clone())
        .map_err(|error| LaunchGuardError::InvalidPath(error.to_string()))?;
    let runtime = AbsolutePathBuf::from_absolute_path(policy.signed_runtime_root.clone())
        .map_err(|error| LaunchGuardError::InvalidPath(error.to_string()))?;
    let session = AbsolutePathBuf::from_absolute_path(policy.session_cwd.clone())
        .map_err(|error| LaunchGuardError::InvalidPath(error.to_string()))?;
    let rendezvous_path = AbsolutePathBuf::from_absolute_path(rendezvous.socket_path())
        .map_err(|error| LaunchGuardError::InvalidPath(error.to_string()))?;
    let forbidden = policy
        .forbidden_roots
        .iter()
        .cloned()
        .map(AbsolutePathBuf::from_absolute_path)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| LaunchGuardError::InvalidPath(error.to_string()))?;
    let compiled = create_rb_outer_omp_seatbelt_command(RbOuterOmpSeatbeltRequest {
        command: &policy.argv,
        verified_executable: &executable,
        signed_runtime_read_roots: std::slice::from_ref(&runtime),
        session_read_write_roots: std::slice::from_ref(&session),
        forbidden_roots: &forbidden,
        inherited_fds: &[],
        rendezvous: RbOuterOmpRendezvous::ConnectExact(&rendezvous_path),
        expected_macos_build: &policy.expected_macos_build,
        expected_arch: &policy.expected_arch,
    })
    .map_err(|error| LaunchGuardError::Sandbox(error.to_string()))?;
    let compiled_launch_digest = compiled.profile_seal.compiled_launch_sha256;

    Ok(PreparedRendezvousLaunch {
        program: compiled.program,
        args: compiled.args,
        environment: vec![
            (
                "RB_RENDEZVOUS_PATH".to_string(),
                rendezvous
                    .socket_path()
                    .to_str()
                    .ok_or_else(|| {
                        LaunchGuardError::InvalidPath(
                            "rendezvous path is not valid UTF-8".to_string(),
                        )
                    })?
                    .to_string(),
            ),
            ("RB_EPOCH".to_string(), epoch.to_string()),
            ("RB_GENERATION".to_string(), generation.to_string()),
        ],
        session_cwd,
        policy,
        rendezvous,
        compiled_launch_digest,
        one_shot_ticket_digest,
    })
}

impl PreparedRendezvousLaunch {
    pub fn spawn(self) -> Result<SpawnedRendezvousLaunch, LaunchGuardError> {
        self.spawn_with_hooks(|| {}, || {})
    }

    #[cfg(test)]
    pub(crate) fn rendezvous_path(&self) -> &std::path::Path {
        self.rendezvous.socket_path()
    }

    fn spawn_with_hooks(
        self,
        after_revalidation: impl FnOnce(),
        after_baseline: impl FnOnce(),
    ) -> Result<SpawnedRendezvousLaunch, LaunchGuardError> {
        self.policy.revalidate_for_exec()?;
        after_revalidation();
        verify_session_cwd_file(&self.session_cwd, &self.policy)?;
        let child = SuspendedChild::spawn(
            &self.program,
            &self.args,
            &self.environment,
            &self.session_cwd,
        )?;
        let child_id = child.id();
        let mut suspended_argv = Vec::with_capacity(self.args.len() + 1);
        suspended_argv.push(
            self.program
                .to_str()
                .ok_or_else(|| {
                    LaunchGuardError::InvalidPath(
                        "suspended spawn program is not valid UTF-8".to_string(),
                    )
                })?
                .to_string(),
        );
        suspended_argv.extend(self.args.iter().cloned());
        verify_macos_live_process_argv(child_id, &suspended_argv)?;
        verify_session_cwd_file(&self.session_cwd, &self.policy)?;
        let watcher = MacProcessEventWatcher::new(child_id)?;
        let baseline = read_macos_task_audit_identity(child_id)?;
        let repeated_baseline = read_macos_task_audit_identity(child_id)?;
        if baseline != repeated_baseline {
            return Err(LaunchGuardError::LiveIdentity(
                "suspended TASK_AUDIT_TOKEN baseline changed before resume".to_string(),
            ));
        }
        after_baseline();
        child.resume()?;
        Ok(SpawnedRendezvousLaunch {
            child: Some(child),
            baseline_pid_version: baseline.pid_version,
            policy: self.policy,
            rendezvous: self.rendezvous,
            compiled_launch_digest: self.compiled_launch_digest,
            watcher: Some(watcher),
            one_shot_ticket_digest: self.one_shot_ticket_digest,
        })
    }

    #[cfg(test)]
    pub(crate) fn spawn_after_test_mutation(
        self,
        mutation: impl FnOnce(),
    ) -> Result<SpawnedRendezvousLaunch, LaunchGuardError> {
        self.spawn_with_hooks(mutation, || {})
    }

    #[cfg(test)]
    pub(crate) fn spawn_with_test_after_baseline(
        self,
        after_baseline: impl FnOnce(),
    ) -> Result<SpawnedRendezvousLaunch, LaunchGuardError> {
        self.spawn_with_hooks(|| {}, after_baseline)
    }
}

impl SpawnedRendezvousLaunch {
    pub fn authenticate_unreachable(
        mut self,
        timeout: Duration,
    ) -> Result<AuthenticatedUnreachableTransport, LaunchGuardError> {
        let authenticated = self.rendezvous.accept(timeout)?;
        reject_buffered_pre_identity_bytes(&authenticated)?;
        let child_pid = self.require_running_child()?;
        let live_identity = authenticate_macos_exec_generation(
            &authenticated,
            child_pid,
            self.baseline_pid_version,
            &self.policy.designated_requirement,
        )?;
        verify_macos_live_process_argv(child_pid, &self.policy.argv)?;
        match self.watcher()?.wait(Duration::ZERO)? {
            Some(crate::MacProcessEvent::Exec) => {
                // NOTE_EXEC independently proves that an exec occurred. The
                // exact execution identity is the peer/current pidversion
                // observed above and frozen for all later frame admissions.
                verify_macos_authenticated_exec_generation(
                    &authenticated,
                    child_pid,
                    live_identity.pid_version,
                    &self.policy.designated_requirement,
                )?;
                verify_macos_live_process_argv(child_pid, &self.policy.argv)?;
            }
            Some(crate::MacProcessEvent::Exit | crate::MacProcessEvent::ExecAndExit) => {
                return Err(LaunchGuardError::LiveIdentity(
                    "child exited while establishing approved initial exec".to_string(),
                ));
            }
            None => {
                return Err(LaunchGuardError::LiveIdentity(
                    "approved initial exec boundary was not observed".to_string(),
                ));
            }
        }
        reject_buffered_pre_identity_bytes(&authenticated)?;
        self.rendezvous.consume()?;

        self.require_running_child()?;
        if self.watcher()?.wait(Duration::ZERO)?.is_some() {
            return Err(LaunchGuardError::LiveIdentity(
                "child exec or exit preceded authenticated transport".to_string(),
            ));
        }
        verify_macos_authenticated_exec_generation(
            &authenticated,
            child_pid,
            live_identity.pid_version,
            &self.policy.designated_requirement,
        )?;
        verify_macos_live_process_argv(child_pid, &self.policy.argv)?;
        self.require_running_child()?;
        if self.watcher()?.wait(Duration::ZERO)?.is_some() {
            return Err(LaunchGuardError::LiveIdentity(
                "child exec or exit raced authenticated transport creation".to_string(),
            ));
        }
        authenticated
            .set_read_timeout(Some(timeout))
            .map_err(|error| LaunchGuardError::Io(error.to_string()))?;

        Ok(AuthenticatedUnreachableTransport {
            child: self.child.take(),
            policy: self.policy.clone(),
            authenticated_pid_version: live_identity.pid_version,
            reader: Some(BufReader::new(authenticated)),
            watcher: self.watcher.take().ok_or_else(|| {
                LaunchGuardError::LiveIdentity("process watcher is absent".to_string())
            })?,
            sequence: 0,
            revoked: false,
            _compiled_launch_digest: self.compiled_launch_digest.clone(),
            _one_shot_ticket_digest: self.one_shot_ticket_digest.clone(),
        })
    }

    pub fn child_id(&self) -> Option<u32> {
        self.child.as_ref().map(SuspendedChild::id)
    }

    fn require_running_child(&mut self) -> Result<u32, LaunchGuardError> {
        let child = self
            .child
            .as_mut()
            .ok_or_else(|| LaunchGuardError::LiveIdentity("child is absent".to_string()))?;
        let child_id = child.id();
        if let Some(status) = child.try_wait()? {
            return Err(LaunchGuardError::LiveIdentity(format!(
                "child exited before authenticated transport: {status}"
            )));
        }
        Ok(child_id)
    }

    fn watcher(&self) -> Result<&MacProcessEventWatcher, LaunchGuardError> {
        self.watcher
            .as_ref()
            .ok_or_else(|| LaunchGuardError::LiveIdentity("process watcher is absent".to_string()))
    }
}

impl AuthenticatedUnreachableTransport {
    pub fn policy(&self) -> &ValidatedLaunchPolicy {
        &self.policy
    }

    pub fn child_id(&self) -> u32 {
        self.child.as_ref().map_or(0, SuspendedChild::id)
    }

    pub fn read_owned_frame(&mut self) -> Result<AuthenticatedInboundFrame, LaunchGuardError> {
        self.read_owned_frame_with_hook(|| {})
    }

    #[cfg(test)]
    pub(crate) fn read_owned_frame_with_test_after_precheck(
        &mut self,
        after_precheck: impl FnOnce(),
    ) -> Result<AuthenticatedInboundFrame, LaunchGuardError> {
        self.read_owned_frame_with_hook(after_precheck)
    }

    fn read_owned_frame_with_hook(
        &mut self,
        after_precheck: impl FnOnce(),
    ) -> Result<AuthenticatedInboundFrame, LaunchGuardError> {
        if self.revoked {
            return Err(LaunchGuardError::TransportRevoked);
        }
        match self.read_owned_frame_inner(after_precheck) {
            Ok(frame) => Ok(frame),
            Err(error) => Err(self.revoke(error)),
        }
    }

    fn read_owned_frame_inner(
        &mut self,
        after_precheck: impl FnOnce(),
    ) -> Result<AuthenticatedInboundFrame, LaunchGuardError> {
        if let Some(event) = self.watcher.wait(Duration::ZERO)? {
            return Err(process_event_error(event));
        }
        let child_pid = self.require_running_child()?;
        after_precheck();
        let line = {
            let reader = self
                .reader
                .as_mut()
                .ok_or(LaunchGuardError::TransportRevoked)?;
            read_bounded_utf8_line(reader, RB_OMP_MAX_PHYSICAL_FRAME_BYTES)
        };
        let line = match line {
            Ok(Some(line)) => line,
            Ok(None) => return Err(LaunchGuardError::TransportEof),
            Err(BoundedLineError::InvalidUtf8(_)) => {
                return Err(LaunchGuardError::InvalidFrameUtf8);
            }
            Err(BoundedLineError::PhysicalFrameTooLong { max_physical_bytes }) => {
                return Err(LaunchGuardError::FrameTooLong { max_physical_bytes });
            }
            Err(BoundedLineError::InvalidLimit | BoundedLineError::Io(_)) => {
                return Err(LaunchGuardError::TransportRevoked);
            }
        };
        if !line.terminated_by_lf {
            return Err(LaunchGuardError::PartialFrameAtEof);
        }
        if line.text.trim().is_empty() {
            return Err(LaunchGuardError::EmptyFrame);
        }

        let stream = self
            .reader
            .as_ref()
            .ok_or(LaunchGuardError::TransportRevoked)?
            .get_ref();
        verify_macos_authenticated_exec_generation(
            stream,
            child_pid,
            self.authenticated_pid_version,
            &self.policy.designated_requirement,
        )?;
        if let Some(event) = self.watcher.wait(Duration::ZERO)? {
            return Err(process_event_error(event));
        }

        let bytes = line.text.into_bytes();
        let parsed = serde_json::from_slice::<serde_json::Value>(&bytes)
            .map_err(|_| LaunchGuardError::InvalidFrameJson);
        let parsed = parsed?;
        if !parsed.is_object() {
            return Err(LaunchGuardError::FrameMustBeObject);
        }
        let sequence = match self.sequence.checked_add(1) {
            Some(sequence) => sequence,
            None => return Err(LaunchGuardError::FrameSequenceOverflow),
        };
        self.sequence = sequence;
        let sha256 = format!("{:x}", Sha256::digest(&bytes));
        Ok(AuthenticatedInboundFrame {
            bytes: bytes.into_boxed_slice(),
            sha256,
            sequence,
        })
    }

    fn require_running_child(&mut self) -> Result<u32, LaunchGuardError> {
        let child = self
            .child
            .as_mut()
            .ok_or(LaunchGuardError::TransportRevoked)?;
        let child_id = child.id();
        if child.try_wait()?.is_some() {
            return Err(LaunchGuardError::ProcessExitObserved);
        }
        Ok(child_id)
    }

    fn revoke(&mut self, error: LaunchGuardError) -> LaunchGuardError {
        self.revoked = true;
        self.reader.take();
        let _ = terminate_child(&mut self.child);
        error
    }

    pub fn terminate(mut self) -> Result<std::process::ExitStatus, LaunchGuardError> {
        self.revoked = true;
        self.reader.take();
        terminate_child(&mut self.child)
    }

    #[cfg(test)]
    pub(crate) fn set_sequence_for_test(&mut self, sequence: u64) {
        self.sequence = sequence;
    }
}

fn process_event_error(event: crate::MacProcessEvent) -> LaunchGuardError {
    match event {
        crate::MacProcessEvent::Exec => LaunchGuardError::ProcessExecObserved,
        crate::MacProcessEvent::Exit => LaunchGuardError::ProcessExitObserved,
        crate::MacProcessEvent::ExecAndExit => LaunchGuardError::ProcessExecAndExitObserved,
    }
}

impl Drop for SpawnedRendezvousLaunch {
    fn drop(&mut self) {
        let _ = terminate_child(&mut self.child);
    }
}

impl Drop for AuthenticatedUnreachableTransport {
    fn drop(&mut self) {
        let _ = terminate_child(&mut self.child);
    }
}

fn terminate_child(
    child: &mut Option<SuspendedChild>,
) -> Result<std::process::ExitStatus, LaunchGuardError> {
    let mut child = child
        .take()
        .ok_or_else(|| LaunchGuardError::LiveIdentity("child already reaped".to_string()))?;
    child.terminate()
}

fn open_session_cwd(policy: &ValidatedLaunchPolicy) -> Result<File, LaunchGuardError> {
    use std::os::unix::ffi::OsStrExt;

    let path = std::ffi::CString::new(policy.session_cwd.as_os_str().as_bytes())
        .map_err(|_| LaunchGuardError::InvalidPath("session cwd contains NUL".to_string()))?;
    let descriptor = unsafe {
        libc::open(
            path.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if descriptor < 0 {
        return Err(LaunchGuardError::Io(
            std::io::Error::last_os_error().to_string(),
        ));
    }
    let directory = unsafe { File::from_raw_fd(descriptor) };
    verify_session_cwd_file(&directory, policy)?;
    Ok(directory)
}

fn verify_session_cwd_file(
    directory: &File,
    policy: &ValidatedLaunchPolicy,
) -> Result<(), LaunchGuardError> {
    let metadata = directory
        .metadata()
        .map_err(|error| LaunchGuardError::Io(error.to_string()))?;
    if !metadata.is_dir()
        || metadata.dev() != policy.session_cwd_device
        || metadata.ino() != policy.session_cwd_inode
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.permissions().mode() & 0o777 != 0o700
    {
        return Err(LaunchGuardError::IdentityDrift(
            "session cwd identity, owner, type, or mode changed before spawn".to_string(),
        ));
    }
    Ok(())
}
