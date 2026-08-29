use crate::LaunchGuardError;
use std::ffi::CString;
use std::os::fd::AsRawFd;
use std::path::Path;

unsafe extern "C" {
    fn posix_spawn_file_actions_addfchdir(
        actions: *mut libc::posix_spawn_file_actions_t,
        fd: libc::c_int,
    ) -> libc::c_int;
    fn posix_spawn_file_actions_addinherit_np(
        actions: *mut libc::posix_spawn_file_actions_t,
        fd: libc::c_int,
    ) -> libc::c_int;
}

pub(crate) struct SuspendedChild {
    pid: libc::pid_t,
    reaped: bool,
}

impl SuspendedChild {
    pub(crate) fn spawn(
        program: &Path,
        args: &[String],
        environment: &[(String, String)],
        cwd: &impl AsRawFd,
    ) -> Result<Self, LaunchGuardError> {
        let program = CString::new(program.as_os_str().as_encoded_bytes())
            .map_err(|_| LaunchGuardError::InvalidPath("spawn program contains NUL".to_string()))?;
        let mut argv = Vec::with_capacity(args.len() + 1);
        argv.push(program.clone());
        for argument in args {
            argv.push(CString::new(argument.as_bytes()).map_err(|_| {
                LaunchGuardError::InvalidAuthority("spawn argv contains NUL".to_string())
            })?);
        }
        let mut argv_pointers = argv
            .iter()
            .map(|argument| argument.as_ptr().cast_mut())
            .collect::<Vec<_>>();
        argv_pointers.push(std::ptr::null_mut());

        let environment = environment
            .iter()
            .map(|(key, value)| CString::new(format!("{key}={value}")))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| {
                LaunchGuardError::InvalidAuthority("spawn env contains NUL".to_string())
            })?;
        let mut environment_pointers = environment
            .iter()
            .map(|entry| entry.as_ptr().cast_mut())
            .collect::<Vec<_>>();
        environment_pointers.push(std::ptr::null_mut());

        let mut actions = SpawnFileActions::new()?;
        for descriptor in [libc::STDIN_FILENO, libc::STDOUT_FILENO, libc::STDERR_FILENO] {
            let result =
                unsafe { posix_spawn_file_actions_addinherit_np(&raw mut actions.raw, descriptor) };
            actions.check(result)?;
        }
        let result =
            unsafe { posix_spawn_file_actions_addfchdir(&raw mut actions.raw, cwd.as_raw_fd()) };
        actions.check(result)?;
        let result = unsafe {
            libc::posix_spawn_file_actions_addclose(&raw mut actions.raw, cwd.as_raw_fd())
        };
        actions.check(result)?;

        let mut attributes = SpawnAttributes::new()?;
        let flags = (libc::POSIX_SPAWN_START_SUSPENDED | libc::POSIX_SPAWN_CLOEXEC_DEFAULT)
            as libc::c_short;
        let result = unsafe { libc::posix_spawnattr_setflags(&raw mut attributes.raw, flags) };
        attributes.check(result)?;

        let mut pid = 0;
        // The posix_spawn window duplicates the caller's whole descriptor
        // table into the child until exec applies O_CLOEXEC. Test builds hold
        // the spawn/flock exclusion so a parallel lock-lifecycle test never
        // closes and reopens a store inside that window.
        #[cfg(test)]
        let _spawn_exclusion = crate::test_spawn_exclusion::acquire();
        let result = unsafe {
            libc::posix_spawn(
                &raw mut pid,
                program.as_ptr(),
                &raw const actions.raw,
                &raw const attributes.raw,
                argv_pointers.as_ptr(),
                environment_pointers.as_ptr(),
            )
        };
        if result != 0 || pid < 1 {
            return Err(LaunchGuardError::Io(format!(
                "suspended posix_spawn failed: {}",
                std::io::Error::from_raw_os_error(result)
            )));
        }
        Ok(Self { pid, reaped: false })
    }

    pub(crate) fn id(&self) -> u32 {
        self.pid as u32
    }

    pub(crate) fn resume(&self) -> Result<(), LaunchGuardError> {
        if unsafe { libc::kill(self.pid, libc::SIGCONT) } != 0 {
            return Err(LaunchGuardError::Io(format!(
                "resume suspended child failed: {}",
                std::io::Error::last_os_error()
            )));
        }
        Ok(())
    }

    pub(crate) fn try_wait(
        &mut self,
    ) -> Result<Option<std::process::ExitStatus>, LaunchGuardError> {
        if self.reaped {
            return Err(LaunchGuardError::LiveIdentity(
                "child already reaped".to_string(),
            ));
        }
        let mut status = 0;
        let result = unsafe { libc::waitpid(self.pid, &raw mut status, libc::WNOHANG) };
        if result < 0 {
            return Err(LaunchGuardError::Io(
                std::io::Error::last_os_error().to_string(),
            ));
        }
        if result == 0 {
            return Ok(None);
        }
        self.reaped = true;
        Ok(Some(std::os::unix::process::ExitStatusExt::from_raw(
            status,
        )))
    }

    pub(crate) fn terminate(&mut self) -> Result<std::process::ExitStatus, LaunchGuardError> {
        if let Some(status) = self.try_wait()? {
            return Ok(status);
        }
        if unsafe { libc::kill(self.pid, libc::SIGKILL) } != 0 {
            return Err(LaunchGuardError::Io(
                std::io::Error::last_os_error().to_string(),
            ));
        }
        let mut status = 0;
        if unsafe { libc::waitpid(self.pid, &raw mut status, 0) } != self.pid {
            return Err(LaunchGuardError::Io(
                std::io::Error::last_os_error().to_string(),
            ));
        }
        self.reaped = true;
        Ok(std::os::unix::process::ExitStatusExt::from_raw(status))
    }
}

impl Drop for SuspendedChild {
    fn drop(&mut self) {
        if !self.reaped {
            let _ = unsafe { libc::kill(self.pid, libc::SIGKILL) };
            let mut status = 0;
            let _ = unsafe { libc::waitpid(self.pid, &raw mut status, 0) };
            self.reaped = true;
        }
    }
}

struct SpawnFileActions {
    raw: libc::posix_spawn_file_actions_t,
}

impl SpawnFileActions {
    fn new() -> Result<Self, LaunchGuardError> {
        let mut raw = std::ptr::null_mut();
        let result = unsafe { libc::posix_spawn_file_actions_init(&raw mut raw) };
        if result != 0 {
            return Err(spawn_configuration_error("file actions init", result));
        }
        Ok(Self { raw })
    }

    fn check(&mut self, result: libc::c_int) -> Result<(), LaunchGuardError> {
        if result == 0 {
            Ok(())
        } else {
            Err(spawn_configuration_error("file action", result))
        }
    }
}

impl Drop for SpawnFileActions {
    fn drop(&mut self) {
        let _ = unsafe { libc::posix_spawn_file_actions_destroy(&raw mut self.raw) };
    }
}

struct SpawnAttributes {
    raw: libc::posix_spawnattr_t,
}

impl SpawnAttributes {
    fn new() -> Result<Self, LaunchGuardError> {
        let mut raw = std::ptr::null_mut();
        let result = unsafe { libc::posix_spawnattr_init(&raw mut raw) };
        if result != 0 {
            return Err(spawn_configuration_error("attributes init", result));
        }
        Ok(Self { raw })
    }

    fn check(&mut self, result: libc::c_int) -> Result<(), LaunchGuardError> {
        if result == 0 {
            Ok(())
        } else {
            Err(spawn_configuration_error("attribute", result))
        }
    }
}

impl Drop for SpawnAttributes {
    fn drop(&mut self) {
        let _ = unsafe { libc::posix_spawnattr_destroy(&raw mut self.raw) };
    }
}

fn spawn_configuration_error(stage: &str, error: libc::c_int) -> LaunchGuardError {
    LaunchGuardError::Io(format!(
        "posix_spawn {stage} failed: {}",
        std::io::Error::from_raw_os_error(error)
    ))
}
