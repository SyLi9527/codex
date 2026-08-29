use crate::LaunchGuardError;
use std::mem::MaybeUninit;
use std::time::Duration;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MacProcessEvent {
    Exec,
    Exit,
    ExecAndExit,
}

pub struct MacProcessEventWatcher {
    queue: i32,
    pid: u32,
}

impl MacProcessEventWatcher {
    pub fn new(pid: u32) -> Result<Self, LaunchGuardError> {
        if pid == 0 || pid > libc::pid_t::MAX as u32 {
            return Err(LaunchGuardError::LiveIdentity(
                "invalid pid for NOTE_EXEC watcher".to_string(),
            ));
        }
        let queue = unsafe { libc::kqueue() };
        if queue < 0 {
            return Err(LaunchGuardError::LiveIdentity(format!(
                "kqueue creation failed: {}",
                std::io::Error::last_os_error()
            )));
        }
        let change = libc::kevent {
            ident: pid as libc::uintptr_t,
            filter: libc::EVFILT_PROC,
            flags: libc::EV_ADD | libc::EV_ENABLE | libc::EV_CLEAR,
            fflags: libc::NOTE_EXEC | libc::NOTE_EXIT,
            data: 0,
            udata: std::ptr::null_mut(),
        };
        let registered = unsafe {
            libc::kevent(
                queue,
                &raw const change,
                1,
                std::ptr::null_mut(),
                0,
                std::ptr::null(),
            )
        };
        if registered != 0 {
            let error = std::io::Error::last_os_error();
            unsafe { libc::close(queue) };
            return Err(LaunchGuardError::LiveIdentity(format!(
                "NOTE_EXEC registration failed: {error}"
            )));
        }
        Ok(Self { queue, pid })
    }

    pub fn wait(&self, timeout: Duration) -> Result<Option<MacProcessEvent>, LaunchGuardError> {
        let seconds = timeout.as_secs();
        if seconds > libc::time_t::MAX as u64 {
            return Err(LaunchGuardError::LiveIdentity(
                "NOTE_EXEC timeout is too large".to_string(),
            ));
        }
        let timeout = libc::timespec {
            tv_sec: seconds as libc::time_t,
            tv_nsec: timeout.subsec_nanos() as libc::c_long,
        };
        let mut event = MaybeUninit::<libc::kevent>::uninit();
        let count = unsafe {
            libc::kevent(
                self.queue,
                std::ptr::null(),
                0,
                event.as_mut_ptr(),
                1,
                &raw const timeout,
            )
        };
        if count < 0 {
            return Err(LaunchGuardError::LiveIdentity(format!(
                "NOTE_EXEC wait failed: {}",
                std::io::Error::last_os_error()
            )));
        }
        if count == 0 {
            return Ok(None);
        }
        let event = unsafe { event.assume_init() };
        if event.ident != self.pid as libc::uintptr_t
            || event.filter != libc::EVFILT_PROC
            || event.flags & libc::EV_ERROR != 0
        {
            return Err(LaunchGuardError::LiveIdentity(
                "unexpected NOTE_EXEC event identity or error".to_string(),
            ));
        }
        let exec = event.fflags & libc::NOTE_EXEC != 0;
        let exit = event.fflags & libc::NOTE_EXIT != 0;
        match (exec, exit) {
            (true, true) => Ok(Some(MacProcessEvent::ExecAndExit)),
            (true, false) => Ok(Some(MacProcessEvent::Exec)),
            (false, true) => Ok(Some(MacProcessEvent::Exit)),
            (false, false) => Err(LaunchGuardError::LiveIdentity(
                "process watcher returned no requested event".to_string(),
            )),
        }
    }
}

impl Drop for MacProcessEventWatcher {
    fn drop(&mut self) {
        unsafe { libc::close(self.queue) };
    }
}
