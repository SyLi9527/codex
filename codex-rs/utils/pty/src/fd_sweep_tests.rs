use super::*;
use pretty_assertions::assert_eq;
use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::io::Read;
use std::os::fd::AsRawFd;
use std::os::fd::FromRawFd;
use std::os::unix::process::CommandExt;
use std::process::Command;

struct FakeStrictFdSweepSyscalls {
    inventory: StrictFdInventory,
    inventory_errno: Option<i32>,
    open_fds: BTreeMap<RawFd, libc::c_int>,
    fd_flags_errno: Option<(RawFd, i32)>,
    close_errno: Option<(RawFd, i32)>,
    nofile_limit: RawFd,
    nofile_errno: Option<i32>,
    closed: BTreeSet<RawFd>,
}

impl FakeStrictFdSweepSyscalls {
    fn complete(fd: RawFd) -> Self {
        let mut open_fds = BTreeMap::from([
            (libc::STDIN_FILENO, 0),
            (libc::STDOUT_FILENO, 0),
            (libc::STDERR_FILENO, 0),
        ]);
        open_fds.insert(fd, 0);
        Self {
            inventory: StrictFdInventory::Complete(1),
            inventory_errno: None,
            open_fds,
            fd_flags_errno: None,
            close_errno: None,
            nofile_limit: 32,
            nofile_errno: None,
            closed: BTreeSet::new(),
        }
    }

    fn saturated() -> Self {
        let mut syscalls = Self::complete(10);
        syscalls.inventory = StrictFdInventory::Saturated;
        syscalls
    }
}

impl StrictFdSweepSyscalls for FakeStrictFdSweepSyscalls {
    fn enumerate(
        &mut self,
        descriptors: &mut [libc::proc_fdinfo],
    ) -> std::io::Result<StrictFdInventory> {
        if let Some(errno) = self.inventory_errno {
            return Err(std::io::Error::from_raw_os_error(errno));
        }
        if self.inventory == StrictFdInventory::Complete(1) {
            descriptors[0].proc_fd = 10;
        }
        Ok(self.inventory)
    }

    fn fd_flags(&mut self, fd: RawFd) -> std::io::Result<Option<libc::c_int>> {
        if let Some((failed_fd, errno)) = self.fd_flags_errno
            && fd == failed_fd
        {
            return Err(std::io::Error::from_raw_os_error(errno));
        }
        Ok(self.open_fds.get(&fd).copied())
    }

    fn close_fd(&mut self, fd: RawFd) -> std::io::Result<()> {
        if let Some((failed_fd, errno)) = self.close_errno
            && fd == failed_fd
        {
            return Err(std::io::Error::from_raw_os_error(errno));
        }
        self.closed.insert(fd);
        self.open_fds.remove(&fd);
        Ok(())
    }

    fn nofile_limit(&mut self) -> std::io::Result<RawFd> {
        if let Some(errno) = self.nofile_errno {
            return Err(std::io::Error::from_raw_os_error(errno));
        }
        Ok(self.nofile_limit)
    }
}

#[test]
fn strict_launcher_sweep_aborts_on_each_syscall_failure_path() {
    let mut enumeration_failure = FakeStrictFdSweepSyscalls::complete(10);
    enumeration_failure.inventory_errno = Some(libc::EIO);

    let mut listed_fcntl_failure = FakeStrictFdSweepSyscalls::complete(10);
    listed_fcntl_failure.fd_flags_errno = Some((10, libc::EIO));

    let mut close_failure = FakeStrictFdSweepSyscalls::complete(10);
    close_failure.close_errno = Some((10, libc::EIO));

    let mut limit_failure = FakeStrictFdSweepSyscalls::saturated();
    limit_failure.nofile_errno = Some(libc::EIO);

    let mut fallback_fcntl_failure = FakeStrictFdSweepSyscalls::saturated();
    fallback_fcntl_failure.fd_flags_errno = Some((3, libc::EIO));

    for (label, mut syscalls) in [
        ("proc_pidinfo", enumeration_failure),
        ("listed fcntl", listed_fcntl_failure),
        ("close", close_failure),
        ("getrlimit", limit_failure),
        ("fallback fcntl", fallback_fcntl_failure),
    ] {
        let error = close_inherited_fds_except_strict_with(&[], &mut syscalls)
            .expect_err("strict launcher must abort exec");
        assert_eq!(error.raw_os_error(), Some(libc::EIO), "{label}");
    }
}

#[test]
fn strict_launcher_sweep_rejects_a_preserved_descriptor_that_exec_would_close() {
    let mut syscalls = FakeStrictFdSweepSyscalls::complete(10);
    syscalls.open_fds.insert(10, libc::FD_CLOEXEC);
    let error = close_inherited_fds_except_strict_with(&[10], &mut syscalls)
        .expect_err("preserved descriptor must survive exec");
    assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
}

#[test]
fn strict_launcher_sweep_leaves_exact_inventory_after_exec() -> anyhow::Result<()> {
    const CHILD_ENV: &str = "CODEX_STRICT_FD_INVENTORY_CHILD";
    const PRESERVED_FD_ENV: &str = "CODEX_STRICT_FD_PRESERVED";

    if std::env::var(CHILD_ENV).as_deref() == Ok("1") {
        let preserved_fd = std::env::var(PRESERVED_FD_ENV)?.parse::<RawFd>()?;
        let mut actual = Vec::new();
        for fd in 0..8192 {
            if unsafe { libc::fcntl(fd, libc::F_GETFD) } >= 0 {
                actual.push(fd);
            }
        }
        let expected = vec![
            libc::STDIN_FILENO,
            libc::STDOUT_FILENO,
            libc::STDERR_FILENO,
            preserved_fd,
        ];
        let message = if actual == expected {
            "exact".to_string()
        } else {
            format!("unexpected:{actual:?}")
        };
        unsafe {
            libc::write(
                preserved_fd,
                message.as_ptr().cast(),
                message.len() as libc::size_t,
            );
            libc::_exit(if actual == expected { 0 } else { 91 });
        }
    }

    let mut pipe_fds = [0; 2];
    if unsafe { libc::pipe(pipe_fds.as_mut_ptr()) } != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    let mut read_end = unsafe { std::fs::File::from_raw_fd(pipe_fds[0]) };
    let write_end = unsafe { std::fs::File::from_raw_fd(pipe_fds[1]) };
    let preserved_fd = write_end.as_raw_fd();

    let mut child = Command::new(std::env::current_exe()?);
    child
        .args([
            "--exact",
            "pty::fd_sweep_tests::strict_launcher_sweep_leaves_exact_inventory_after_exec",
            "--nocapture",
        ])
        .env(CHILD_ENV, "1")
        .env(PRESERVED_FD_ENV, preserved_fd.to_string());
    unsafe {
        child.pre_exec(move || close_inherited_fds_except_strict(&[preserved_fd]));
    }
    let output = child.output()?;
    drop(write_end);

    let mut inventory = String::new();
    read_end.read_to_string(&mut inventory)?;
    assert!(
        output.status.success(),
        "strict inventory child failed: status={:?}, inventory={inventory}, stderr={}",
        output.status.code(),
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(inventory, "exact");
    Ok(())
}
