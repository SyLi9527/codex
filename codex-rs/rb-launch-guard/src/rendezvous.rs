use crate::LaunchGuardError;
use std::fs;
use std::fs::File;
use std::os::unix::fs::DirBuilderExt;
use std::os::unix::fs::FileTypeExt;
use std::os::unix::fs::MetadataExt;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixListener;
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::path::PathBuf;
use std::time::Duration;
use std::time::Instant;

const MAX_ACCEPT_ATTEMPTS: usize = 4;

pub(crate) struct OneShotRendezvous {
    listener: Option<UnixListener>,
    launch_dir: PathBuf,
    launch_dir_device: u64,
    launch_dir_inode: u64,
    socket_path: PathBuf,
    socket_device: u64,
    socket_inode: u64,
    consumed: bool,
}

impl OneShotRendezvous {
    pub(crate) fn create(
        root: &Path,
        expected_device: u64,
        expected_inode: u64,
    ) -> Result<Self, LaunchGuardError> {
        verify_private_root(root, expected_device, expected_inode)?;
        let launch_dir = root.join(format!("launch-{}", random_hex_128()?));
        let mut builder = fs::DirBuilder::new();
        builder.mode(0o700);
        builder
            .create(&launch_dir)
            .map_err(|error| LaunchGuardError::Io(error.to_string()))?;
        let launch_dir_metadata = launch_dir
            .metadata()
            .map_err(|error| LaunchGuardError::Io(error.to_string()))?;
        verify_private_root(
            &launch_dir,
            launch_dir_metadata.dev(),
            launch_dir_metadata.ino(),
        )?;

        // The per-launch directory already carries 128 bits of randomness. Keep
        // the leaf fixed so the complete sockaddr_un remains below SUN_LEN.
        let socket_path = launch_dir.join("r.sock");
        if socket_path.symlink_metadata().is_ok() {
            return Err(LaunchGuardError::InvalidPath(
                "rendezvous socket path already exists".to_string(),
            ));
        }
        let listener = UnixListener::bind(&socket_path)
            .map_err(|error| LaunchGuardError::Io(error.to_string()))?;
        fs::set_permissions(&socket_path, fs::Permissions::from_mode(0o600))
            .map_err(|error| LaunchGuardError::Io(error.to_string()))?;
        let metadata = socket_path
            .symlink_metadata()
            .map_err(|error| LaunchGuardError::Io(error.to_string()))?;
        if metadata.file_type().is_symlink()
            || !metadata.file_type().is_socket()
            || metadata.uid() != unsafe { libc::geteuid() }
            || metadata.permissions().mode() & 0o777 != 0o600
        {
            return Err(LaunchGuardError::InvalidPath(
                "rendezvous endpoint is not an euid-owned 0600 Unix socket".to_string(),
            ));
        }
        sync_directory(&launch_dir)?;
        verify_private_root(root, expected_device, expected_inode)?;
        Ok(Self {
            listener: Some(listener),
            launch_dir,
            launch_dir_device: launch_dir_metadata.dev(),
            launch_dir_inode: launch_dir_metadata.ino(),
            socket_path,
            socket_device: metadata.dev(),
            socket_inode: metadata.ino(),
            consumed: false,
        })
    }

    pub(crate) fn socket_path(&self) -> &Path {
        &self.socket_path
    }

    pub(crate) fn accept(&self, timeout: Duration) -> Result<UnixStream, LaunchGuardError> {
        let listener = self.listener.as_ref().ok_or_else(|| {
            LaunchGuardError::LiveIdentity("rendezvous listener is closed".to_string())
        })?;
        listener
            .set_nonblocking(true)
            .map_err(|error| LaunchGuardError::Io(error.to_string()))?;
        let deadline = Instant::now()
            .checked_add(timeout)
            .ok_or_else(|| LaunchGuardError::LiveIdentity("accept timeout overflow".to_string()))?;
        let mut attempts = 0;
        loop {
            match listener.accept() {
                Ok((stream, _)) => {
                    attempts += 1;
                    if attempts > MAX_ACCEPT_ATTEMPTS {
                        return Err(LaunchGuardError::LiveIdentity(
                            "rendezvous accept attempt ceiling exceeded".to_string(),
                        ));
                    }
                    stream
                        .set_nonblocking(false)
                        .map_err(|error| LaunchGuardError::Io(error.to_string()))?;
                    return Ok(stream);
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    if Instant::now() >= deadline {
                        return Err(LaunchGuardError::LiveIdentity(
                            "rendezvous accept timed out".to_string(),
                        ));
                    }
                    std::thread::sleep(Duration::from_millis(2));
                }
                Err(error) => return Err(LaunchGuardError::Io(error.to_string())),
            }
        }
    }

    pub(crate) fn consume(&mut self) -> Result<(), LaunchGuardError> {
        verify_private_root(
            &self.launch_dir,
            self.launch_dir_device,
            self.launch_dir_inode,
        )?;
        verify_socket_identity(&self.socket_path, self.socket_device, self.socket_inode)?;
        self.listener.take();
        fs::remove_file(&self.socket_path)
            .map_err(|error| LaunchGuardError::Io(error.to_string()))?;
        sync_directory(&self.launch_dir)?;
        self.consumed = true;
        Ok(())
    }
}

impl Drop for OneShotRendezvous {
    fn drop(&mut self) {
        self.listener.take();
        if !self.consumed
            && verify_socket_identity(&self.socket_path, self.socket_device, self.socket_inode)
                .is_ok()
        {
            let _ = fs::remove_file(&self.socket_path);
            let _ = sync_directory(&self.launch_dir);
        }
        let _ = fs::remove_dir(&self.launch_dir);
    }
}

pub(crate) fn reject_buffered_pre_identity_bytes(
    stream: &UnixStream,
) -> Result<(), LaunchGuardError> {
    let mut available: libc::c_int = 0;
    if unsafe { libc::ioctl(stream.as_raw_fd(), libc::FIONREAD, &raw mut available) } != 0 {
        return Err(LaunchGuardError::LiveIdentity(format!(
            "FIONREAD before identity failed: {}",
            std::io::Error::last_os_error()
        )));
    }
    if available != 0 {
        return Err(LaunchGuardError::LiveIdentity(
            "peer sent bytes before live identity".to_string(),
        ));
    }
    Ok(())
}

fn verify_private_root(
    path: &Path,
    expected_device: u64,
    expected_inode: u64,
) -> Result<(), LaunchGuardError> {
    let metadata = path
        .symlink_metadata()
        .map_err(|error| LaunchGuardError::InvalidPath(error.to_string()))?;
    let canonical = path
        .canonicalize()
        .map_err(|error| LaunchGuardError::InvalidPath(error.to_string()))?;
    if canonical != path
        || metadata.file_type().is_symlink()
        || !metadata.is_dir()
        || metadata.dev() != expected_device
        || metadata.ino() != expected_inode
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.permissions().mode() & 0o777 != 0o700
    {
        return Err(LaunchGuardError::IdentityDrift(
            "launch directory canonical identity/owner/mode drift".to_string(),
        ));
    }
    Ok(())
}

fn verify_socket_identity(
    path: &Path,
    expected_device: u64,
    expected_inode: u64,
) -> Result<(), LaunchGuardError> {
    let metadata = path
        .symlink_metadata()
        .map_err(|error| LaunchGuardError::IdentityDrift(error.to_string()))?;
    if metadata.file_type().is_symlink()
        || !metadata.file_type().is_socket()
        || metadata.dev() != expected_device
        || metadata.ino() != expected_inode
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.permissions().mode() & 0o777 != 0o600
    {
        return Err(LaunchGuardError::IdentityDrift(
            "rendezvous socket identity/owner/mode drift".to_string(),
        ));
    }
    Ok(())
}

fn sync_directory(path: &Path) -> Result<(), LaunchGuardError> {
    File::open(path)
        .and_then(|directory| directory.sync_all())
        .map_err(|error| LaunchGuardError::Io(error.to_string()))
}

pub(crate) fn random_hex_128() -> Result<String, LaunchGuardError> {
    let mut bytes = [0_u8; 16];
    if unsafe { libc::getentropy(bytes.as_mut_ptr().cast(), bytes.len()) } != 0 {
        return Err(LaunchGuardError::Io(format!(
            "getentropy failed: {}",
            std::io::Error::last_os_error()
        )));
    }
    Ok(bytes
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<Vec<_>>()
        .join(""))
}

use std::os::fd::AsRawFd;

#[cfg(test)]
#[path = "rendezvous_tests.rs"]
mod tests;
