#![allow(clippy::expect_used)]

#[cfg(target_os = "macos")]
mod macos {
    use codex_sandboxing::RbOuterOmpSeatbeltRequest;
    use codex_sandboxing::create_rb_outer_omp_seatbelt_command;
    use codex_sandboxing::rb_outer_omp_current_macos_build;
    use codex_utils_absolute_path::AbsolutePathBuf;
    use pretty_assertions::assert_eq;
    use std::fs;
    use std::io::Read;
    use std::net::TcpListener;
    use std::os::fd::AsRawFd;
    use std::os::fd::FromRawFd;
    use std::os::unix::fs::PermissionsExt;
    use std::os::unix::net::UnixListener;
    use std::os::unix::net::UnixStream;
    use std::os::unix::process::CommandExt;
    use std::os::unix::process::ExitStatusExt;
    use std::path::Path;
    use std::path::PathBuf;
    use std::process::Command;
    use tempfile::TempDir;

    fn absolute(path: impl AsRef<Path>) -> AbsolutePathBuf {
        AbsolutePathBuf::from_absolute_path(
            path.as_ref()
                .canonicalize()
                .expect("canonical fixture path"),
        )
        .expect("absolute fixture path")
    }

    fn compile(
        executable: &Path,
        command: &[String],
        session_root: &AbsolutePathBuf,
        forbidden_roots: &[AbsolutePathBuf],
        inherited_fds: &[i32],
    ) -> codex_sandboxing::RbOuterOmpSeatbeltCommand {
        let executable = absolute(executable);
        let runtime_root = absolute(executable.as_path().parent().expect("executable parent"));
        let build = rb_outer_omp_current_macos_build().expect("current macOS build");
        create_rb_outer_omp_seatbelt_command(RbOuterOmpSeatbeltRequest {
            command,
            verified_executable: &executable,
            signed_runtime_read_roots: std::slice::from_ref(&runtime_root),
            session_read_write_roots: std::slice::from_ref(session_root),
            forbidden_roots,
            inherited_fds,
            rendezvous: codex_sandboxing::RbOuterOmpRendezvous::DenyAll,
            expected_macos_build: &build,
            expected_arch: codex_sandboxing::rb_outer_omp_current_arch()
                .expect("current architecture"),
        })
        .expect("compile world-effect profile")
    }

    #[test]
    fn rb_outer_omp_world_effects_are_confined_without_skipping_apply_failures() {
        const CHILD_ENV: &str = "RB_OUTER_WORLD_PROBE_CHILD";
        const PROBE_FD_ENV: &str = "RB_OUTER_WORLD_PROBE_FD";
        const RUNTIME_FILE_ENV: &str = "RB_OUTER_RUNTIME_FILE";
        const SESSION_ROOT_ENV: &str = "RB_OUTER_SESSION_ROOT";
        const WORKSPACE_SECRET_ENV: &str = "RB_OUTER_WORKSPACE_SECRET";
        const OUTSIDE_SECRET_ENV: &str = "RB_OUTER_OUTSIDE_SECRET";
        const SHARED_TMP_ENV: &str = "RB_OUTER_SHARED_TMP";
        const TCP_ADDRESS_ENV: &str = "RB_OUTER_TCP_ADDRESS";

        if std::env::var(CHILD_ENV).as_deref() == Ok("1") {
            let marker_fd = std::env::var(PROBE_FD_ENV)
                .expect("marker fd")
                .parse::<i32>()
                .expect("numeric marker fd");
            let marker = b"started";
            let written = unsafe {
                libc::write(
                    marker_fd,
                    marker.as_ptr().cast(),
                    marker.len() as libc::size_t,
                )
            };
            if written != marker.len() as isize {
                unsafe { libc::_exit(90) };
            }
            let runtime = std::env::var(RUNTIME_FILE_ENV).expect("runtime file");
            if fs::read(runtime).is_err() {
                unsafe { libc::_exit(91) };
            }
            let session_effect =
                PathBuf::from(std::env::var(SESSION_ROOT_ENV).expect("session root"))
                    .join("effect.txt");
            if fs::write(&session_effect, "session-effect").is_err()
                || !matches!(
                    fs::read_to_string(&session_effect),
                    Ok(value) if value == "session-effect"
                )
            {
                unsafe { libc::_exit(92) };
            }
            for forbidden in [WORKSPACE_SECRET_ENV, OUTSIDE_SECRET_ENV] {
                if fs::read(std::env::var(forbidden).expect("forbidden path")).is_ok() {
                    unsafe { libc::_exit(93) };
                }
            }
            if fs::write(
                std::env::var(SHARED_TMP_ENV).expect("shared temp path"),
                "effect",
            )
            .is_ok()
            {
                unsafe { libc::_exit(94) };
            }
            let tcp_address = std::env::var(TCP_ADDRESS_ENV).expect("TCP address");
            if std::net::TcpStream::connect(tcp_address).is_ok() {
                unsafe { libc::_exit(95) };
            }
            let fork_result = unsafe { libc::fork() };
            if fork_result >= 0 {
                unsafe { libc::_exit(96) };
            }
            let success = b"RB_OUTER_WORLD_OK";
            if unsafe {
                libc::write(
                    libc::STDOUT_FILENO,
                    success.as_ptr().cast(),
                    success.len() as libc::size_t,
                )
            } != success.len() as isize
            {
                unsafe { libc::_exit(97) };
            }
            unsafe { libc::_exit(0) };
        }

        let session = TempDir::new().expect("session root");
        let workspace = TempDir::new().expect("workspace root");
        let fake_home = TempDir::new().expect("fake home root");
        let outside = TempDir::new().expect("outside root");
        let session_root = absolute(session.path());
        let workspace_root = absolute(workspace.path());
        let fake_home_root = absolute(fake_home.path());
        let forbidden_roots = vec![workspace_root, fake_home_root];

        let workspace_secret = workspace.path().join("workspace-secret.txt");
        fs::write(&workspace_secret, "workspace-secret").expect("workspace fixture");
        let outside_secret = outside.path().join("outside-secret.txt");
        fs::write(&outside_secret, "outside-secret").expect("outside fixture");
        let shared_tmp_target = PathBuf::from(format!(
            "/private/tmp/rb-outer-omp-shared-{}-{}",
            std::process::id(),
            session
                .path()
                .file_name()
                .unwrap_or_default()
                .to_str()
                .expect("UTF-8 temporary directory")
        ));
        let _ = fs::remove_file(&shared_tmp_target);
        let tcp_listener = TcpListener::bind("127.0.0.1:0").expect("loopback listener");

        let mut capability_pipe = [0; 2];
        assert_eq!(unsafe { libc::pipe(capability_pipe.as_mut_ptr()) }, 0);
        let mut capability_read = unsafe { fs::File::from_raw_fd(capability_pipe[0]) };
        let capability_write = unsafe { fs::File::from_raw_fd(capability_pipe[1]) };
        let capability_fd = capability_write.as_raw_fd();

        let executable = std::env::current_exe().expect("current test executable");
        let executable_utf8 = executable.to_str().expect("UTF-8 test executable");
        let command = vec![
            executable_utf8.to_string(),
            "--exact".to_string(),
            "macos::rb_outer_omp_world_effects_are_confined_without_skipping_apply_failures"
                .to_string(),
            "--nocapture".to_string(),
        ];
        let compiled = compile(
            &executable,
            &command,
            &session_root,
            &forbidden_roots,
            &[capability_fd],
        );
        let tcp_address = tcp_listener.local_addr().expect("TCP address");
        let mut child = Command::new(&compiled.program);
        child
            .args(&compiled.args)
            .current_dir(session.path())
            .env_clear()
            .env(CHILD_ENV, "1")
            .env(PROBE_FD_ENV, capability_fd.to_string())
            .env(RUNTIME_FILE_ENV, &executable)
            .env(SESSION_ROOT_ENV, session_root.as_path())
            .env(
                WORKSPACE_SECRET_ENV,
                workspace_secret.canonicalize().expect("workspace secret"),
            )
            .env(
                OUTSIDE_SECRET_ENV,
                outside_secret.canonicalize().expect("outside secret"),
            )
            .env(SHARED_TMP_ENV, &shared_tmp_target)
            .env(TCP_ADDRESS_ENV, tcp_address.to_string());
        let preserved_fds = compiled.inherited_fds.clone();
        // SAFETY: the callback only invokes the fork-safe descriptor sweep.
        unsafe {
            child.pre_exec(move || {
                codex_utils_pty::pty::close_inherited_fds_except_strict(&preserved_fds)
            });
        }
        let output = child.output().expect("launch sandbox-exec");
        drop(capability_write);
        let mut capability_output = String::new();
        capability_read
            .read_to_string(&mut capability_output)
            .expect("capability pipe output");
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            !capability_output.is_empty(),
            "sandbox apply or child bootstrap failed before marker; status={:?}, signal={:?}, stderr={stderr}",
            output.status.code(),
            output.status.signal()
        );
        assert!(
            output.status.success(),
            "sandboxed world-effect probe failed; status={:?}, stdout={}, stderr={stderr}",
            output.status.code(),
            String::from_utf8_lossy(&output.stdout)
        );
        assert_eq!(capability_output, "started");
        assert!(
            output.stdout.ends_with(b"RB_OUTER_WORLD_OK"),
            "world probe did not reach terminal marker: {}",
            String::from_utf8_lossy(&output.stdout)
        );
        assert_eq!(
            fs::read_to_string(session.path().join("effect.txt")).expect("session effect"),
            "session-effect"
        );
        assert!(!shared_tmp_target.exists());
    }

    #[test]
    fn rb_outer_omp_named_unix_socket_is_denied_after_bootstrap() {
        const CHILD_ENV: &str = "RB_NAMED_UNIX_PROBE_CHILD";
        const MARKER_FD_ENV: &str = "RB_NAMED_UNIX_MARKER_FD";
        const SOCKET_PATH_ENV: &str = "RB_NAMED_UNIX_SOCKET_PATH";

        if std::env::var(CHILD_ENV).as_deref() == Ok("1") {
            let marker_fd = std::env::var(MARKER_FD_ENV)
                .expect("marker fd")
                .parse::<i32>()
                .expect("numeric marker fd");
            let marker = b"started";
            let bytes_written = unsafe {
                libc::write(
                    marker_fd,
                    marker.as_ptr().cast(),
                    marker.len() as libc::size_t,
                )
            };
            if bytes_written != marker.len() as isize {
                unsafe { libc::_exit(93) };
            }
            let socket_path = std::env::var(SOCKET_PATH_ENV).expect("socket path");
            let connected = UnixStream::connect(socket_path).is_ok();
            unsafe { libc::_exit(if connected { 94 } else { 0 }) };
        }

        let session = TempDir::new().expect("session root");
        let outside = TempDir::new().expect("outside root");
        let session_root = absolute(session.path());
        let outside_root = absolute(outside.path());
        let forbidden_roots = vec![outside_root];
        let socket_path = outside.path().join("named.sock");
        let listener = UnixListener::bind(&socket_path).expect("Unix listener");
        listener
            .set_nonblocking(true)
            .expect("nonblocking Unix listener");

        let mut marker_pipe = [0; 2];
        assert_eq!(unsafe { libc::pipe(marker_pipe.as_mut_ptr()) }, 0);
        let mut marker_read = unsafe { fs::File::from_raw_fd(marker_pipe[0]) };
        let marker_write = unsafe { fs::File::from_raw_fd(marker_pipe[1]) };
        let marker_fd = marker_write.as_raw_fd();
        let executable = std::env::current_exe().expect("current test executable");
        let executable_utf8 = executable.to_str().expect("UTF-8 test executable");
        let command = vec![
            executable_utf8.to_string(),
            "--exact".to_string(),
            "macos::rb_outer_omp_named_unix_socket_is_denied_after_bootstrap".to_string(),
            "--nocapture".to_string(),
        ];
        let compiled = compile(
            &executable,
            &command,
            &session_root,
            &forbidden_roots,
            &[marker_fd],
        );
        let preserved_fds = compiled.inherited_fds.clone();
        let mut child = Command::new(compiled.program);
        child
            .args(compiled.args)
            .env_clear()
            .env(CHILD_ENV, "1")
            .env(MARKER_FD_ENV, marker_fd.to_string())
            .env(SOCKET_PATH_ENV, &socket_path);
        unsafe {
            child.pre_exec(move || {
                codex_utils_pty::pty::close_inherited_fds_except_strict(&preserved_fds)
            });
        }
        let output = child.output().expect("run named Unix probe");
        drop(marker_write);
        let mut marker = String::new();
        marker_read
            .read_to_string(&mut marker)
            .expect("bootstrap marker");
        assert!(
            !marker.is_empty(),
            "profile, loader, or child bootstrap failed before named Unix probe; status={:?}, signal={:?}, stderr={}",
            output.status.code(),
            output.status.signal(),
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(marker, "started");
        assert!(output.status.success(), "named Unix connect was not denied");
        assert!(matches!(
            listener.accept(),
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock
        ));
    }

    #[test]
    fn rb_outer_omp_allows_only_the_exact_rendezvous_connect_and_never_bind() {
        const CHILD_ENV: &str = "RB_EXACT_UNIX_CHILD";
        const MARKER_FD_ENV: &str = "RB_EXACT_UNIX_MARKER_FD";
        const EXACT_PATH_ENV: &str = "RB_EXACT_UNIX_PATH";
        const OTHER_PATH_ENV: &str = "RB_OTHER_UNIX_PATH";
        const BIND_PATH_ENV: &str = "RB_BIND_UNIX_PATH";

        if std::env::var(CHILD_ENV).as_deref() == Ok("1") {
            let marker_fd = std::env::var(MARKER_FD_ENV)
                .expect("marker fd")
                .parse::<i32>()
                .expect("numeric marker fd");
            if unsafe { libc::write(marker_fd, b"started".as_ptr().cast(), 7) } != 7 {
                unsafe { libc::_exit(90) };
            }
            let exact = std::env::var(EXACT_PATH_ENV).expect("exact path");
            let other = std::env::var(OTHER_PATH_ENV).expect("other path");
            let bind = std::env::var(BIND_PATH_ENV).expect("bind path");
            if UnixStream::connect(exact).is_err() {
                unsafe { libc::_exit(91) };
            }
            if UnixStream::connect(other).is_ok() {
                unsafe { libc::_exit(92) };
            }
            if UnixListener::bind(bind).is_ok() {
                unsafe { libc::_exit(93) };
            }
            unsafe { libc::_exit(0) };
        }

        let root = tempfile::Builder::new()
            .prefix("rbxu-")
            .tempdir_in("/private/tmp")
            .expect("short exact Unix fixture");
        let session = root.path().join("s");
        let rendezvous_dir = root.path().join("g");
        let forbidden = root.path().join("w");
        fs::create_dir(&session).expect("session root");
        fs::create_dir(&rendezvous_dir).expect("rendezvous root");
        fs::create_dir(&forbidden).expect("forbidden root");
        fs::set_permissions(&session, fs::Permissions::from_mode(0o700)).expect("session mode");
        fs::set_permissions(&rendezvous_dir, fs::Permissions::from_mode(0o700))
            .expect("rendezvous mode");
        let exact_path = rendezvous_dir.join("exact.sock");
        let other_path = rendezvous_dir.join("other.sock");
        let bind_path = session.join("forbidden-bind.sock");
        let exact_listener = UnixListener::bind(&exact_path).expect("exact listener");
        let other_listener = UnixListener::bind(&other_path).expect("other listener");
        exact_listener
            .set_nonblocking(true)
            .expect("exact nonblocking");
        other_listener
            .set_nonblocking(true)
            .expect("other nonblocking");

        let mut marker_pipe = [0; 2];
        assert_eq!(unsafe { libc::pipe(marker_pipe.as_mut_ptr()) }, 0);
        let mut marker_read = unsafe { fs::File::from_raw_fd(marker_pipe[0]) };
        let marker_write = unsafe { fs::File::from_raw_fd(marker_pipe[1]) };
        let marker_fd = marker_write.as_raw_fd();
        let executable = std::env::current_exe().expect("current test executable");
        let executable = absolute(&executable);
        let runtime_root = absolute(executable.as_path().parent().expect("executable parent"));
        let session_root = absolute(&session);
        let forbidden_root = absolute(&forbidden);
        let exact_socket =
            AbsolutePathBuf::from_absolute_path(exact_path.clone()).expect("absolute exact socket");
        let command = vec![
            executable
                .as_path()
                .to_str()
                .expect("UTF-8 executable")
                .to_string(),
            "--exact".to_string(),
            "macos::rb_outer_omp_allows_only_the_exact_rendezvous_connect_and_never_bind"
                .to_string(),
            "--nocapture".to_string(),
        ];
        let build = rb_outer_omp_current_macos_build().expect("current macOS build");
        let compiled = create_rb_outer_omp_seatbelt_command(RbOuterOmpSeatbeltRequest {
            command: &command,
            verified_executable: &executable,
            signed_runtime_read_roots: std::slice::from_ref(&runtime_root),
            session_read_write_roots: std::slice::from_ref(&session_root),
            forbidden_roots: std::slice::from_ref(&forbidden_root),
            inherited_fds: &[marker_fd],
            rendezvous: codex_sandboxing::RbOuterOmpRendezvous::ConnectExact(&exact_socket),
            expected_macos_build: &build,
            expected_arch: codex_sandboxing::rb_outer_omp_current_arch()
                .expect("current architecture"),
        })
        .expect("compile exact-connect profile");
        let policy = compiled
            .args
            .windows(2)
            .find_map(|pair| (pair[0] == "-p").then_some(pair[1].as_str()))
            .expect("compiled policy");
        assert!(policy.contains("(allow system-socket (socket-domain AF_UNIX))"));
        assert!(policy.contains(
            "(allow network-outbound (remote unix-socket (literal (param \"RB_RENDEZVOUS_SOCKET\"))))"
        ));
        assert!(!policy.contains("network-bind"));
        assert!(!policy.contains("subpath (param \"RB_RENDEZVOUS_SOCKET\")"));

        let preserved_fds = compiled.inherited_fds.clone();
        let mut child = Command::new(compiled.program);
        child
            .args(compiled.args)
            .env_clear()
            .env(CHILD_ENV, "1")
            .env(MARKER_FD_ENV, marker_fd.to_string())
            .env(EXACT_PATH_ENV, &exact_path)
            .env(OTHER_PATH_ENV, &other_path)
            .env(BIND_PATH_ENV, &bind_path);
        unsafe {
            child.pre_exec(move || {
                codex_utils_pty::pty::close_inherited_fds_except_strict(&preserved_fds)
            });
        }
        let output = child.output().expect("run exact Unix probe");
        drop(marker_write);
        let mut marker = String::new();
        marker_read
            .read_to_string(&mut marker)
            .expect("bootstrap marker");
        assert_eq!(marker, "started");
        assert!(
            output.status.success(),
            "exact-connect probe failed: status={:?}, stderr={}",
            output.status.code(),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(exact_listener.accept().is_ok());
        assert!(matches!(
            other_listener.accept(),
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock
        ));
        assert!(!bind_path.exists());
    }
}

#[cfg(not(target_os = "macos"))]
#[test]
fn rb_outer_omp_reports_non_macos_as_unsupported() {
    assert!(matches!(
        codex_sandboxing::rb_outer_omp_current_macos_build(),
        Err(codex_sandboxing::RbOuterOmpPreparationError::UnsupportedPlatform)
    ));
}
