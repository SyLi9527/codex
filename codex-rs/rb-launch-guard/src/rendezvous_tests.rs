use super::*;
use pretty_assertions::assert_eq;
use std::os::unix::fs::MetadataExt;
use std::os::unix::fs::PermissionsExt;

fn private_root() -> tempfile::TempDir {
    let root = tempfile::Builder::new()
        .prefix("rbrv-")
        .tempdir_in("/private/tmp")
        .expect("short rendezvous root");
    fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).expect("private root mode");
    root
}

#[test]
fn one_shot_rendezvous_is_random_private_and_removed_after_consume() {
    let root = private_root();
    let metadata = root.path().metadata().expect("root metadata");
    let mut first = OneShotRendezvous::create(root.path(), metadata.dev(), metadata.ino())
        .expect("first rendezvous");
    let first_path = first.socket_path().to_path_buf();
    let first_metadata = first_path.metadata().expect("first socket metadata");
    assert_eq!(first_metadata.permissions().mode() & 0o777, 0o600);
    assert_eq!(
        first_path
            .parent()
            .expect("launch dir")
            .metadata()
            .expect("launch dir metadata")
            .permissions()
            .mode()
            & 0o777,
        0o700
    );
    first.consume().expect("consume first rendezvous");
    drop(first);
    assert!(!first_path.exists());
    assert_eq!(fs::read_dir(root.path()).expect("root entries").count(), 0);

    let second = OneShotRendezvous::create(root.path(), metadata.dev(), metadata.ino())
        .expect("second rendezvous");
    assert_ne!(second.socket_path(), first_path);
}

#[test]
fn socket_replacement_and_launch_directory_mode_drift_fail_closed() {
    let root = private_root();
    let metadata = root.path().metadata().expect("root metadata");
    let mut replaced = OneShotRendezvous::create(root.path(), metadata.dev(), metadata.ino())
        .expect("replacement rendezvous");
    let replaced_path = replaced.socket_path().to_path_buf();
    fs::remove_file(&replaced_path).expect("unlink original socket");
    fs::write(&replaced_path, b"replacement").expect("regular-file replacement");
    assert!(matches!(
        replaced.consume(),
        Err(LaunchGuardError::IdentityDrift(_))
    ));
    drop(replaced);

    let root = private_root();
    let metadata = root.path().metadata().expect("root metadata");
    let mut drifted = OneShotRendezvous::create(root.path(), metadata.dev(), metadata.ino())
        .expect("mode-drift rendezvous");
    let launch_dir = drifted
        .socket_path()
        .parent()
        .expect("launch dir")
        .to_path_buf();
    fs::set_permissions(&launch_dir, fs::Permissions::from_mode(0o755)).expect("drift launch mode");
    assert!(matches!(
        drifted.consume(),
        Err(LaunchGuardError::IdentityDrift(_))
    ));
}
