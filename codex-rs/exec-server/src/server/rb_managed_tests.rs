use codex_file_system::ExecFileSystemPath;
use codex_file_system::ExecFileSystemSandboxEntry;
use codex_file_system::ExecManagedFileSystemPermissions;
use codex_file_system::ExecPermissionProfile;
use codex_file_system::FileSystemSandboxContext;
use codex_protocol::config_types::WindowsSandboxLevel;
use codex_protocol::permissions::FileSystemAccessMode;
use codex_protocol::permissions::NetworkSandboxPolicy;
use codex_utils_path_uri::PathUri;
use pretty_assertions::assert_eq;

use super::RbManagedConfigError;
use super::RbManagedServerConfig;

fn context(permissions: ExecPermissionProfile) -> FileSystemSandboxContext {
    let root = PathUri::from_host_native_path(std::env::temp_dir().join("rb-managed-workspace"))
        .expect("absolute workspace URI");
    FileSystemSandboxContext {
        permissions,
        cwd: Some(root.clone()),
        workspace_roots: vec![root],
        temporary_directories: None,
        windows_sandbox_level: WindowsSandboxLevel::Disabled,
        windows_sandbox_private_desktop: false,
        windows_sandbox_proxy_settings_mode: None,
        use_legacy_landlock: false,
    }
}

fn restricted_permissions() -> ExecPermissionProfile {
    let root = PathUri::from_host_native_path(std::env::temp_dir().join("rb-managed-workspace"))
        .expect("absolute workspace URI");
    ExecPermissionProfile::Managed {
        file_system: ExecManagedFileSystemPermissions::Restricted {
            entries: vec![ExecFileSystemSandboxEntry {
                path: ExecFileSystemPath::Path { path: root },
                access: FileSystemAccessMode::Read,
                missing_path_behavior: None,
            }],
            glob_scan_max_depth: None,
        },
        network: NetworkSandboxPolicy::Restricted,
    }
}

#[test]
fn accepts_only_restricted_managed_exact_roots() {
    RbManagedServerConfig::try_new(context(restricted_permissions()))
        .expect("restricted exact managed policy should be accepted");

    let unrestricted = context(ExecPermissionProfile::Managed {
        file_system: ExecManagedFileSystemPermissions::Unrestricted,
        network: NetworkSandboxPolicy::Restricted,
    });
    assert_eq!(
        RbManagedServerConfig::try_new(unrestricted).expect_err("unrestricted filesystem"),
        RbManagedConfigError::NonRestrictedFileSystem
    );

    let disabled = context(ExecPermissionProfile::Disabled);
    assert_eq!(
        RbManagedServerConfig::try_new(disabled).expect_err("disabled profile"),
        RbManagedConfigError::NonRestrictedFileSystem
    );
}

#[test]
fn rejects_glob_and_special_policy_entries() {
    let permissions = ExecPermissionProfile::Managed {
        file_system: ExecManagedFileSystemPermissions::Restricted {
            entries: vec![ExecFileSystemSandboxEntry {
                path: ExecFileSystemPath::GlobPattern {
                    pattern: "**".to_string(),
                },
                access: FileSystemAccessMode::Read,
                missing_path_behavior: None,
            }],
            glob_scan_max_depth: None,
        },
        network: NetworkSandboxPolicy::Restricted,
    };
    assert_eq!(
        RbManagedServerConfig::try_new(context(permissions)).expect_err("glob policy entry"),
        RbManagedConfigError::NonExactFileSystemPath
    );
}

#[test]
fn rejects_enabled_network_and_missing_workspace_roots() {
    let enabled_network = context(ExecPermissionProfile::Managed {
        file_system: ExecManagedFileSystemPermissions::Restricted {
            entries: Vec::new(),
            glob_scan_max_depth: None,
        },
        network: NetworkSandboxPolicy::Enabled,
    });
    assert_eq!(
        RbManagedServerConfig::try_new(enabled_network).expect_err("enabled network"),
        RbManagedConfigError::NonRestrictedNetwork
    );

    let mut missing_roots = context(restricted_permissions());
    missing_roots.workspace_roots.clear();
    assert_eq!(
        RbManagedServerConfig::try_new(missing_roots).expect_err("missing workspace roots"),
        RbManagedConfigError::MissingRoot
    );
}
