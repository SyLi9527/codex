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

use super::build_router;
use crate::protocol::ENVIRONMENT_STATUS_METHOD;
use crate::protocol::INITIALIZE_METHOD;
use crate::protocol::INITIALIZED_METHOD;
use crate::server::rb_managed::RbManagedServerConfig;
use crate::server::rb_managed::ServerProtocol;

fn managed_protocol() -> ServerProtocol {
    let root = PathUri::from_host_native_path(std::env::temp_dir().join("rb-managed-workspace"))
        .expect("absolute workspace URI");
    let sandbox = FileSystemSandboxContext {
        permissions: ExecPermissionProfile::Managed {
            file_system: ExecManagedFileSystemPermissions::Restricted {
                entries: vec![ExecFileSystemSandboxEntry {
                    path: ExecFileSystemPath::Path { path: root.clone() },
                    access: FileSystemAccessMode::Read,
                    missing_path_behavior: None,
                }],
                glob_scan_max_depth: None,
            },
            network: NetworkSandboxPolicy::Restricted,
        },
        cwd: Some(root.clone()),
        workspace_roots: vec![root],
        temporary_directories: None,
        windows_sandbox_level: WindowsSandboxLevel::Disabled,
        windows_sandbox_private_desktop: false,
        windows_sandbox_proxy_settings_mode: None,
        use_legacy_landlock: false,
    };
    ServerProtocol::RbManaged(
        RbManagedServerConfig::try_new(sandbox).expect("managed server config"),
    )
}

#[test]
fn managed_router_exposes_only_handshake_and_status() {
    let router = build_router(&managed_protocol());
    assert_eq!(
        router.request_method_names(),
        vec![ENVIRONMENT_STATUS_METHOD, INITIALIZE_METHOD]
    );
    assert_eq!(router.notification_method_names(), vec![INITIALIZED_METHOD]);
}
