use codex_file_system::ExecFileSystemPath;
use codex_file_system::ExecManagedFileSystemPermissions;
use codex_file_system::ExecPermissionProfile;
use codex_file_system::FileSystemSandboxContext;
use codex_protocol::permissions::NetworkSandboxPolicy;
use thiserror::Error;

/// Server-owned filesystem policy for the ResearchBuddy managed stdio protocol.
///
/// The policy is supplied by the trusted launcher, never by an RPC request. The
/// initial feasibility build deliberately exposes no filesystem methods: the
/// stock helper profile still permits child processes, and macOS pathname
/// confinement has not yet passed the required race gate.
#[derive(Clone, Debug)]
pub struct RbManagedServerConfig {
    pub(crate) sandbox: FileSystemSandboxContext,
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum RbManagedConfigError {
    #[error("RB managed mode requires a restricted managed filesystem profile")]
    NonRestrictedFileSystem,
    #[error("RB managed mode requires network access to be restricted")]
    NonRestrictedNetwork,
    #[error("RB managed mode accepts only absolute, exact filesystem paths")]
    NonExactFileSystemPath,
    #[error("RB managed mode requires at least one exact workspace or approved root")]
    MissingRoot,
    #[error("RB managed mode requires every workspace root to be host-native and absolute")]
    InvalidWorkspaceRoot,
}

impl RbManagedServerConfig {
    pub fn try_new(sandbox: FileSystemSandboxContext) -> Result<Self, RbManagedConfigError> {
        let ExecPermissionProfile::Managed {
            file_system: ExecManagedFileSystemPermissions::Restricted { entries, .. },
            network,
        } = &sandbox.permissions
        else {
            return Err(RbManagedConfigError::NonRestrictedFileSystem);
        };
        if *network != NetworkSandboxPolicy::Restricted {
            return Err(RbManagedConfigError::NonRestrictedNetwork);
        }
        if entries.iter().any(|entry| {
            !matches!(
                &entry.path,
                ExecFileSystemPath::Path { path } if path.to_abs_path().is_ok()
            )
        }) {
            return Err(RbManagedConfigError::NonExactFileSystemPath);
        }
        if sandbox.workspace_roots.is_empty() {
            return Err(RbManagedConfigError::MissingRoot);
        }
        if sandbox
            .workspace_roots
            .iter()
            .any(|root| root.to_abs_path().is_err())
        {
            return Err(RbManagedConfigError::InvalidWorkspaceRoot);
        }
        Ok(Self { sandbox })
    }

    pub fn sandbox(&self) -> &FileSystemSandboxContext {
        &self.sandbox
    }
}

#[derive(Clone, Debug)]
pub(crate) enum ServerProtocol {
    Standard,
    RbManaged(RbManagedServerConfig),
}

impl ServerProtocol {
    pub(crate) fn rb_managed_config(&self) -> Option<&RbManagedServerConfig> {
        match self {
            Self::Standard => None,
            Self::RbManaged(config) => Some(config),
        }
    }
}

#[cfg(test)]
#[path = "rb_managed_tests.rs"]
mod tests;
