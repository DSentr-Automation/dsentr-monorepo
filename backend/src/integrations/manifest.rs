#[derive(Debug, Clone)]
pub struct IntegrationManifest {
    pub integration_id: String,
    pub auth_type: IntegrationAuthType,
    pub token_scope: TokenScope,
    pub ownership_model: OwnershipModel,
    pub provider_constraints: ProviderConstraints,
    pub ui_metadata: UiMetadata,
    pub oauth_metadata: Option<OAuthMetadata>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IntegrationAuthType {
    OAuth2,
    ApiKey,
    None,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenScope {
    Personal,
    Workspace,
    PersonalAndWorkspace,
}

impl TokenScope {
    pub fn supports_personal(self) -> bool {
        matches!(
            self,
            TokenScope::Personal | TokenScope::PersonalAndWorkspace
        )
    }

    pub fn supports_workspace(self) -> bool {
        matches!(
            self,
            TokenScope::Workspace | TokenScope::PersonalAndWorkspace
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OwnershipModel {
    PersonalOnly,
    WorkspaceOnly,
    Hybrid,
}

impl OwnershipModel {
    pub fn supports_personal(self) -> bool {
        matches!(self, OwnershipModel::PersonalOnly | OwnershipModel::Hybrid)
    }

    pub fn supports_workspace(self) -> bool {
        matches!(self, OwnershipModel::WorkspaceOnly | OwnershipModel::Hybrid)
    }
}

#[derive(Debug, Clone)]
pub struct ProviderConstraints {
    pub workspace_first: bool,
    pub single_install_per_workspace: bool,
}

#[derive(Debug, Clone)]
pub struct UiMetadata {
    pub display_name: String,
    pub description: String,
    pub icon_key: Option<String>,
    pub docs_url: Option<String>,
}

#[derive(Debug, Clone)]
pub struct OAuthMetadata {
    pub scopes: Vec<String>,
    pub github_app: bool,
    pub user_tokens_optional: bool,
    pub installation_scoped: bool,
}
