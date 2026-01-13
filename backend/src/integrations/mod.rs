pub mod manifest;
pub mod registry;

use manifest::{
    IntegrationAuthType, IntegrationManifest, OAuthMetadata, OwnershipModel, ProviderConstraints,
    TokenScope, UiMetadata,
};
use registry::{IntegrationRegistry, IntegrationRegistryError};

pub fn build_integration_registry() -> Result<IntegrationRegistry, IntegrationRegistryError> {
    let manifests = vec![
        IntegrationManifest {
            integration_id: "google".to_string(),
            auth_type: IntegrationAuthType::OAuth2,
            token_scope: TokenScope::PersonalAndWorkspace,
            ownership_model: OwnershipModel::Hybrid,
            provider_constraints: ProviderConstraints {
                workspace_first: false,
                single_install_per_workspace: false,
            },
            ui_metadata: UiMetadata {
                display_name: "Google".to_string(),
                description: "Connect Google services for workflow steps.".to_string(),
                icon_key: Some("google".to_string()),
                docs_url: None,
            },
            oauth_metadata: Some(OAuthMetadata { scopes: Vec::new() }),
        },
        IntegrationManifest {
            integration_id: "microsoft".to_string(),
            auth_type: IntegrationAuthType::OAuth2,
            token_scope: TokenScope::PersonalAndWorkspace,
            ownership_model: OwnershipModel::Hybrid,
            provider_constraints: ProviderConstraints {
                workspace_first: false,
                single_install_per_workspace: false,
            },
            ui_metadata: UiMetadata {
                display_name: "Microsoft".to_string(),
                description: "Connect Microsoft 365 services for workflows.".to_string(),
                icon_key: Some("microsoft".to_string()),
                docs_url: None,
            },
            oauth_metadata: Some(OAuthMetadata { scopes: Vec::new() }),
        },
        IntegrationManifest {
            integration_id: "slack".to_string(),
            auth_type: IntegrationAuthType::OAuth2,
            token_scope: TokenScope::PersonalAndWorkspace,
            ownership_model: OwnershipModel::Hybrid,
            provider_constraints: ProviderConstraints {
                workspace_first: true,
                single_install_per_workspace: true,
            },
            ui_metadata: UiMetadata {
                display_name: "Slack".to_string(),
                description: "Send messages and automate Slack actions.".to_string(),
                icon_key: Some("slack".to_string()),
                docs_url: None,
            },
            oauth_metadata: Some(OAuthMetadata { scopes: Vec::new() }),
        },
        IntegrationManifest {
            integration_id: "asana".to_string(),
            auth_type: IntegrationAuthType::OAuth2,
            token_scope: TokenScope::PersonalAndWorkspace,
            ownership_model: OwnershipModel::Hybrid,
            provider_constraints: ProviderConstraints {
                workspace_first: false,
                single_install_per_workspace: false,
            },
            ui_metadata: UiMetadata {
                display_name: "Asana".to_string(),
                description: "Sync tasks and projects from Asana.".to_string(),
                icon_key: Some("asana".to_string()),
                docs_url: None,
            },
            oauth_metadata: Some(OAuthMetadata { scopes: Vec::new() }),
        },
        IntegrationManifest {
            integration_id: "notion".to_string(),
            auth_type: IntegrationAuthType::OAuth2,
            token_scope: TokenScope::PersonalAndWorkspace,
            ownership_model: OwnershipModel::Hybrid,
            provider_constraints: ProviderConstraints {
                workspace_first: false,
                single_install_per_workspace: false,
            },
            ui_metadata: UiMetadata {
                display_name: "Notion".to_string(),
                description: "Read and update Notion databases.".to_string(),
                icon_key: Some("notion".to_string()),
                docs_url: None,
            },
            oauth_metadata: Some(OAuthMetadata { scopes: Vec::new() }),
        },
        IntegrationManifest {
            integration_id: "bitly".to_string(),
            auth_type: IntegrationAuthType::OAuth2,
            token_scope: TokenScope::Personal,
            ownership_model: OwnershipModel::PersonalOnly,
            provider_constraints: ProviderConstraints {
                workspace_first: false,
                single_install_per_workspace: false,
            },
            ui_metadata: UiMetadata {
                display_name: "Bitly".to_string(),
                description: "Shorten and manage links with Bitly.".to_string(),
                icon_key: Some("bitly".to_string()),
                docs_url: None,
            },
            oauth_metadata: Some(OAuthMetadata {
                scopes: vec!["bitly".to_string()],
            }),
        },
    ];

    IntegrationRegistry::new(manifests)
}
