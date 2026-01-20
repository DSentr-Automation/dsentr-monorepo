pub mod manifest;
pub mod registry;

use crate::config::Config;
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
            oauth_metadata: Some(OAuthMetadata {
                scopes: Vec::new(),
                github_app: false,
                user_tokens_optional: false,
                installation_scoped: false,
            }),
        },
        IntegrationManifest {
            integration_id: "github".to_string(),
            auth_type: IntegrationAuthType::OAuth2,
            token_scope: TokenScope::PersonalAndWorkspace,
            ownership_model: OwnershipModel::Hybrid,
            provider_constraints: ProviderConstraints {
                workspace_first: false,
                single_install_per_workspace: false,
            },
            ui_metadata: UiMetadata {
                display_name: "GitHub".to_string(),
                description: "Automate GitHub workflows and repositories.".to_string(),
                icon_key: Some("github".to_string()),
                docs_url: None,
            },
            oauth_metadata: Some(OAuthMetadata {
                scopes: vec![
                    "read:user".to_string(),
                    "user:email".to_string(),
                    "repo".to_string(),
                    "workflow".to_string(),
                ],
                github_app: true,
                user_tokens_optional: true,
                installation_scoped: false,
            }),
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
            oauth_metadata: Some(OAuthMetadata {
                scopes: Vec::new(),
                github_app: false,
                user_tokens_optional: false,
                installation_scoped: false,
            }),
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
            oauth_metadata: Some(OAuthMetadata {
                scopes: Vec::new(),
                github_app: false,
                user_tokens_optional: false,
                installation_scoped: false,
            }),
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
            oauth_metadata: Some(OAuthMetadata {
                scopes: Vec::new(),
                github_app: false,
                user_tokens_optional: false,
                installation_scoped: false,
            }),
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
            oauth_metadata: Some(OAuthMetadata {
                scopes: Vec::new(),
                github_app: false,
                user_tokens_optional: false,
                installation_scoped: false,
            }),
        },
        IntegrationManifest {
            integration_id: "bitly".to_string(),
            auth_type: IntegrationAuthType::OAuth2,
            token_scope: TokenScope::PersonalAndWorkspace,
            ownership_model: OwnershipModel::Hybrid,
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
                github_app: false,
                user_tokens_optional: false,
                installation_scoped: false,
            }),
        },
        IntegrationManifest {
            integration_id: "raindrop".to_string(),
            auth_type: IntegrationAuthType::OAuth2,
            token_scope: TokenScope::PersonalAndWorkspace,
            ownership_model: OwnershipModel::Hybrid,
            provider_constraints: ProviderConstraints {
                workspace_first: false,
                single_install_per_workspace: false,
            },
            ui_metadata: UiMetadata {
                display_name: "Raindrop".to_string(),
                description: "Manage bookmarks with Raindrop.io.".to_string(),
                icon_key: Some("raindrop".to_string()),
                docs_url: None,
            },
            oauth_metadata: Some(OAuthMetadata {
                scopes: Vec::new(),
                github_app: false,
                user_tokens_optional: false,
                installation_scoped: false,
            }),
        },
    ];

    IntegrationRegistry::new(manifests)
}

pub fn assert_github_app_settings(config: &Config, registry: &IntegrationRegistry) {
    let Some(manifest) = registry.get("github") else {
        return;
    };
    let Some(oauth_metadata) = manifest.oauth_metadata.as_ref() else {
        return;
    };
    if !oauth_metadata.github_app {
        return;
    }

    if !config.github_app.is_configured() {
        panic!(
            "GitHub App configuration is required when github_app=true. Set GITHUB_APP_ID and GITHUB_APP_PRIVATE_KEY."
        );
    }

    if !config.github_app.user_oauth_enabled {
        panic!(
            "GitHub App user OAuth must be enabled when github_app=true. Enable user-to-server OAuth in the GitHub App settings and set GITHUB_APP_USER_OAUTH_ENABLED=true."
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{GitHubAppSettings, OAuthProviderConfig, OAuthSettings, StripeSettings};
    use crate::config::{
        DEFAULT_WORKSPACE_MEMBER_LIMIT, DEFAULT_WORKSPACE_MONTHLY_RUN_LIMIT, RUNAWAY_LIMIT_5MIN,
    };

    fn stub_config(github_app: GitHubAppSettings) -> Config {
        Config {
            database_url: "postgres://localhost".into(),
            frontend_origin: "http://localhost".into(),
            admin_origin: "http://localhost".into(),
            oauth: OAuthSettings {
                google: OAuthProviderConfig {
                    client_id: "id".into(),
                    client_secret: "secret".into(),
                    redirect_uri: "http://localhost".into(),
                },
                github: OAuthProviderConfig {
                    client_id: "id".into(),
                    client_secret: "secret".into(),
                    redirect_uri: "http://localhost".into(),
                },
                microsoft: OAuthProviderConfig {
                    client_id: "id".into(),
                    client_secret: "secret".into(),
                    redirect_uri: "http://localhost".into(),
                },
                slack: OAuthProviderConfig {
                    client_id: "id".into(),
                    client_secret: "secret".into(),
                    redirect_uri: "http://localhost".into(),
                },
                asana: OAuthProviderConfig {
                    client_id: "id".into(),
                    client_secret: "secret".into(),
                    redirect_uri: "http://localhost".into(),
                },
                notion: OAuthProviderConfig {
                    client_id: "id".into(),
                    client_secret: "secret".into(),
                    redirect_uri: "http://localhost".into(),
                },
                bitly: OAuthProviderConfig {
                    client_id: "id".into(),
                    client_secret: "secret".into(),
                    redirect_uri: "http://localhost".into(),
                },
                raindrop: OAuthProviderConfig {
                    client_id: "id".into(),
                    client_secret: "secret".into(),
                    redirect_uri: "http://localhost".into(),
                },
                token_encryption_key: vec![0u8; 32],
            },
            github_app,
            api_secrets_encryption_key: vec![1u8; 32],
            stripe: StripeSettings {
                client_id: "stub".into(),
                secret_key: "stub".into(),
                webhook_secret: "stub".into(),
            },
            auth_cookie_secure: true,
            jwt_issuer: "test-issuer".into(),
            jwt_audience: "test-audience".into(),
            workspace_member_limit: DEFAULT_WORKSPACE_MEMBER_LIMIT,
            workspace_monthly_run_limit: DEFAULT_WORKSPACE_MONTHLY_RUN_LIMIT,
            runaway_limit_5min: RUNAWAY_LIMIT_5MIN,
            webhook_ingress_dedupe_mode: crate::config::WebhookIngressDedupeMode::Off,
            webhook_verification_body_fields: vec![],
            webhook_verification_header_fields: vec![],
            webhook_event_type_fields: vec![],
        }
    }

    #[test]
    fn github_app_validation_panics_when_missing_settings() {
        let registry = build_integration_registry().expect("registry should build");
        let config = stub_config(GitHubAppSettings {
            app_id: None,
            private_key: None,
            user_oauth_enabled: true,
            user_token_refresh_enabled: false,
        });

        let result = std::panic::catch_unwind(|| assert_github_app_settings(&config, &registry));

        assert!(result.is_err());
    }

    #[test]
    fn github_app_validation_panics_when_user_oauth_disabled() {
        let registry = build_integration_registry().expect("registry should build");
        let config = stub_config(GitHubAppSettings {
            app_id: Some(42),
            private_key: Some("key".into()),
            user_oauth_enabled: false,
            user_token_refresh_enabled: false,
        });

        let result = std::panic::catch_unwind(|| assert_github_app_settings(&config, &registry));

        assert!(result.is_err());
    }
}
