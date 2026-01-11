use std::collections::HashMap;

use thiserror::Error;

use super::manifest::{IntegrationAuthType, IntegrationManifest};

#[derive(Debug, Error)]
pub enum IntegrationRegistryError {
    #[error("integration id is required")]
    MissingIntegrationId,
    #[error("duplicate integration id `{0}`")]
    DuplicateIntegrationId(String),
    #[error("invalid integration manifest `{integration_id}`: {reason}")]
    InvalidManifest {
        integration_id: String,
        reason: String,
    },
}

#[derive(Debug, Clone)]
pub struct IntegrationRegistry {
    // Integration registry is keyed by integration_id by design; OAuth provider enums remain
    // isolated to OAuth routing to avoid leaking legacy identities into manifests.
    manifests: HashMap<String, IntegrationManifest>,
}

impl IntegrationRegistry {
    pub fn new(manifests: Vec<IntegrationManifest>) -> Result<Self, IntegrationRegistryError> {
        let mut entries: HashMap<String, IntegrationManifest> = HashMap::new();
        for manifest in manifests {
            let normalized_id = normalize_id(&manifest.integration_id);
            if normalized_id.is_empty() {
                return Err(IntegrationRegistryError::MissingIntegrationId);
            }

            if entries.contains_key(&normalized_id) {
                return Err(IntegrationRegistryError::DuplicateIntegrationId(
                    normalized_id,
                ));
            }

            let mut manifest = manifest;
            manifest.integration_id = normalized_id.clone();
            validate_manifest(&manifest)?;

            entries.insert(normalized_id, manifest);
        }

        Ok(Self { manifests: entries })
    }

    #[cfg(test)]
    pub fn empty_for_tests() -> Self {
        Self {
            manifests: HashMap::new(),
        }
    }

    pub fn get(&self, integration_id: &str) -> Option<&IntegrationManifest> {
        let normalized_id = normalize_id(integration_id);
        self.manifests.get(&normalized_id)
    }

    pub fn iter(&self) -> impl Iterator<Item = &IntegrationManifest> {
        self.manifests.values()
    }
}

fn validate_manifest(manifest: &IntegrationManifest) -> Result<(), IntegrationRegistryError> {
    let integration_id = manifest.integration_id.as_str();
    let trimmed_id = integration_id.trim();
    if trimmed_id.is_empty() {
        return Err(IntegrationRegistryError::MissingIntegrationId);
    }

    if manifest.ui_metadata.display_name.trim().is_empty() {
        return Err(invalid_manifest(
            manifest,
            "ui_metadata.display_name is required",
        ));
    }

    if manifest.auth_type == IntegrationAuthType::OAuth2 && manifest.oauth_metadata.is_none() {
        return Err(invalid_manifest(
            manifest,
            "oauth_metadata is required for oauth2 auth_type",
        ));
    }

    if manifest.auth_type != IntegrationAuthType::OAuth2 && manifest.oauth_metadata.is_some() {
        return Err(invalid_manifest(
            manifest,
            "oauth_metadata is only valid for oauth2 auth_type",
        ));
    }

    let token_personal = manifest.token_scope.supports_personal();
    let token_workspace = manifest.token_scope.supports_workspace();
    let ownership_personal = manifest.ownership_model.supports_personal();
    let ownership_workspace = manifest.ownership_model.supports_workspace();
    if token_personal != ownership_personal || token_workspace != ownership_workspace {
        return Err(invalid_manifest(
            manifest,
            "token_scope and ownership_model must align for personal/workspace support",
        ));
    }

    let supports_personal = token_personal && ownership_personal;
    let supports_workspace = token_workspace && ownership_workspace;
    if !supports_personal && !supports_workspace {
        return Err(invalid_manifest(
            manifest,
            "token_scope and ownership_model must support personal, workspace, or both",
        ));
    }

    let constraints = &manifest.provider_constraints;
    if constraints.workspace_first && (!supports_workspace || !supports_personal) {
        return Err(invalid_manifest(
            manifest,
            "workspace_first requires both personal and workspace support",
        ));
    }

    if constraints.workspace_first && !constraints.single_install_per_workspace {
        return Err(invalid_manifest(
            manifest,
            "workspace_first requires single_install_per_workspace",
        ));
    }

    if constraints.single_install_per_workspace && !supports_workspace {
        return Err(invalid_manifest(
            manifest,
            "single_install_per_workspace requires workspace support",
        ));
    }

    Ok(())
}

fn invalid_manifest(
    manifest: &IntegrationManifest,
    reason: impl Into<String>,
) -> IntegrationRegistryError {
    IntegrationRegistryError::InvalidManifest {
        integration_id: manifest.integration_id.clone(),
        reason: reason.into(),
    }
}

fn normalize_id(value: &str) -> String {
    value.trim().to_ascii_lowercase()
}
