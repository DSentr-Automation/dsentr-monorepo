use std::collections::HashSet;
use std::sync::OnceLock;

use include_dir::{include_dir, Dir};
use serde::{Deserialize, Serialize};

use super::registry::ActionAlias;

static ACTION_MANIFEST_DIR: Dir = include_dir!("$CARGO_MANIFEST_DIR/src/action_manifests");
static ACTION_MANIFEST_REGISTRY: OnceLock<ActionManifestRegistry> = OnceLock::new();

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ActionManifestSpec {
    pub action_id: String,
    pub executor: String,
    pub ui: UiMetadata,
    pub inputs: Vec<ActionInput>,
    pub http: HttpManifest,
    pub egress: Option<EgressManifest>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct EgressManifest {
    pub allow: Vec<String>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(deny_unknown_fields)]
pub(crate) struct UiMetadata {
    pub label: String,
    pub description: String,
    pub category: String,
    pub icon: String,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(deny_unknown_fields)]
#[allow(dead_code)]
pub(crate) struct ActionInput {
    pub name: String,
    pub label: String,
    #[serde(rename = "type")]
    pub field_type: String,
    pub required: bool,
    pub provider: Option<String>,
    #[serde(rename = "connection_scopes")]
    pub connection_scopes: Option<Vec<String>>,
    pub options: Option<Vec<String>>,
}

#[allow(dead_code)]
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct HttpManifest {
    pub method: String,
    pub url: String,
    pub headers: Vec<KeyValuePair>,
    #[serde(rename = "queryParams")]
    pub query_params: Vec<KeyValuePair>,
    #[serde(rename = "bodyType")]
    pub body_type: String,
    pub body: String,
    #[serde(rename = "formBody")]
    pub form_body: Vec<KeyValuePair>,
}

#[allow(dead_code)]
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct KeyValuePair {
    pub key: String,
    pub value: String,
}

#[derive(Debug, Serialize, Clone)]
pub(crate) struct ActionManifestEntry {
    pub action_id: String,
    pub executor: String,
    pub ui: UiMetadata,
    pub inputs: Vec<ActionInput>,
}

#[derive(Debug)]
pub(crate) struct ActionManifestRegistry {
    entries: Vec<ActionManifestEntry>,
    http_manifests: std::collections::HashMap<String, HttpManifest>,
    egress_manifests: std::collections::HashMap<String, EgressManifest>,
}

impl ActionManifestRegistry {
    pub(crate) fn entries(&self) -> &[ActionManifestEntry] {
        &self.entries
    }

    #[allow(dead_code)]
    pub(crate) fn empty() -> Self {
        Self {
            entries: Vec::new(),
            http_manifests: std::collections::HashMap::new(),
            egress_manifests: std::collections::HashMap::new(),
        }
    }

    /// Get HTTP manifest data by action ID for runtime hydration
    pub(crate) fn get_http_manifest(&self, action_id: &str) -> Option<&HttpManifest> {
        self.http_manifests.get(&action_id.to_ascii_lowercase())
    }

    /// Get egress manifest data by action ID for runtime allowlist collection
    pub(crate) fn get_egress_manifest(&self, action_id: &str) -> Option<&EgressManifest> {
        self.egress_manifests.get(&action_id.to_ascii_lowercase())
    }
}

#[allow(dead_code)]
pub(crate) fn init_action_manifest_registry() -> Result<(), String> {
    if ACTION_MANIFEST_REGISTRY.get().is_some() {
        return Ok(());
    }

    let registry = load_action_manifest_registry()?;
    ACTION_MANIFEST_REGISTRY
        .set(registry)
        .map_err(|_| "Action manifest registry already initialized".to_string())?;
    Ok(())
}

pub(crate) fn action_manifest_registry() -> &'static ActionManifestRegistry {
    ACTION_MANIFEST_REGISTRY.get_or_init(|| {
        load_action_manifest_registry()
            .unwrap_or_else(|error| panic!("Failed to load action manifests: {}", error))
    })
}

fn load_action_manifest_registry() -> Result<ActionManifestRegistry, String> {
    let mut entries = Vec::new();
    let mut http_manifests: std::collections::HashMap<String, HttpManifest> =
        std::collections::HashMap::new();
    let mut egress_manifests: std::collections::HashMap<String, EgressManifest> =
        std::collections::HashMap::new();
    let mut seen: HashSet<String> = HashSet::new();

    for file in ACTION_MANIFEST_DIR.files() {
        if !is_json_file(file.path()) {
            return Err(format!(
                "{}: only .json manifests are allowed",
                file.path().display()
            ));
        }

        let manifest: ActionManifestSpec = serde_json::from_slice(file.contents())
            .map_err(|err| format!("{}: failed to parse manifest: {err}", file.path().display()))?;

        validate_manifest(&manifest)
            .map_err(|err| format!("{}: invalid manifest: {err}", file.path().display()))?;

        let action_id = normalize_id(&manifest.action_id);
        if !seen.insert(action_id.clone()) {
            return Err(format!(
                "{}: duplicate action_id `{}`",
                file.path().display(),
                action_id
            ));
        }

        let executor = normalize_id(&manifest.executor);

        // Store HTTP manifest data for runtime hydration if this is an HTTP-based action
        if executor == "http" {
            http_manifests.insert(action_id.clone(), manifest.http);
        }

        // Store egress manifest data if present
        if let Some(egress) = manifest.egress {
            egress_manifests.insert(action_id.clone(), egress);
        }

        entries.push(ActionManifestEntry {
            action_id,
            executor,
            ui: manifest.ui,
            inputs: manifest.inputs,
        });
    }

    entries.sort_by(|left, right| left.action_id.cmp(&right.action_id));

    Ok(ActionManifestRegistry {
        entries,
        http_manifests,
        egress_manifests,
    })
}

pub(crate) fn load_action_manifest_aliases() -> Result<Vec<ActionAlias>, String> {
    let mut aliases = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();

    for file in ACTION_MANIFEST_DIR.files() {
        if !is_json_file(file.path()) {
            return Err(format!(
                "{}: only .json manifests are allowed",
                file.path().display()
            ));
        }

        let manifest: ActionManifestSpec = serde_json::from_slice(file.contents())
            .map_err(|err| format!("{}: failed to parse manifest: {err}", file.path().display()))?;

        validate_manifest(&manifest)
            .map_err(|err| format!("{}: invalid manifest: {err}", file.path().display()))?;

        let action_id = normalize_id(&manifest.action_id);
        if !seen.insert(action_id.clone()) {
            return Err(format!(
                "{}: duplicate action_id `{}`",
                file.path().display(),
                action_id
            ));
        }

        let executor = normalize_id(&manifest.executor);
        let executor_action_type = match executor.as_str() {
            "http" => "http",
            other => {
                return Err(format!(
                    "{}: unsupported executor `{}`",
                    file.path().display(),
                    other
                ))
            }
        };

        aliases.push(ActionAlias {
            action_type: action_id,
            executor_action_type: executor_action_type.to_string(),
        });
    }

    Ok(aliases)
}

fn validate_manifest(manifest: &ActionManifestSpec) -> Result<(), String> {
    if manifest.action_id.trim().is_empty() {
        return Err("action_id is required".to_string());
    }

    if manifest.executor.trim().is_empty() {
        return Err("executor is required".to_string());
    }

    validate_ui(&manifest.ui)?;
    validate_inputs(&manifest.inputs)?;
    validate_egress(&manifest.egress)?;

    let executor = manifest.executor.trim().to_ascii_lowercase();
    match executor.as_str() {
        "http" => validate_http(&manifest.http),
        other => Err(format!("unsupported executor `{}`", other)),
    }
}

fn validate_ui(ui: &UiMetadata) -> Result<(), String> {
    if ui.label.trim().is_empty() {
        return Err("ui.label is required".to_string());
    }
    if ui.description.trim().is_empty() {
        return Err("ui.description is required".to_string());
    }
    if ui.category.trim().is_empty() {
        return Err("ui.category is required".to_string());
    }
    if ui.icon.trim().is_empty() {
        return Err("ui.icon is required".to_string());
    }
    Ok(())
}

fn validate_inputs(inputs: &[ActionInput]) -> Result<(), String> {
    let mut seen: HashSet<String> = HashSet::new();
    for input in inputs {
        let name = input.name.trim();
        if name.is_empty() {
            return Err("inputs.name is required".to_string());
        }
        if input.label.trim().is_empty() {
            return Err(format!("inputs.{}.label is required", name));
        }
        if input.field_type.trim().is_empty() {
            return Err(format!("inputs.{}.type is required", name));
        }
        if !seen.insert(name.to_ascii_lowercase()) {
            return Err(format!("duplicate input name `{}`", name));
        }

        // OAuth-specific validation
        if input.field_type == "oauth_connection"
            && (input.provider.is_none() || input.provider.as_ref().unwrap().trim().is_empty())
        {
            return Err(format!(
                "inputs.{}.provider is required for oauth_connection type",
                name
            ));
        }
    }
    Ok(())
}

fn validate_http(http: &HttpManifest) -> Result<(), String> {
    if http.method.trim().is_empty() {
        return Err("http.method is required".to_string());
    }
    let raw_method = http.method.trim();

    let is_templated = raw_method.starts_with("{{") && raw_method.ends_with("}}");

    if !is_templated {
        let method = raw_method.to_ascii_uppercase();
        match method.as_str() {
            "GET" | "POST" | "PUT" | "PATCH" | "DELETE" | "HEAD" => {}
            other => return Err(format!("http.method `{}` is not supported", other)),
        }
    }

    if http.url.trim().is_empty() {
        return Err("http.url is required".to_string());
    }

    let body_type = http.body_type.trim().to_ascii_lowercase();
    match body_type.as_str() {
        "raw" | "json" | "form" => {}
        other => return Err(format!("http.bodyType `{}` is not supported", other)),
    }

    validate_kv_list("http.headers", &http.headers)?;
    validate_kv_list("http.queryParams", &http.query_params)?;
    validate_kv_list("http.formBody", &http.form_body)?;

    Ok(())
}

fn validate_kv_list(label: &str, list: &[KeyValuePair]) -> Result<(), String> {
    for entry in list {
        if entry.key.trim().is_empty() {
            return Err(format!("{} entries require a key", label));
        }
    }
    Ok(())
}

fn validate_egress(egress: &Option<EgressManifest>) -> Result<(), String> {
    if let Some(egress) = egress {
        if egress.allow.is_empty() {
            return Err("egress.allow cannot be empty when egress is specified".to_string());
        }
        for host in &egress.allow {
            if host.trim().is_empty() {
                return Err("egress.allow entries cannot be empty".to_string());
            }
        }
    }
    Ok(())
}

fn normalize_id(value: &str) -> String {
    value.trim().to_ascii_lowercase()
}

fn is_json_file(path: &std::path::Path) -> bool {
    path.extension()
        .and_then(|ext| ext.to_str())
        .map(|ext| ext.eq_ignore_ascii_case("json"))
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_oauth_connection_input_success() {
        let manifest = ActionManifestSpec {
            action_id: "test.action".to_string(),
            executor: "http".to_string(),
            ui: UiMetadata {
                label: "Test".to_string(),
                description: "Test action".to_string(),
                category: "Test".to_string(),
                icon: "test".to_string(),
            },
            inputs: vec![ActionInput {
                name: "connection".to_string(),
                label: "Account".to_string(),
                field_type: "oauth_connection".to_string(),
                required: true,
                provider: Some("bitly".to_string()),
                connection_scopes: Some(vec!["personal".to_string(), "workspace".to_string()]),
                options: None,
            }],
            http: HttpManifest {
                method: "GET".to_string(),
                url: "https://example.com".to_string(),
                headers: vec![],
                query_params: vec![],
                body_type: "raw".to_string(),
                body: "".to_string(),
                form_body: vec![],
            },
            egress: None,
        };

        let result = validate_manifest(&manifest);
        assert!(result.is_ok());
    }

    #[test]
    fn validate_oauth_connection_input_missing_provider() {
        let manifest = ActionManifestSpec {
            action_id: "test.action".to_string(),
            executor: "http".to_string(),
            ui: UiMetadata {
                label: "Test".to_string(),
                description: "Test action".to_string(),
                category: "Test".to_string(),
                icon: "test".to_string(),
            },
            inputs: vec![ActionInput {
                name: "connection".to_string(),
                label: "Account".to_string(),
                field_type: "oauth_connection".to_string(),
                required: true,
                provider: None,
                connection_scopes: Some(vec!["personal".to_string()]),
                options: None,
            }],
            http: HttpManifest {
                method: "GET".to_string(),
                url: "https://example.com".to_string(),
                headers: vec![],
                query_params: vec![],
                body_type: "raw".to_string(),
                body: "".to_string(),
                form_body: vec![],
            },
            egress: None,
        };

        let result = validate_manifest(&manifest);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("provider is required"));
    }

    #[test]
    fn validate_oauth_connection_input_empty_provider() {
        let manifest = ActionManifestSpec {
            action_id: "test.action".to_string(),
            executor: "http".to_string(),
            ui: UiMetadata {
                label: "Test".to_string(),
                description: "Test action".to_string(),
                category: "Test".to_string(),
                icon: "test".to_string(),
            },
            inputs: vec![ActionInput {
                name: "connection".to_string(),
                label: "Account".to_string(),
                field_type: "oauth_connection".to_string(),
                required: true,
                provider: Some("".to_string()),
                connection_scopes: Some(vec!["personal".to_string()]),
                options: None,
            }],
            http: HttpManifest {
                method: "GET".to_string(),
                url: "https://example.com".to_string(),
                headers: vec![],
                query_params: vec![],
                body_type: "raw".to_string(),
                body: "".to_string(),

                form_body: vec![],
            },
            egress: None,
        };

        let result = validate_manifest(&manifest);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("provider is required"));
    }

    #[test]
    fn validate_regular_input_no_oauth_validation() {
        let manifest = ActionManifestSpec {
            action_id: "test.action".to_string(),
            executor: "http".to_string(),
            ui: UiMetadata {
                label: "Test".to_string(),
                description: "Test action".to_string(),
                category: "Test".to_string(),
                icon: "test".to_string(),
            },
            inputs: vec![ActionInput {
                name: "text".to_string(),
                label: "Text".to_string(),
                field_type: "string".to_string(),
                required: true,
                provider: None,
                connection_scopes: None,
                options: None,
            }],
            http: HttpManifest {
                method: "GET".to_string(),
                url: "https://example.com".to_string(),
                headers: vec![],
                query_params: vec![],
                body_type: "raw".to_string(),
                body: "".to_string(),
                form_body: vec![],
            },
            egress: None,
        };

        let result = validate_manifest(&manifest);
        assert!(result.is_ok());
    }
}
