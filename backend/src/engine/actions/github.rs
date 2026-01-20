use serde_json::{Map, Value};

const DEFAULT_GITHUB_API_BASE_URL: &str = "https://api.github.com";

pub(crate) fn hydrate_github_params(params: &mut Value) -> Result<(), String> {
    let input = params
        .as_object()
        .ok_or_else(|| "GitHub params must be an object".to_string())?;

    if !input.contains_key("operation") {
        return Err("GitHub operation is required".to_string());
    }
    let operation = required_string(input, "operation")?;
    let operation_key = operation.to_ascii_lowercase();

    let owner = required_string(input, "owner")?;
    let repo = required_string(input, "repo")?;
    let base_url = DEFAULT_GITHUB_API_BASE_URL.trim_end_matches('/');

    let mut sanitized = Map::new();
    sanitized.insert("operation".to_string(), Value::String(operation.clone()));
    sanitized.insert("owner".to_string(), Value::String(owner.clone()));
    sanitized.insert("repo".to_string(), Value::String(repo.clone()));
    // Preserve connectionScope/connectionId so the executor can resolve the OAuth token;
    // these are internal fields and must never be forwarded to the GitHub API payload.
    copy_optional_string(input, "connectionScope", &mut sanitized);
    copy_optional_string(input, "connectionId", &mut sanitized);

    let (method, url, body) = match operation_key.as_str() {
        "create_issue" => {
            let title = required_string(input, "title")?;
            let body = optional_string(input, "body");

            let mut payload = Map::new();
            payload.insert("title".to_string(), Value::String(title.clone()));
            if let Some(body) = body {
                payload.insert("body".to_string(), Value::String(body));
            }

            sanitized.insert("title".to_string(), Value::String(title));

            (
                "POST".to_string(),
                format!("{base_url}/repos/{owner}/{repo}/issues"),
                Value::Object(payload),
            )
        }
        "create_issue_comment" => {
            let issue_number = required_number_as_string(input, "issue_number")?;
            let body = required_string(input, "body")?;

            let mut payload = Map::new();
            payload.insert("body".to_string(), Value::String(body));

            sanitized.insert(
                "issue_number".to_string(),
                Value::String(issue_number.clone()),
            );

            (
                "POST".to_string(),
                format!("{base_url}/repos/{owner}/{repo}/issues/{issue_number}/comments"),
                Value::Object(payload),
            )
        }
        "add_labels_to_issue" => {
            let issue_number = required_number_as_string(input, "issue_number")?;
            let labels = required_string_array(input, "labels")?;

            let payload = json_object_with_array("labels", &labels);

            sanitized.insert(
                "issue_number".to_string(),
                Value::String(issue_number.clone()),
            );
            sanitized.insert(
                "labels".to_string(),
                Value::Array(labels.into_iter().map(Value::String).collect()),
            );

            (
                "POST".to_string(),
                format!("{base_url}/repos/{owner}/{repo}/issues/{issue_number}/labels"),
                payload,
            )
        }
        "create_pull_request" => {
            let title = required_string(input, "title")?;
            let head = required_string(input, "head")?;
            let base = required_string(input, "base")?;
            let body = optional_string(input, "body");
            let draft = optional_bool(input, "draft")?;

            let mut payload = Map::new();
            payload.insert("title".to_string(), Value::String(title.clone()));
            payload.insert("head".to_string(), Value::String(head.clone()));
            payload.insert("base".to_string(), Value::String(base.clone()));
            if let Some(body) = body {
                payload.insert("body".to_string(), Value::String(body));
            }
            if let Some(draft) = draft {
                payload.insert("draft".to_string(), Value::Bool(draft));
            }

            sanitized.insert("title".to_string(), Value::String(title));
            sanitized.insert("head".to_string(), Value::String(head));
            sanitized.insert("base".to_string(), Value::String(base));
            if let Some(draft) = draft {
                sanitized.insert("draft".to_string(), Value::Bool(draft));
            }

            (
                "POST".to_string(),
                format!("{base_url}/repos/{owner}/{repo}/pulls"),
                Value::Object(payload),
            )
        }
        "create_release" => {
            let tag_name = required_string(input, "tag_name")?;
            let name = optional_string(input, "name");
            let body = optional_string(input, "body");
            let draft = optional_bool(input, "draft")?;
            let prerelease = optional_bool(input, "prerelease")?;

            let mut payload = Map::new();
            payload.insert("tag_name".to_string(), Value::String(tag_name.clone()));
            if let Some(name) = name {
                payload.insert("name".to_string(), Value::String(name.clone()));
                sanitized.insert("name".to_string(), Value::String(name));
            }
            if let Some(body) = body {
                payload.insert("body".to_string(), Value::String(body));
            }
            if let Some(draft) = draft {
                payload.insert("draft".to_string(), Value::Bool(draft));
                sanitized.insert("draft".to_string(), Value::Bool(draft));
            }
            if let Some(prerelease) = prerelease {
                payload.insert("prerelease".to_string(), Value::Bool(prerelease));
                sanitized.insert("prerelease".to_string(), Value::Bool(prerelease));
            }

            sanitized.insert("tag_name".to_string(), Value::String(tag_name));

            (
                "POST".to_string(),
                format!("{base_url}/repos/{owner}/{repo}/releases"),
                Value::Object(payload),
            )
        }
        "dispatch_workflow" => {
            let workflow_id = required_string(input, "workflow_id")?;
            let git_ref = required_string(input, "ref")?;
            let inputs = optional_object(input, "inputs")?;

            let mut payload = Map::new();
            payload.insert("ref".to_string(), Value::String(git_ref.clone()));
            if let Some(inputs) = inputs {
                payload.insert("inputs".to_string(), inputs.clone());
                sanitized.insert("inputs".to_string(), inputs);
            }

            sanitized.insert(
                "workflow_id".to_string(),
                Value::String(workflow_id.clone()),
            );
            sanitized.insert("ref".to_string(), Value::String(git_ref));

            (
                "POST".to_string(),
                format!(
                    "{base_url}/repos/{owner}/{repo}/actions/workflows/{workflow_id}/dispatches"
                ),
                Value::Object(payload),
            )
        }
        other => {
            return Err(format!("Unsupported GitHub operation `{}`", other));
        }
    };

    sanitized.insert("_method".to_string(), Value::String(method));
    sanitized.insert("_url".to_string(), Value::String(url));
    sanitized.insert("_body".to_string(), body);

    *params = Value::Object(sanitized);
    Ok(())
}

fn required_string(input: &Map<String, Value>, field: &str) -> Result<String, String> {
    input
        .get(field)
        .and_then(|v| v.as_str())
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
        .ok_or_else(|| format!("GitHub {} is required", field))
}

fn optional_string(input: &Map<String, Value>, field: &str) -> Option<String> {
    input
        .get(field)
        .and_then(|v| v.as_str())
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
}

fn required_number_as_string(input: &Map<String, Value>, field: &str) -> Result<String, String> {
    match input.get(field) {
        Some(Value::Number(n)) => Ok(n.to_string()),
        Some(Value::String(s)) => {
            let trimmed = s.trim();
            if trimmed.is_empty() {
                return Err(format!("GitHub {} is required", field));
            }
            if trimmed.parse::<u64>().is_ok() {
                Ok(trimmed.to_string())
            } else {
                Err(format!(
                    "GitHub {} must be a number or numeric string",
                    field
                ))
            }
        }
        Some(_) => Err(format!(
            "GitHub {} must be a number or numeric string",
            field
        )),
        None => Err(format!("GitHub {} is required", field)),
    }
}

fn required_string_array(input: &Map<String, Value>, field: &str) -> Result<Vec<String>, String> {
    let array = input
        .get(field)
        .and_then(|v| v.as_array())
        .ok_or_else(|| format!("GitHub {} must be an array of strings", field))?;
    if array.is_empty() {
        return Err(format!("GitHub {} cannot be empty", field));
    }

    let mut values = Vec::new();
    for entry in array {
        let value = entry
            .as_str()
            .map(|s| s.trim())
            .filter(|s| !s.is_empty())
            .ok_or_else(|| format!("GitHub {} entries cannot be empty", field))?;
        values.push(value.to_string());
    }

    Ok(values)
}

fn optional_bool(input: &Map<String, Value>, field: &str) -> Result<Option<bool>, String> {
    match input.get(field) {
        Some(Value::Bool(value)) => Ok(Some(*value)),
        Some(Value::Null) | None => Ok(None),
        Some(_) => Err(format!("GitHub {} must be a boolean", field)),
    }
}

fn optional_object(input: &Map<String, Value>, field: &str) -> Result<Option<Value>, String> {
    match input.get(field) {
        // Empty objects are intentionally omitted to keep dispatch payloads minimal.
        Some(Value::Object(map)) if !map.is_empty() => Ok(Some(Value::Object(map.clone()))),
        Some(Value::Object(_)) | Some(Value::Null) | None => Ok(None),
        Some(_) => Err(format!("GitHub {} must be an object", field)),
    }
}

fn copy_optional_string(input: &Map<String, Value>, field: &str, target: &mut Map<String, Value>) {
    if let Some(value) = input
        .get(field)
        .and_then(|v| v.as_str())
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
    {
        target.insert(field.to_string(), Value::String(value.to_string()));
    }
}

fn json_object_with_array(field: &str, values: &[String]) -> Value {
    let array = values
        .iter()
        .cloned()
        .map(Value::String)
        .collect::<Vec<_>>();
    let mut map = Map::new();
    map.insert(field.to_string(), Value::Array(array));
    Value::Object(map)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn hydrate_create_issue() {
        let mut params = json!({
            "operation": "create_issue",
            "owner": "octo",
            "repo": "example",
            "title": "Bug report",
            "body": "Steps to reproduce"
        });

        hydrate_github_params(&mut params).expect("hydrate");

        assert_eq!(params.get("_method").and_then(|v| v.as_str()), Some("POST"));
        assert_eq!(
            params.get("_url").and_then(|v| v.as_str()),
            Some("https://api.github.com/repos/octo/example/issues")
        );
        assert_eq!(
            params.get("_body"),
            Some(&json!({
                "title": "Bug report",
                "body": "Steps to reproduce"
            }))
        );
        assert!(params.get("body").is_none());
    }

    #[test]
    fn hydrate_create_issue_comment() {
        let mut params = json!({
            "operation": "create_issue_comment",
            "owner": "octo",
            "repo": "example",
            "issue_number": 42,
            "body": "Looks good"
        });

        hydrate_github_params(&mut params).expect("hydrate");

        assert_eq!(params.get("_method").and_then(|v| v.as_str()), Some("POST"));
        assert_eq!(
            params.get("_url").and_then(|v| v.as_str()),
            Some("https://api.github.com/repos/octo/example/issues/42/comments")
        );
        assert_eq!(params.get("_body"), Some(&json!({"body": "Looks good"})));
    }

    #[test]
    fn hydrate_add_labels_to_issue() {
        let mut params = json!({
            "operation": "add_labels_to_issue",
            "owner": "octo",
            "repo": "example",
            "issue_number": "7",
            "labels": ["bug", "urgent"]
        });

        hydrate_github_params(&mut params).expect("hydrate");

        assert_eq!(params.get("_method").and_then(|v| v.as_str()), Some("POST"));
        assert_eq!(
            params.get("_url").and_then(|v| v.as_str()),
            Some("https://api.github.com/repos/octo/example/issues/7/labels")
        );
        assert_eq!(
            params.get("_body"),
            Some(&json!({"labels": ["bug", "urgent"]}))
        );
    }

    #[test]
    fn hydrate_create_pull_request() {
        let mut params = json!({
            "operation": "create_pull_request",
            "owner": "octo",
            "repo": "example",
            "title": "Add feature",
            "head": "feature",
            "base": "main",
            "body": "",
            "draft": true
        });

        hydrate_github_params(&mut params).expect("hydrate");

        assert_eq!(params.get("_method").and_then(|v| v.as_str()), Some("POST"));
        assert_eq!(
            params.get("_url").and_then(|v| v.as_str()),
            Some("https://api.github.com/repos/octo/example/pulls")
        );
        assert_eq!(
            params.get("_body"),
            Some(&json!({
                "title": "Add feature",
                "head": "feature",
                "base": "main",
                "draft": true
            }))
        );
    }

    #[test]
    fn hydrate_create_release() {
        let mut params = json!({
            "operation": "create_release",
            "owner": "octo",
            "repo": "example",
            "tag_name": "v1.0.0",
            "name": "Release v1.0.0",
            "body": "Notes",
            "draft": false,
            "prerelease": true
        });

        hydrate_github_params(&mut params).expect("hydrate");

        assert_eq!(params.get("_method").and_then(|v| v.as_str()), Some("POST"));
        assert_eq!(
            params.get("_url").and_then(|v| v.as_str()),
            Some("https://api.github.com/repos/octo/example/releases")
        );
        assert_eq!(
            params.get("_body"),
            Some(&json!({
                "tag_name": "v1.0.0",
                "name": "Release v1.0.0",
                "body": "Notes",
                "draft": false,
                "prerelease": true
            }))
        );
    }

    #[test]
    fn hydrate_dispatch_workflow() {
        let mut params = json!({
            "operation": "dispatch_workflow",
            "owner": "octo",
            "repo": "example",
            "workflow_id": "build.yml",
            "ref": "main",
            "inputs": {
                "release": "2026.01"
            }
        });

        hydrate_github_params(&mut params).expect("hydrate");

        assert_eq!(params.get("_method").and_then(|v| v.as_str()), Some("POST"));
        assert_eq!(
            params.get("_url").and_then(|v| v.as_str()),
            Some(
                "https://api.github.com/repos/octo/example/actions/workflows/build.yml/dispatches"
            )
        );
        assert_eq!(
            params.get("_body"),
            Some(&json!({
                "ref": "main",
                "inputs": {
                    "release": "2026.01"
                }
            }))
        );
    }

    #[test]
    fn hydrate_rejects_unsupported_operation() {
        let mut params = json!({
            "operation": "archive_repo",
            "owner": "octo",
            "repo": "example"
        });

        let err = hydrate_github_params(&mut params).expect_err("should reject");
        assert!(err.contains("Unsupported GitHub operation"));
    }
}
