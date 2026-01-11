use std::collections::HashSet;

use boa_engine::context::Context as JsContext;
use boa_engine::Source;
use serde_json::{json, Map, Value};

use crate::engine::actions::registry::{ActionExecutionSemantics, ActionManifest, ActionValidator};
use crate::engine::actions::validate_required_fields;
use crate::engine::graph::Node;
use crate::engine::templating::templ_str;

pub(crate) const MANIFEST: ActionManifest = ActionManifest {
    action_type: "code",
    required_fields: &["params"],
    execution_semantics: ActionExecutionSemantics::Standard,
};

pub(crate) struct CodeValidator;

impl ActionValidator for CodeValidator {
    fn validate(&self, node: &Node) -> Result<(), String> {
        validate_required_fields(node, MANIFEST.required_fields)
    }
}

pub(crate) async fn execute_code(
    node: &Node,
    context: &Value,
) -> Result<(Value, Option<String>), String> {
    let params = node.data.get("params").cloned().unwrap_or(Value::Null);
    let code_raw = params
        .get("code")
        .and_then(|v| v.as_str())
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .ok_or_else(|| "Custom code is required".to_string())?;

    let (inputs_value, input_keys) = build_inputs(&params, context)?;

    let context_literal = serde_json::to_string(context)
        .map_err(|_| "Failed to serialize workflow context".to_string())?;
    let inputs_literal = serde_json::to_string(&inputs_value)
        .map_err(|_| "Failed to serialize custom code inputs".to_string())?;

    let script = format!(
        "const inputs = {};\nconst context = {};\nconst __dsentrResult = (() => {{\n{}\n}})();\nJSON.stringify(__dsentrResult);",
        inputs_literal, context_literal, code_raw
    );

    let mut js_context = JsContext::default();
    let result = js_context
        .eval(Source::from_bytes(script.as_bytes()))
        .map_err(format_js_error)?;

    let result_value = if result.is_undefined() || result.is_null() {
        Value::Null
    } else {
        let json_text = result
            .to_string(&mut js_context)
            .map_err(format_js_error)?
            .to_std_string()
            .map_err(|_| "Failed to convert custom code result to string".to_string())?;

        if json_text.trim().is_empty() {
            Value::Null
        } else {
            serde_json::from_str::<Value>(&json_text).unwrap_or(Value::String(json_text.clone()))
        }
    };

    let outputs = map_outputs(&params, result_value, &input_keys)?;

    Ok((outputs, None))
}

fn build_inputs(params: &Value, context: &Value) -> Result<(Value, HashSet<String>), String> {
    let mut inputs = Map::new();
    let mut seen = HashSet::new();
    if let Some(arr) = params.get("inputs").and_then(|v| v.as_array()) {
        for entry in arr {
            let Some(key) = entry
                .get("key")
                .and_then(|v| v.as_str())
                .map(|s| s.trim())
                .filter(|s| !s.is_empty())
            else {
                continue;
            };
            if !seen.insert(key.to_string()) {
                return Err(format!("Duplicate input parameter key: {}", key));
            }
            let value_raw = entry.get("value").and_then(|v| v.as_str()).unwrap_or("");
            let templated = templ_str(value_raw, context);
            let parsed = parse_jsonish(&templated);
            inputs.insert(key.to_string(), parsed);
        }
    }
    Ok((Value::Object(inputs), seen))
}

fn map_outputs(
    params: &Value,
    result_value: Value,
    input_keys: &HashSet<String>,
) -> Result<Value, String> {
    let result = result_value;
    if let Some(arr) = params.get("outputs").and_then(|v| v.as_array()) {
        if !arr.is_empty() {
            let mut mapped = Map::new();
            let mut seen = HashSet::new();
            for entry in arr {
                let Some(key) = entry
                    .get("key")
                    .and_then(|v| v.as_str())
                    .map(|s| s.trim())
                    .filter(|s| !s.is_empty())
                else {
                    continue;
                };
                if !seen.insert(key.to_string()) {
                    return Err(format!("Duplicate output key: {}", key));
                }
                if input_keys.contains(key) {
                    return Err(format!("Output key conflicts with input key: {}", key));
                }
                let path = entry
                    .get("value")
                    .and_then(|v| v.as_str())
                    .map(|s| s.trim())
                    .unwrap_or("");
                let value = if path.is_empty() {
                    result.clone()
                } else {
                    extract_path(&result, path).unwrap_or(Value::Null)
                };
                mapped.insert(key.to_string(), value);
            }
            return Ok(Value::Object(mapped));
        }
    }
    if result.is_object() {
        Ok(result)
    } else {
        Ok(json!({ "result": result }))
    }
}

fn parse_jsonish(raw: &str) -> Value {
    if raw.trim().is_empty() {
        return Value::Null;
    }
    if let Ok(json_val) = serde_json::from_str::<Value>(raw) {
        return json_val;
    }
    if let Ok(json_val) = serde_json::from_str::<Value>(raw.trim()) {
        return json_val;
    }
    Value::String(raw.to_string())
}

fn extract_path(value: &Value, path: &str) -> Option<Value> {
    let segments = parse_path(path);
    let mut current = value;
    for segment in segments {
        match segment {
            PathSegment::Key(k) => {
                current = current.get(&k)?;
            }
            PathSegment::Index(i) => {
                current = current.get(i)?;
            }
        }
    }
    Some(current.clone())
}

fn parse_path(path: &str) -> Vec<PathSegment> {
    let mut segments = Vec::new();
    let mut buf = String::new();
    let mut idx_buf = String::new();
    let mut in_brackets = false;
    for ch in path.chars() {
        match ch {
            '.' if !in_brackets => {
                if !buf.is_empty() {
                    let key = buf.trim();
                    if !key.is_empty() {
                        segments.push(PathSegment::Key(key.to_string()));
                    }
                    buf.clear();
                }
            }
            '[' => {
                if !buf.is_empty() {
                    let key = buf.trim();
                    if !key.is_empty() {
                        segments.push(PathSegment::Key(key.to_string()));
                    }
                    buf.clear();
                }
                in_brackets = true;
                idx_buf.clear();
            }
            ']' => {
                if in_brackets {
                    if let Ok(idx) = idx_buf.trim().parse::<usize>() {
                        segments.push(PathSegment::Index(idx));
                    }
                    idx_buf.clear();
                    in_brackets = false;
                }
            }
            _ => {
                if in_brackets {
                    idx_buf.push(ch);
                } else {
                    buf.push(ch);
                }
            }
        }
    }
    if !buf.trim().is_empty() {
        segments.push(PathSegment::Key(buf.trim().to_string()));
    }
    segments
}

enum PathSegment {
    Key(String),
    Index(usize),
}

fn format_js_error(err: boa_engine::JsError) -> String {
    let message = err.to_string();
    if message.trim().is_empty() {
        "JavaScript execution error".to_string()
    } else {
        message
    }
}
