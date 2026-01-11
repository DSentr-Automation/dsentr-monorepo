use std::collections::HashMap;
use std::str::FromStr;

use async_trait::async_trait;
use chrono::{DateTime, Datelike, NaiveDate, NaiveDateTime, TimeZone, Timelike, Utc};
use chrono_tz::Tz;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use crate::engine::actions::registry::{
    ActionExecutionResult, ActionExecutionSemantics, ActionExecutor, ActionManifest,
    ActionRuntimeContext, ActionValidator,
};
use crate::engine::actions::{lookup_path, parse_flexible_value, validate_required_fields};
use crate::engine::graph::Node;
use crate::engine::templating::templ_str;

pub(crate) const MANIFEST: ActionManifest = ActionManifest {
    action_type: "formatter",
    required_fields: &["config"],
    execution_semantics: ActionExecutionSemantics::Standard,
};

pub(crate) struct FormatterValidator;

impl ActionValidator for FormatterValidator {
    fn validate(&self, node: &Node) -> Result<(), String> {
        validate_required_fields(node, MANIFEST.required_fields)?;
        let config_value = node.data.get("config").cloned().unwrap_or(Value::Null);
        let config = parse_formatter_config(&config_value)?;
        validate_formatter_config(&config)
    }
}

pub(crate) struct FormatterExecutor;

#[async_trait]
impl ActionExecutor for FormatterExecutor {
    async fn execute(
        &self,
        ctx: ActionRuntimeContext<'_>,
    ) -> Result<ActionExecutionResult, String> {
        let (outputs, selected_next) = execute_formatter(ctx.node, ctx.context)?;
        Ok(ActionExecutionResult::Immediate {
            outputs,
            selected_next,
        })
    }
}

fn parse_formatter_config(value: &Value) -> Result<FormatterConfig, String> {
    serde_json::from_value(value.clone())
        .map_err(|_| "Invalid formatter configuration".to_string())
}

fn validate_formatter_config(config: &FormatterConfig) -> Result<(), String> {
    let operation = config.operation.trim();
    if operation.is_empty() {
        return Err("Formatter operation is required.".to_string());
    }

    let output_key = config.output_key.trim();
    if output_key.is_empty() {
        return Err("Output key is required.".to_string());
    }
    if !is_valid_output_key(output_key) {
        return Err("Output key must start with a letter/underscore and contain only letters, numbers, or underscores.".to_string());
    }

    Ok(())
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct FormatterConfig {
    #[serde(default)]
    pub operation: String,
    #[serde(default)]
    pub input: String,
    #[serde(default)]
    pub fields: HashMap<String, Value>,
    #[serde(default)]
    pub output_key: String,
}

fn is_valid_output_key(key: &str) -> bool {
    let mut chars = key.chars();
    match chars.next() {
        Some(c) if c.is_ascii_alphabetic() || c == '_' => {}
        _ => return false,
    }
    chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

fn json_number(value: f64) -> Result<Value, String> {
    if !value.is_finite() {
        return Err("Numeric result is not finite".to_string());
    }
    let number = if (value.fract().abs() < f64::EPSILON)
        && value >= i64::MIN as f64
        && value <= i64::MAX as f64
    {
        serde_json::Number::from(value as i64)
    } else {
        serde_json::Number::from_f64(value)
            .ok_or_else(|| "Numeric result cannot be represented".to_string())?
    };
    Ok(Value::Number(number))
}

fn parse_number(label: &str, raw: &str) -> Result<f64, String> {
    f64::from_str(raw.trim()).map_err(|_| format!("{label} must be a valid number"))
}

fn read_string_field(
    fields: &HashMap<String, Value>,
    key: &str,
    context: &Value,
) -> Option<String> {
    fields.get(key).and_then(|value| {
        if let Some(s) = value.as_str() {
            Some(templ_str(s, context))
        } else if value.is_boolean() || value.is_number() {
            Some(value.to_string())
        } else {
            None
        }
    })
}

fn required_string_field(
    fields: &HashMap<String, Value>,
    key: &str,
    context: &Value,
    label: &str,
) -> Result<String, String> {
    let raw = read_string_field(fields, key, context).unwrap_or_default();
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(format!("{label} is required"));
    }
    Ok(trimmed.to_string())
}

fn read_number_field(
    fields: &HashMap<String, Value>,
    key: &str,
    context: &Value,
    label: &str,
) -> Result<Option<f64>, String> {
    if let Some(value) = fields.get(key) {
        if let Some(n) = value.as_f64() {
            return Ok(Some(n));
        }
        if let Some(s) = value.as_str() {
            if s.trim().is_empty() {
                return Ok(None);
            }
            return Ok(Some(parse_number(label, &templ_str(s, context))?));
        }
    }
    Ok(None)
}

fn required_number_field(
    fields: &HashMap<String, Value>,
    key: &str,
    context: &Value,
    label: &str,
) -> Result<f64, String> {
    read_number_field(fields, key, context, label)?.ok_or_else(|| format!("{label} is required"))
}

fn required_index_field(
    fields: &HashMap<String, Value>,
    key: &str,
    context: &Value,
) -> Result<usize, String> {
    let raw = read_number_field(fields, key, context, "Index")?
        .ok_or_else(|| "Index is required".to_string())?;
    if raw < 0.0 {
        return Err("Index must be zero or greater".to_string());
    }
    Ok(raw.floor() as usize)
}

fn parse_json_input(raw: &str) -> Result<Value, String> {
    serde_json::from_str::<Value>(raw).map_err(|err| format!("Invalid JSON input: {err}"))
}

fn flatten_json(prefix: &str, value: &Value, out: &mut Map<String, Value>) {
    match value {
        Value::Object(map) => {
            for (k, v) in map {
                let path = if prefix.is_empty() {
                    k.to_string()
                } else {
                    format!("{prefix}.{k}")
                };
                flatten_json(&path, v, out);
            }
        }
        Value::Array(arr) => {
            for (idx, v) in arr.iter().enumerate() {
                let path = if prefix.is_empty() {
                    idx.to_string()
                } else {
                    format!("{prefix}.{idx}")
                };
                flatten_json(&path, v, out);
            }
        }
        other => {
            out.insert(prefix.to_string(), other.clone());
        }
    }
}

fn normalized_path(path: &str) -> String {
    let replaced = path.replace(['[', ']'], ".");
    let mut cleaned = replaced.trim_matches('.').to_string();
    while cleaned.contains("..") {
        let compacted = cleaned.replace("..", ".");
        if compacted == cleaned {
            break;
        }
        cleaned = compacted;
    }
    cleaned
        .trim_matches('.')
        .trim_start_matches('$')
        .trim_start_matches('.')
        .to_string()
}

fn parse_date_with_format(input: &str, format: &str) -> Result<DateTime<Utc>, String> {
    match format {
        "rfc3339" => DateTime::parse_from_rfc3339(input)
            .map(|dt| dt.with_timezone(&Utc))
            .map_err(|_| "Date must be RFC3339 / ISO 8601".to_string()),
        "rfc2822" => DateTime::parse_from_rfc2822(input)
            .map(|dt| dt.with_timezone(&Utc))
            .map_err(|_| "Date must be RFC2822 (e.g., Thu, 01 Jan 1970 00:00:00 GMT)".to_string()),
        "date_only" => NaiveDate::parse_from_str(input, "%Y-%m-%d")
            .map(|d| d.and_hms_opt(0, 0, 0).unwrap())
            .map(|ndt| Utc.from_utc_datetime(&ndt))
            .map_err(|_| "Date must match YYYY-MM-DD".to_string()),
        "datetime" => NaiveDateTime::parse_from_str(input, "%Y-%m-%d %H:%M:%S")
            .map(|ndt| Utc.from_utc_datetime(&ndt))
            .map_err(|_| "Datetime must match YYYY-MM-DD HH:mm:ss (UTC)".to_string()),
        "us_short" => NaiveDate::parse_from_str(input, "%m/%d/%Y")
            .map(|d| d.and_hms_opt(0, 0, 0).unwrap())
            .map(|ndt| Utc.from_utc_datetime(&ndt))
            .map_err(|_| "Date must match MM/DD/YYYY".to_string()),
        "unix_seconds" => {
            let secs = i64::from_str(input.trim()).map_err(|_| "Unix seconds must be numeric")?;
            Utc.timestamp_opt(secs, 0)
                .single()
                .ok_or_else(|| "Unix seconds are out of range".to_string())
        }
        "unix_milliseconds" => {
            let millis =
                i64::from_str(input.trim()).map_err(|_| "Unix milliseconds must be numeric")?;
            let secs = millis.div_euclid(1000);
            let nsecs = ((millis.rem_euclid(1000)) * 1_000_000) as u32;
            Utc.timestamp_opt(secs, nsecs)
                .single()
                .ok_or_else(|| "Unix milliseconds are out of range".to_string())
        }
        other => Err(format!("Unsupported date format `{other}`")),
    }
}

fn parse_any_supported_date(input: &str) -> Result<DateTime<Utc>, String> {
    let formats = [
        "rfc3339",
        "rfc2822",
        "datetime",
        "date_only",
        "us_short",
        "unix_milliseconds",
        "unix_seconds",
    ];
    for fmt in formats {
        if let Ok(dt) = parse_date_with_format(input, fmt) {
            return Ok(dt);
        }
    }
    Err("Unable to parse date. Supported formats: ISO 8601, RFC2822, YYYY-MM-DD, YYYY-MM-DD HH:mm:ss, MM/DD/YYYY, Unix seconds, Unix milliseconds."
        .to_string())
}

fn coerce_bool(value: &Value) -> Result<bool, String> {
    match value {
        Value::Bool(b) => Ok(*b),
        Value::Number(n) => Ok(n.as_f64().unwrap_or(0.0) != 0.0),
        Value::String(s) => {
            let lowered = s.trim().to_ascii_lowercase();
            if lowered.is_empty() {
                return Ok(false);
            }
            match lowered.as_str() {
                "true" | "1" | "yes" | "y" | "on" => Ok(true),
                "false" | "0" | "no" | "n" | "off" => Ok(false),
                _ => Err(
                    "Cannot convert string to boolean. Use true/false, yes/no, or 1/0.".to_string(),
                ),
            }
        }
        Value::Null => Ok(false),
        Value::Array(arr) => Ok(!arr.is_empty()),
        Value::Object(map) => Ok(!map.is_empty()),
    }
}

fn is_empty_value(value: &Value) -> bool {
    match value {
        Value::Null => true,
        Value::Bool(b) => !*b,
        Value::String(s) => s.trim().is_empty(),
        Value::Number(_) => false,
        Value::Array(arr) => arr.is_empty(),
        Value::Object(map) => map.is_empty(),
    }
}

pub(crate) fn execute_formatter(
    node: &Node,
    context: &Value,
) -> Result<(Value, Option<String>), String> {
    let config_value = node.data.get("config").cloned().unwrap_or(Value::Null);
    let config = parse_formatter_config(&config_value)?;
    let FormatterConfig {
        operation,
        input,
        fields,
        output_key,
    } = config;

    let operation = operation.trim();
    let input_value = templ_str(&input, context);

    let result = match operation {
        "string.trim" => Value::String(input_value.trim().to_string()),
        "string.lowercase" => Value::String(input_value.to_lowercase()),
        "string.uppercase" => Value::String(input_value.to_uppercase()),
        "string.replace" => {
            let search_for = required_string_field(&fields, "search_for", context, "Search text")?;
            let replace_with =
                read_string_field(&fields, "replace_with", context).unwrap_or_default();
            Value::String(input_value.replace(&search_for, &replace_with))
        }
        "string.split" => {
            let delimiter = required_string_field(&fields, "delimiter", context, "Delimiter")?;
            let index = required_index_field(&fields, "index", context)?;
            let parts: Vec<&str> = input_value.split(&delimiter).collect();
            if index >= parts.len() {
                return Err(format!(
                    "Index {index} is out of range for split result of length {}.",
                    parts.len()
                ));
            }
            Value::String(parts[index].to_string())
        }
        "string.substring" => {
            let start = required_index_field(&fields, "start", context)?;
            let length = required_index_field(&fields, "length", context)?;
            let slice: String = input_value.chars().skip(start).take(length).collect();
            Value::String(slice)
        }
        "number.add" | "number.subtract" | "number.multiply" | "number.divide" => {
            let operand = required_number_field(&fields, "value", context, "Value")?;
            let input_num = parse_number("Input", &input_value)?;
            let computed = match operation {
                "number.add" => input_num + operand,
                "number.subtract" => input_num - operand,
                "number.multiply" => input_num * operand,
                "number.divide" => {
                    if operand.abs() < f64::EPSILON {
                        return Err("Cannot divide by zero.".to_string());
                    }
                    input_num / operand
                }
                _ => input_num,
            };
            json_number(computed)?
        }
        "number.round" => {
            let places =
                required_number_field(&fields, "decimal_places", context, "Decimal places")?;
            if places < 0.0 {
                return Err("Decimal places must be zero or greater.".to_string());
            }
            let input_num = parse_number("Input", &input_value)?;
            let places_int = places.floor();
            if places_int > 15.0 {
                return Err("Decimal places must be 15 or less.".to_string());
            }
            let factor = 10_f64.powi(places_int as i32);
            json_number((input_num * factor).round() / factor)?
        }
        "type.to_number" => {
            let input_num = parse_number("Input", &input_value)?;
            json_number(input_num)?
        }
        "json.pick" => {
            let path = required_string_field(&fields, "json_path", context, "JSON path")?;
            let parsed = parse_json_input(&input_value)?;
            let normalized = normalized_path(&path);
            lookup_path(&parsed, &normalized)
                .ok_or_else(|| format!("Path `{path}` not found in JSON input"))?
        }
        "json.flatten" => {
            let parsed = parse_json_input(&input_value)?;
            if !parsed.is_object() && !parsed.is_array() {
                parsed
            } else {
                let mut out = Map::new();
                flatten_json("", &parsed, &mut out);
                Value::Object(out)
            }
        }
        "json.merge" => {
            let base = parse_json_input(&input_value)?;
            let other_raw =
                required_string_field(&fields, "input_two", context, "Second JSON input")?;
            let other = parse_json_input(&other_raw)?;
            let base_obj = base
                .as_object()
                .cloned()
                .ok_or_else(|| "Primary input must be a JSON object to merge.".to_string())?;
            let other_obj = other
                .as_object()
                .cloned()
                .ok_or_else(|| "Second input must be a JSON object to merge.".to_string())?;

            let mut merged = base_obj;
            for (k, v) in other_obj {
                merged.insert(k, v);
            }
            Value::Object(merged)
        }
        "json.to_array" => {
            let delimiter = required_string_field(&fields, "delimiter", context, "Delimiter")?;
            let trim_items = fields
                .get("trim_items")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            let parsed = serde_json::from_str::<Value>(&input_value).ok();
            let base_array = match parsed {
                Some(Value::Array(arr)) => {
                    if trim_items {
                        arr.into_iter()
                            .map(|v| {
                                if let Some(s) = v.as_str() {
                                    Value::String(s.trim().to_string())
                                } else {
                                    v
                                }
                            })
                            .collect()
                    } else {
                        arr
                    }
                }
                Some(Value::String(s)) => s
                    .split(&delimiter)
                    .map(|item| {
                        if trim_items {
                            Value::String(item.trim().to_string())
                        } else {
                            Value::String(item.to_string())
                        }
                    })
                    .collect(),
                Some(other) => {
                    let raw = other.to_string();
                    raw.split(&delimiter)
                        .map(|s| {
                            if trim_items {
                                Value::String(s.trim().to_string())
                            } else {
                                Value::String(s.to_string())
                            }
                        })
                        .collect()
                }
                None => input_value
                    .split(&delimiter)
                    .map(|s| {
                        if trim_items {
                            Value::String(s.trim().to_string())
                        } else {
                            Value::String(s.to_string())
                        }
                    })
                    .collect(),
            };
            Value::Array(base_array)
        }
        "json.to_object" => {
            let key = required_string_field(&fields, "key_name", context, "Key name")?;
            let parsed = parse_flexible_value(&templ_str(&input_value, context));
            let mut map = Map::new();
            map.insert(key, parsed);
            Value::Object(map)
        }
        "date.parse" => {
            let format = required_string_field(&fields, "format", context, "Input format")?;
            let dt = parse_date_with_format(&input_value, &format)?;
            Value::String(dt.to_rfc3339())
        }
        "date.format" => {
            let format = required_string_field(&fields, "output_format", context, "Output format")?;
            let dt = parse_any_supported_date(&input_value)?;
            match format.as_str() {
                "unix_seconds" => json_number(dt.timestamp() as f64)?,
                "unix_milliseconds" => json_number(dt.timestamp_millis() as f64)?,
                "rfc3339" => Value::String(dt.to_rfc3339()),
                "rfc2822" => Value::String(dt.to_rfc2822()),
                "date_only" => Value::String(dt.format("%Y-%m-%d").to_string()),
                "datetime" => Value::String(dt.format("%Y-%m-%d %H:%M:%S").to_string()),
                "us_short" => Value::String(dt.format("%m/%d/%Y").to_string()),
                other => {
                    return Err(format!("Unsupported output format `{other}`"));
                }
            }
        }
        "date.adjust" => {
            let dt = parse_any_supported_date(&input_value)?;
            let days = read_number_field(&fields, "days", context, "Days")?.unwrap_or(0.0);
            let hours = read_number_field(&fields, "hours", context, "Hours")?.unwrap_or(0.0);
            let minutes = read_number_field(&fields, "minutes", context, "Minutes")?.unwrap_or(0.0);

            if days == 0.0 && hours == 0.0 && minutes == 0.0 {
                return Err("Add at least one offset (days, hours, or minutes).".to_string());
            }

            let mut adjusted = dt;
            adjusted = adjusted
                .checked_add_signed(chrono::Duration::days(days as i64))
                .ok_or_else(|| "Adjusted date is out of range".to_string())?;
            adjusted = adjusted
                .checked_add_signed(chrono::Duration::hours(hours as i64))
                .ok_or_else(|| "Adjusted date is out of range".to_string())?;
            adjusted = adjusted
                .checked_add_signed(chrono::Duration::minutes(minutes as i64))
                .ok_or_else(|| "Adjusted date is out of range".to_string())?;

            Value::String(adjusted.to_rfc3339())
        }
        "date.extract" => {
            let component = required_string_field(&fields, "component", context, "Component")?;
            let tz_str = required_string_field(&fields, "timezone", context, "Timezone")?;
            let tz: Tz = tz_str
                .parse()
                .map_err(|_| format!("Invalid timezone `{tz_str}`"))?;
            let dt = parse_any_supported_date(&input_value)?;
            let localized = dt.with_timezone(&tz);
            match component.as_str() {
                "year" => json_number(localized.year() as f64)?,
                "month" => json_number(localized.month() as f64)?,
                "day" => json_number(localized.day() as f64)?,
                "hour" => json_number(localized.hour() as f64)?,
                "minute" => json_number(localized.minute() as f64)?,
                "second" => json_number(localized.second() as f64)?,
                "weekday" => json_number(localized.weekday().number_from_monday() as f64)?,
                other => return Err(format!("Unsupported component `{other}`")),
            }
        }
        "bool.to_boolean" => {
            let parsed = parse_flexible_value(&input_value);
            Value::Bool(coerce_bool(&parsed)?)
        }
        "bool.is_empty" => {
            let parsed = parse_flexible_value(&input_value);
            Value::Bool(is_empty_value(&parsed))
        }
        "type.to_string" => {
            let parsed = parse_flexible_value(&input_value);
            let text = match parsed {
                Value::String(s) => s,
                Value::Number(n) => n.to_string(),
                Value::Bool(b) => b.to_string(),
                Value::Null => "".to_string(),
                other => other.to_string(),
            };
            Value::String(text)
        }
        other => {
            return Err(format!("Unsupported formatter operation `{other}`"));
        }
    };

    let output_key = output_key.trim();
    let mut map = Map::new();
    map.insert(output_key.to_string(), result);
    Ok((Value::Object(map), None))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn formatter_node(config: FormatterConfig) -> Node {
        Node {
            id: "formatter-1".to_string(),
            kind: "formatter".to_string(),
            data: json!({ "config": config }),
        }
    }

    #[test]
    fn trims_and_outputs_under_key() {
        let config = FormatterConfig {
            operation: "string.trim".into(),
            input: "  hello  ".into(),
            fields: HashMap::new(),
            output_key: "clean".into(),
        };
        let node = formatter_node(config);
        let (output, _) = execute_formatter(&node, &json!({})).expect("trim succeeds");
        assert_eq!(output.get("clean").and_then(Value::as_str), Some("hello"));
    }

    #[test]
    fn adds_numbers_and_returns_number_type() {
        let mut fields = HashMap::new();
        fields.insert("value".into(), Value::Number(5.into()));
        let config = FormatterConfig {
            operation: "number.add".into(),
            input: "10".into(),
            fields,
            output_key: "sum".into(),
        };
        let node = formatter_node(config);
        let (output, _) = execute_formatter(&node, &json!({})).expect("addition succeeds");
        assert!(output.get("sum").and_then(Value::as_f64).is_some());
        assert_eq!(output.get("sum").and_then(Value::as_i64), Some(15));
    }

    #[test]
    fn divide_by_zero_errors() {
        let mut fields = HashMap::new();
        fields.insert("value".into(), Value::Number(0.into()));
        let config = FormatterConfig {
            operation: "number.divide".into(),
            input: "12".into(),
            fields,
            output_key: "out".into(),
        };
        let node = formatter_node(config);
        let err = execute_formatter(&node, &json!({})).expect_err("division by zero fails");
        assert!(err.contains("divide by zero"));
    }

    #[test]
    fn json_pick_uses_path() {
        let mut fields = HashMap::new();
        fields.insert("json_path".into(), Value::String("items.0.id".into()));
        let config = FormatterConfig {
            operation: "json.pick".into(),
            input: r#"{"items":[{"id":42,"name":"Widget"}]}"#.into(),
            fields,
            output_key: "picked".into(),
        };
        let node = formatter_node(config);
        let (output, _) = execute_formatter(&node, &json!({})).expect("pick succeeds");
        assert_eq!(output.get("picked").and_then(Value::as_i64), Some(42));
    }

    #[test]
    fn json_to_array_splits_and_trims() {
        let mut fields = HashMap::new();
        fields.insert("delimiter".into(), Value::String(",".into()));
        fields.insert("trim_items".into(), Value::Bool(true));
        let config = FormatterConfig {
            operation: "json.to_array".into(),
            input: "a, b ,c".into(),
            fields,
            output_key: "arr".into(),
        };
        let node = formatter_node(config);
        let (output, _) = execute_formatter(&node, &json!({})).expect("array conversion succeeds");
        let arr = output
            .get("arr")
            .and_then(Value::as_array)
            .cloned()
            .unwrap();
        assert_eq!(arr.len(), 3);
        assert_eq!(arr[0], Value::String("a".into()));
        assert_eq!(arr[1], Value::String("b".into()));
    }

    #[test]
    fn date_format_converts_to_requested_format() {
        let mut fields = HashMap::new();
        fields.insert("output_format".into(), Value::String("date_only".into()));
        let config = FormatterConfig {
            operation: "date.format".into(),
            input: "2025-01-02T03:04:05Z".into(),
            fields,
            output_key: "formatted".into(),
        };
        let node = formatter_node(config);
        let (output, _) = execute_formatter(&node, &json!({})).expect("formatting succeeds");
        assert_eq!(
            output.get("formatted").and_then(Value::as_str),
            Some("2025-01-02")
        );
    }

    #[test]
    fn date_extract_respects_timezone() {
        let mut fields = HashMap::new();
        fields.insert("component".into(), Value::String("hour".into()));
        fields.insert("timezone".into(), Value::String("America/New_York".into()));
        let config = FormatterConfig {
            operation: "date.extract".into(),
            input: "2025-01-02T15:00:00Z".into(),
            fields,
            output_key: "hour".into(),
        };
        let node = formatter_node(config);
        let (output, _) = execute_formatter(&node, &json!({})).expect("extraction succeeds");
        assert_eq!(output.get("hour").and_then(Value::as_i64), Some(10));
    }

    #[test]
    fn bool_is_empty_handles_arrays() {
        let config = FormatterConfig {
            operation: "bool.is_empty".into(),
            input: "[]".into(),
            fields: HashMap::new(),
            output_key: "empty".into(),
        };
        let node = formatter_node(config);
        let (output, _) = execute_formatter(&node, &json!({})).expect("emptiness works");
        assert_eq!(output.get("empty"), Some(&Value::Bool(true)));
    }

    #[test]
    fn merge_combines_objects() {
        let mut fields = HashMap::new();
        fields.insert("input_two".into(), Value::String(r#"{"b":2,"c":3}"#.into()));
        let config = FormatterConfig {
            operation: "json.merge".into(),
            input: r#"{"a":1,"b":1}"#.into(),
            fields,
            output_key: "obj".into(),
        };
        let node = formatter_node(config);
        let (output, _) = execute_formatter(&node, &json!({})).expect("merge succeeds");
        let obj = output
            .get("obj")
            .and_then(Value::as_object)
            .cloned()
            .unwrap();
        assert_eq!(obj.get("a"), Some(&Value::Number(1.into())));
        assert_eq!(obj.get("b"), Some(&Value::Number(2.into())));
        assert_eq!(obj.get("c"), Some(&Value::Number(3.into())));
    }
}
