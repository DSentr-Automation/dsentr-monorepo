use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::Duration;

use reqwest::header::{HeaderMap, HeaderName, HeaderValue};
use reqwest::redirect;
use serde_json::{json, Value};

use crate::engine::actions::registry::{ActionExecutionSemantics, ActionManifest, ActionValidator};
use crate::engine::actions::validate_required_fields;
use crate::engine::graph::Node;
use crate::engine::templating::templ_str;
use crate::models::workflow_run::WorkflowRun;
use crate::state::AppState;

pub(crate) const MANIFEST: ActionManifest = ActionManifest {
    action_type: "http",
    required_fields: &["params"],
    execution_semantics: ActionExecutionSemantics::Standard,
};

pub(crate) struct HttpValidator;

impl ActionValidator for HttpValidator {
    fn validate(&self, node: &Node) -> Result<(), String> {
        validate_required_fields(node, MANIFEST.required_fields)
    }
}

fn mask_json(value: &Value, secrets: &[String]) -> Value {
    match value {
        Value::String(s) => {
            let mut out = s.clone();
            for sec in secrets {
                if !sec.is_empty() && sec.len() >= 4 {
                    out = out.replace(sec, "[REDACTED]");
                }
            }
            Value::String(out)
        }
        Value::Array(arr) => Value::Array(arr.iter().map(|v| mask_json(v, secrets)).collect()),
        Value::Object(map) => {
            let mut out = serde_json::Map::new();
            for (k, v) in map.iter() {
                out.insert(k.clone(), mask_json(v, secrets));
            }
            Value::Object(out)
        }
        other => other.clone(),
    }
}

fn is_ip_blocked(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let octets = v4.octets();
            let a = octets[0];
            let b = octets[1];
            if a == 127 {
                return true;
            }
            if a == 10 {
                return true;
            }
            if a == 172 && (16..=31).contains(&b) {
                return true;
            }
            if a == 192 && b == 168 {
                return true;
            }
            if a == 169 && b == 254 {
                return true;
            }
            if *v4 == Ipv4Addr::new(169, 254, 169, 254) {
                return true;
            }
            false
        }
        IpAddr::V6(v6) => {
            if *v6 == Ipv6Addr::LOCALHOST {
                return true;
            }
            let seg0 = v6.segments()[0];
            if (seg0 & 0xfe00) == 0xfc00 {
                return true;
            }
            if (seg0 & 0xffc0) == 0xfe80 {
                return true;
            }
            false
        }
    }
}

fn is_host_blocked(host: &str, patterns: &[String]) -> bool {
    let h = host.to_lowercase();
    for pat in patterns {
        if let Some(suffix) = pat.strip_prefix("*.") {
            if h.ends_with(suffix) && h.len() > suffix.len() {
                if let Some(pos) = h.rfind(suffix) {
                    if pos > 0 && h.as_bytes()[pos - 1] == b'.' {
                        return true;
                    }
                }
            }
        } else if h == pat.as_str() {
            return true;
        }
    }
    false
}

fn is_host_allowed(host: &str, patterns: &[String]) -> bool {
    if host.is_empty() {
        return false;
    }
    for pat in patterns {
        if let Some(suffix) = pat.strip_prefix("*.") {
            if host.ends_with(suffix) && host.len() > suffix.len() {
                if let Some(pos) = host.rfind(suffix) {
                    if pos > 0 && host.as_bytes()[pos - 1] == b'.' {
                        return true;
                    }
                }
            }
        } else if host == pat.as_str() {
            return true;
        }
    }
    false
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn execute_http(
    node: &Node,
    context: &Value,
    allowed_hosts: &[String],
    disallowed_hosts: &[String],
    default_deny: bool,
    is_prod: bool,
    state: &AppState,
    run: &WorkflowRun,
) -> Result<(Value, Option<String>), String> {
    let params = node.data.get("params").cloned().unwrap_or(Value::Null);
    let manifest_http = node.data.get("http").cloned().unwrap_or(Value::Null);

    // ---- Resolve core fields (params override manifest) ----

    let url_raw = params
        .get("url")
        .and_then(|v| v.as_str())
        .or_else(|| manifest_http.get("url").and_then(|v| v.as_str()))
        .ok_or_else(|| "HTTP url is required".to_string())?;
    let url = templ_str(url_raw, context);

    let method = params
        .get("method")
        .and_then(|v| v.as_str())
        .or_else(|| manifest_http.get("method").and_then(|v| v.as_str()))
        .unwrap_or("GET");

    let body_type = params
        .get("bodyType")
        .and_then(|v| v.as_str())
        .or_else(|| manifest_http.get("bodyType").and_then(|v| v.as_str()))
        .unwrap_or("raw");

    let follow = params
        .get("followRedirects")
        .and_then(|v| v.as_bool())
        .unwrap_or(true);

    let auth_type = params
        .get("authType")
        .and_then(|v| v.as_str())
        .unwrap_or("none");

    let timeout_ms = node
        .data
        .get("timeout")
        .and_then(|v| v.as_u64())
        .unwrap_or(30_000);

    let retries = node
        .data
        .get("retries")
        .and_then(|v| v.as_u64())
        .unwrap_or(0) as usize;

    let allowed: Vec<String> = allowed_hosts.to_vec();

    // ---- URL validation / SSRF hardening ----

    let parsed = reqwest::Url::parse(&url).map_err(|e| e.to_string())?;
    if !matches!(parsed.scheme(), "http" | "https") {
        return Err("Only http/https schemes are allowed".to_string());
    }

    let host = parsed.host_str().unwrap_or("").to_lowercase();

    if is_host_blocked(&host, disallowed_hosts) {
        let msg = format!("Outbound HTTP blocked by denylist: {}", host);
        let _ = state
            .workflow_repo
            .insert_egress_block_event(
                run.user_id,
                run.workflow_id,
                run.id,
                &node.id,
                &url,
                &host,
                "denylist",
                &msg,
            )
            .await;
        return Err(json!({
            "error": "egress_blocked",
            "host": host,
            "rule": "denylist",
            "message": msg
        })
        .to_string());
    }

    if let Some(ip) = parsed.host_str().and_then(|h| h.parse::<IpAddr>().ok()) {
        if is_prod && is_ip_blocked(&ip) {
            let msg = "Outbound HTTP blocked by SSRF hardening".to_string();
            let _ = state
                .workflow_repo
                .insert_egress_block_event(
                    run.user_id,
                    run.workflow_id,
                    run.id,
                    &node.id,
                    &url,
                    &host,
                    "ssrf_hardening",
                    &msg,
                )
                .await;
            return Err(json!({
                "error": "egress_blocked",
                "host": host,
                "rule": "ssrf_hardening",
                "message": msg
            })
            .to_string());
        }
    }

    if default_deny {
        if allowed.is_empty() || !is_host_allowed(&host, &allowed) {
            let msg = format!("Outbound HTTP not allowed (default-deny): {}", host);
            let _ = state
                .workflow_repo
                .insert_egress_block_event(
                    run.user_id,
                    run.workflow_id,
                    run.id,
                    &node.id,
                    &url,
                    &host,
                    "default_deny",
                    &msg,
                )
                .await;
            return Err(json!({
                "error": "egress_blocked",
                "host": host,
                "rule": "default_deny",
                "message": msg
            })
            .to_string());
        }
    } else if !allowed.is_empty() && !is_host_allowed(&host, &allowed) {
        let msg = format!("Outbound HTTP not allowed: {}", host);
        let _ = state
            .workflow_repo
            .insert_egress_block_event(
                run.user_id,
                run.workflow_id,
                run.id,
                &node.id,
                &url,
                &host,
                "allowlist_miss",
                &msg,
            )
            .await;
        return Err(json!({
            "error": "egress_blocked",
            "host": host,
            "rule": "allowlist_miss",
            "message": msg
        })
        .to_string());
    }

    // ---- Redirect policy ----

    let redirect_policy = if follow {
        let allowed_clone = allowed.clone();
        let disallowed_clone = disallowed_hosts.to_vec();
        let default_deny_local = default_deny;
        let is_prod_local = is_prod;

        redirect::Policy::custom(move |attempt| {
            if attempt.previous().len() >= 10 {
                return attempt.stop();
            }

            let next = attempt.url();
            let host = next.host_str().unwrap_or("").to_lowercase();

            if is_host_blocked(&host, &disallowed_clone) {
                return attempt.stop();
            }

            if let Some(ip) = next.host_str().and_then(|h| h.parse::<IpAddr>().ok()) {
                if is_prod_local && is_ip_blocked(&ip) {
                    return attempt.stop();
                }
            }

            if default_deny_local {
                if is_host_allowed(&host, &allowed_clone) {
                    attempt.follow()
                } else {
                    attempt.stop()
                }
            } else if allowed_clone.is_empty() || is_host_allowed(&host, &allowed_clone) {
                attempt.follow()
            } else {
                attempt.stop()
            }
        })
    } else {
        redirect::Policy::none()
    };

    let client = reqwest::Client::builder()
        .redirect(redirect_policy)
        .timeout(Duration::from_millis(timeout_ms))
        .build()
        .map_err(|e| e.to_string())?;

    // ---- Headers ----

    let mut headers = HeaderMap::new();
    let headers_source = params
        .get("headers")
        .and_then(|v| v.as_array())
        .or_else(|| manifest_http.get("headers").and_then(|v| v.as_array()));

    if let Some(hs) = headers_source {
        for h in hs {
            if let (Some(k), Some(v)) = (
                h.get("key").and_then(|v| v.as_str()),
                h.get("value").and_then(|v| v.as_str()),
            ) {
                let resolved = templ_str(v, context);
                if let (Ok(name), Ok(val)) =
                    (HeaderName::try_from(k), HeaderValue::from_str(&resolved))
                {
                    headers.append(name, val);
                }
            }
        }
    }

    // ---- Query params ----

    let mut url_parsed = url.to_string();
    let query_source = params
        .get("queryParams")
        .and_then(|v| v.as_array())
        .or_else(|| manifest_http.get("queryParams").and_then(|v| v.as_array()));

    if let Some(qs) = query_source {
        let mut first = !url.contains('?');
        for qp in qs {
            if let (Some(k), Some(v)) = (
                qp.get("key").and_then(|v| v.as_str()),
                qp.get("value").and_then(|v| v.as_str()),
            ) {
                let v_resolved = templ_str(v, context);
                url_parsed.push(if first { '?' } else { '&' });
                first = false;
                url_parsed.push_str(&format!(
                    "{}={}",
                    urlencoding::encode(k),
                    urlencoding::encode(&v_resolved)
                ));
            }
        }
    }

    // ---- Request loop ----

    let mut attempt = 0usize;
    loop {
        attempt += 1;

        let mut req = match method {
            "POST" => client.post(&url_parsed),
            "PUT" => client.put(&url_parsed),
            "PATCH" => client.patch(&url_parsed),
            "DELETE" => client.delete(&url_parsed),
            "HEAD" => client.head(&url_parsed),
            _ => client.get(&url_parsed),
        }
        .headers(headers.clone());

        req = match auth_type {
            "basic" => {
                let u = params
                    .get("username")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                let p = params
                    .get("password")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                req.basic_auth(u.to_string(), Some(p.to_string()))
            }
            "bearer" => {
                let t = params.get("token").and_then(|v| v.as_str()).unwrap_or("");
                req.bearer_auth(t.to_string())
            }
            _ => req,
        };

        if !matches!(method, "GET" | "DELETE" | "HEAD") {
            match body_type {
                "json" => {
                    let body_raw = params
                        .get("body")
                        .and_then(|v| v.as_str())
                        .or_else(|| manifest_http.get("body").and_then(|v| v.as_str()))
                        .unwrap_or("");
                    let body = templ_str(body_raw, context);
                    if !body.is_empty() {
                        if let Ok(json) = serde_json::from_str::<Value>(&body) {
                            req = req.json(&json);
                        } else {
                            req = req.body(body);
                        }
                    }
                }
                "form" => {
                    let mut form = vec![];
                    let form_source = params
                        .get("formBody")
                        .and_then(|v| v.as_array())
                        .or_else(|| manifest_http.get("formBody").and_then(|v| v.as_array()));
                    if let Some(fs) = form_source {
                        for kv in fs {
                            if let (Some(k), Some(v)) = (
                                kv.get("key").and_then(|v| v.as_str()),
                                kv.get("value").and_then(|v| v.as_str()),
                            ) {
                                form.push((k.to_string(), templ_str(v, context)));
                            }
                        }
                    }
                    req = req.form(&form);
                }
                _ => {}
            }
        }

        match req.send().await {
            Ok(resp) => {
                let status = resp.status().as_u16();
                let headers = resp.headers().clone();

                let mut header_map = serde_json::Map::new();
                for (k, v) in headers.iter() {
                    if let Ok(s) = v.to_str() {
                        header_map.insert(k.as_str().to_string(), Value::String(s.to_string()));
                    }
                }

                let content_type = headers
                    .get("content-type")
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or("")
                    .to_string();

                let text = resp.text().await.unwrap_or_default();

                let body_value = if content_type.contains("application/json") {
                    serde_json::from_str::<Value>(&text).unwrap_or(Value::String(text))
                } else {
                    Value::String(text)
                };

                let outputs_raw = json!({
                    "status": status,
                    "headers": header_map,
                    "body": body_value,
                });

                let secrets_env = std::env::var("MASK_SECRETS").ok().unwrap_or_default();
                let secrets: Vec<String> = secrets_env
                    .split(',')
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty())
                    .collect();

                let outputs = mask_json(&outputs_raw, &secrets);
                return Ok((outputs, None));
            }
            Err(_) if attempt <= retries + 1 => {
                tokio::time::sleep(Duration::from_millis(250 * attempt as u64)).await;
            }
            Err(e) => return Err(e.to_string()),
        }
    }
}
