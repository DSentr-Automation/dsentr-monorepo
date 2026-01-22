use std::collections::HashSet;
use std::time::Duration;

use chrono::Utc;
use hmac::{Hmac, Mac};
use reqwest::Url;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::engine::actions::registry::{ActionExecutionSemantics, ActionManifest, ActionValidator};
use crate::engine::actions::validate_required_fields;
use crate::engine::graph::Node;
use crate::engine::templating::templ_str;
use crate::services::smtp_mailer::{SmtpConfig, TlsMode};
use crate::state::AppState;
use tokio::time::timeout;

pub(crate) const MANIFEST: ActionManifest = ActionManifest {
    action_type: "email",
    required_fields: &["params"],
    execution_semantics: ActionExecutionSemantics::Standard,
};

pub(crate) struct EmailValidator;

impl ActionValidator for EmailValidator {
    fn validate(&self, node: &Node) -> Result<(), String> {
        validate_required_fields(node, MANIFEST.required_fields)
    }
}

fn is_valid_email_address(value: &str) -> bool {
    let trimmed = value.trim();
    if trimmed.is_empty() || trimmed.contains(' ') {
        return false;
    }
    let mut parts = trimmed.split('@');
    let local = parts.next().unwrap_or("");
    let domain = match parts.next() {
        Some(d) => d,
        None => return false,
    };
    if parts.next().is_some() {
        return false;
    }
    if local.is_empty() || domain.is_empty() {
        return false;
    }
    if domain.starts_with('.') || domain.ends_with('.') {
        return false;
    }
    domain.contains('.')
}

fn parse_recipient_list(raw: &str) -> Result<Vec<String>, String> {
    let mut recipients = Vec::new();
    let mut seen = HashSet::new();
    for entry in raw.split(',').map(|s| s.trim()).filter(|s| !s.is_empty()) {
        if !is_valid_email_address(entry) {
            return Err(format!("Invalid recipient email: {}", entry));
        }
        let lowered = entry.to_lowercase();
        if !seen.insert(lowered) {
            return Err(format!("Duplicate recipient email: {}", entry));
        }
        recipients.push(entry.to_string());
    }
    if recipients.is_empty() {
        return Err("Recipient email(s) required".to_string());
    }
    Ok(recipients)
}

type HmacSha256 = Hmac<Sha256>;

struct AwsSignature {
    authorization: String,
    amz_date: String,
    payload_hash: String,
}

fn derive_aws_signing_key(
    secret_key: &str,
    date_stamp: &str,
    region: &str,
    service: &str,
) -> Result<Vec<u8>, String> {
    let mut mac = HmacSha256::new_from_slice(format!("AWS4{}", secret_key).as_bytes())
        .map_err(|_| "Invalid AWS secret key".to_string())?;
    mac.update(date_stamp.as_bytes());
    let k_date = mac.finalize().into_bytes();

    let mut mac = HmacSha256::new_from_slice(k_date.as_slice())
        .map_err(|_| "Invalid AWS signing key (date)".to_string())?;
    mac.update(region.as_bytes());
    let k_region = mac.finalize().into_bytes();

    let mut mac = HmacSha256::new_from_slice(k_region.as_slice())
        .map_err(|_| "Invalid AWS signing key (region)".to_string())?;
    mac.update(service.as_bytes());
    let k_service = mac.finalize().into_bytes();

    let mut mac = HmacSha256::new_from_slice(k_service.as_slice())
        .map_err(|_| "Invalid AWS signing key (service)".to_string())?;
    mac.update(b"aws4_request");
    Ok(mac.finalize().into_bytes().to_vec())
}

#[allow(clippy::too_many_arguments)]
fn sign_aws_request(
    access_key: &str,
    secret_key: &str,
    region: &str,
    service: &str,
    method: &str,
    canonical_uri: &str,
    canonical_query: &str,
    host: &str,
    payload: &[u8],
) -> Result<AwsSignature, String> {
    let now = Utc::now();
    let amz_date = now.format("%Y%m%dT%H%M%SZ").to_string();
    let date_stamp = now.format("%Y%m%d").to_string();

    let mut payload_hasher = Sha256::new();
    payload_hasher.update(payload);
    let payload_hash = hex::encode(payload_hasher.finalize());

    let canonical_headers = format!(
        "host:{}\nx-amz-content-sha256:{}\nx-amz-date:{}\n",
        host.to_lowercase(),
        payload_hash,
        amz_date
    );
    let signed_headers = "host;x-amz-content-sha256;x-amz-date";

    let canonical_request = format!(
        "{}\n{}\n{}\n{}\n{}\n{}",
        method, canonical_uri, canonical_query, canonical_headers, signed_headers, payload_hash
    );

    let mut canonical_hasher = Sha256::new();
    canonical_hasher.update(canonical_request.as_bytes());
    let canonical_hash = hex::encode(canonical_hasher.finalize());

    let credential_scope = format!("{}/{}/{}/aws4_request", date_stamp, region, service);
    let string_to_sign = format!(
        "AWS4-HMAC-SHA256\n{}\n{}\n{}",
        amz_date, credential_scope, canonical_hash
    );

    let signing_key = derive_aws_signing_key(secret_key, &date_stamp, region, service)?;
    let mut mac = HmacSha256::new_from_slice(&signing_key)
        .map_err(|_| "Failed to derive AWS signature".to_string())?;
    mac.update(string_to_sign.as_bytes());
    let signature = hex::encode(mac.finalize().into_bytes());

    let authorization = format!(
        "AWS4-HMAC-SHA256 Credential={}/{}, SignedHeaders={}, Signature={}",
        access_key, credential_scope, signed_headers, signature
    );

    Ok(AwsSignature {
        authorization,
        amz_date,
        payload_hash,
    })
}

fn determine_ses_endpoint(region: &str) -> Result<(String, String), String> {
    let default = format!("https://email.{}.amazonaws.com", region);
    let base = std::env::var("AWS_SES_ENDPOINT")
        .ok()
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
        .unwrap_or(default);

    let trimmed = base.trim_end_matches('/');
    let url = Url::parse(trimmed).map_err(|_| "Invalid AWS SES endpoint".to_string())?;
    let host = url
        .host_str()
        .ok_or_else(|| "Invalid AWS SES endpoint host".to_string())?;
    let host = if let Some(port) = url.port() {
        format!("{}:{}", host, port)
    } else {
        host.to_string()
    };

    Ok((trimmed.to_string(), host))
}

pub(crate) async fn execute_email(
    node: &Node,
    context: &Value,
    state: &AppState,
) -> Result<(Value, Option<String>), String> {
    let params = node.data.get("params").cloned().unwrap_or(Value::Null);
    let provider = node
        .data
        .get("emailProvider")
        .and_then(|v| v.as_str())
        .unwrap_or_default()
        .to_lowercase();
    match provider.as_str() {
        "smtp" => {
            let timeout_ms = node
                .data
                .get("timeout")
                .and_then(|v| v.as_u64())
                .unwrap_or(30_000);

            let host = params
                .get("smtpHost")
                .and_then(|v| v.as_str())
                .map(|s| s.trim())
                .filter(|s| !s.is_empty())
                .ok_or_else(|| "SMTP Host is required".to_string())?;

            let port_value = params
                .get("smtpPort")
                .ok_or_else(|| "Valid SMTP Port is required".to_string())?;

            let port = match port_value {
                Value::Number(n) => n
                    .as_u64()
                    .and_then(|n| u16::try_from(n).ok())
                    .filter(|n| *n > 0)
                    .ok_or_else(|| "Valid SMTP Port is required".to_string())?,
                Value::String(s) => s
                    .trim()
                    .parse::<u16>()
                    .ok()
                    .filter(|n| *n > 0)
                    .ok_or_else(|| "Valid SMTP Port is required".to_string())?,
                _ => return Err("Valid SMTP Port is required".to_string()),
            };

            let username = params
                .get("smtpUser")
                .and_then(|v| v.as_str())
                .map(|s| s.trim())
                .filter(|s| !s.is_empty())
                .ok_or_else(|| "SMTP User is required".to_string())?;

            let password = params
                .get("smtpPassword")
                .and_then(|v| v.as_str())
                .map(|s| s.trim())
                .filter(|s| !s.is_empty())
                .ok_or_else(|| "SMTP Password is required".to_string())?;

            let from_email = params
                .get("from")
                .and_then(|v| v.as_str())
                .map(|s| s.trim())
                .filter(|s| !s.is_empty())
                .ok_or_else(|| "From email is required".to_string())?;

            if !is_valid_email_address(from_email) {
                return Err("Invalid from email address".to_string());
            }

            let to_raw = params
                .get("to")
                .and_then(|v| v.as_str())
                .ok_or_else(|| "Recipient email(s) required".to_string())?;
            let recipients = parse_recipient_list(to_raw)?;

            let subject_raw = params.get("subject").and_then(|v| v.as_str()).unwrap_or("");
            let body_raw = params.get("body").and_then(|v| v.as_str()).unwrap_or("");
            let subject = templ_str(subject_raw, context);
            let body = templ_str(body_raw, context);

            if subject.trim().is_empty() {
                return Err("Subject is required".to_string());
            }
            if body.trim().is_empty() {
                return Err("Message body is required".to_string());
            }

            let parse_tls_mode = |value: &str| -> Result<TlsMode, String> {
                match value.to_lowercase().as_str() {
                    "starttls" => Ok(TlsMode::StartTls),
                    "implicit_tls" | "implicit" | "wrapper" => Ok(TlsMode::Implicit),
                    "none" | "plaintext" => Err(
                        "SMTP TLS must remain enabled; insecure SMTP transports are no longer supported".to_string(),
                    ),
                    other => Err(format!("Unsupported SMTP TLS mode: {}", other)),
                }
            };

            let tls_mode = match params.get("smtpTlsMode").and_then(|v| v.as_str()) {
                Some(mode) => parse_tls_mode(mode)?,
                None => {
                    let tls_enabled = params
                        .get("smtpTls")
                        .and_then(|v| v.as_bool())
                        .unwrap_or(true);
                    if !tls_enabled {
                        return Err(
                            "SMTP TLS must remain enabled; disable the smtpTls flag or provide a secure smtpTlsMode"
                                .to_string(),
                        );
                    } else if port == 465 {
                        TlsMode::Implicit
                    } else {
                        TlsMode::StartTls
                    }
                }
            };

            let config = SmtpConfig {
                host: host.to_string(),
                port,
                username: Some(username.to_string()),
                password: Some(password.to_string()),
                from: from_email.to_string(),
                tls_mode,
            };

            let tls_label = config.tls_mode.to_string();

            match timeout(
                Duration::from_millis(timeout_ms),
                state
                    .mailer
                    .send_email_with_config(&config, &recipients, &subject, &body),
            )
            .await
            {
                Ok(result) => result.map_err(|e| e.to_string())?,
                Err(_) => {
                    return Err(format!(
                        "SMTP send timed out after {}ms (host: {}:{}, tls: {})",
                        timeout_ms, config.host, config.port, tls_label
                    ));
                }
            }

            Ok((
                json!({
                    "sent": true,
                    "service": "SMTP",
                    "recipient_count": recipients.len(),
                }),
                None,
            ))
        }
        "sendgrid" => {
            let api_key = params
                .get("apiKey")
                .and_then(|v| v.as_str())
                .map(|s| s.trim())
                .filter(|s| !s.is_empty())
                .ok_or_else(|| "SendGrid API key is required".to_string())?
                .to_string();

            let from_email = params
                .get("from")
                .and_then(|v| v.as_str())
                .map(|s| s.trim())
                .filter(|s| !s.is_empty())
                .ok_or_else(|| "From email is required".to_string())?;
            if !is_valid_email_address(from_email) {
                return Err("Invalid from email address".to_string());
            }

            let to_raw = params
                .get("to")
                .and_then(|v| v.as_str())
                .ok_or_else(|| "Recipient email(s) required".to_string())?;
            let recipients = parse_recipient_list(to_raw)?;

            let subject_raw = params.get("subject").and_then(|v| v.as_str()).unwrap_or("");
            let body_raw = params.get("body").and_then(|v| v.as_str()).unwrap_or("");
            let subject = templ_str(subject_raw, context);
            let body = templ_str(body_raw, context);

            let template_id = params
                .get("templateId")
                .and_then(|v| v.as_str())
                .map(|s| s.trim())
                .filter(|s| !s.is_empty())
                .map(|s| s.to_string());

            if template_id.is_none() {
                if subject.trim().is_empty() {
                    return Err(
                        "Subject is required for SendGrid emails without a template".to_string()
                    );
                }
                if body.trim().is_empty() {
                    return Err(
                        "Message body is required for SendGrid emails without a template"
                            .to_string(),
                    );
                }
            }

            let mut personalization = serde_json::Map::new();
            personalization.insert(
                "to".to_string(),
                Value::Array(
                    recipients
                        .iter()
                        .map(|email| json!({ "email": email }))
                        .collect(),
                ),
            );

            if template_id.is_none() {
                personalization.insert("subject".to_string(), Value::String(subject.clone()));
            }

            if let Some(substitutions) = params.get("substitutions").and_then(|v| v.as_array()) {
                let mut template_data = serde_json::Map::new();
                for pair in substitutions {
                    let Some(key) = pair.get("key").and_then(|v| v.as_str()).map(|s| s.trim())
                    else {
                        continue;
                    };
                    if key.is_empty() {
                        continue;
                    }
                    let value_raw = pair.get("value").and_then(|v| v.as_str()).unwrap_or("");
                    let resolved = templ_str(value_raw, context);
                    template_data.insert(key.to_string(), Value::String(resolved));
                }
                if !template_data.is_empty() {
                    personalization.insert(
                        "dynamic_template_data".to_string(),
                        Value::Object(template_data),
                    );
                }
            }

            let mut request_body = serde_json::Map::new();
            request_body.insert("from".to_string(), json!({ "email": from_email }));
            request_body.insert(
                "personalizations".to_string(),
                Value::Array(vec![Value::Object(personalization)]),
            );

            if let Some(tpl) = template_id {
                request_body.insert("template_id".to_string(), Value::String(tpl));
            } else {
                request_body.insert(
                    "content".to_string(),
                    Value::Array(vec![json!({ "type": "text/plain", "value": body })]),
                );
            }

            let base = std::env::var("SENDGRID_API_BASE")
                .ok()
                .map(|v| v.trim().to_string())
                .filter(|v| !v.is_empty())
                .unwrap_or_else(|| "https://api.sendgrid.com/v3".to_string());
            let url = format!("{}/mail/send", base.trim_end_matches('/'));

            let client = reqwest::Client::new();
            let resp = client
                .post(url)
                .bearer_auth(api_key)
                .json(&Value::Object(request_body))
                .send()
                .await
                .map_err(|e| e.to_string())?;

            let status = resp.status();
            if !status.is_success() {
                let body_text = resp.text().await.unwrap_or_default();
                return Err(format!(
                    "SendGrid request failed (status {}): {}",
                    status.as_u16(),
                    body_text
                ));
            }

            let message_id = resp
                .headers()
                .get("x-message-id")
                .and_then(|v| v.to_str().ok())
                .map(|s| s.to_string());

            Ok((
                json!({
                    "sent": true,
                    "service": "SendGrid",
                    "status": status.as_u16(),
                    "message_id": message_id.clone()
                }),
                None,
            ))
        }
        "mailgun" => {
            let domain = params
                .get("domain")
                .and_then(|v| v.as_str())
                .map(|s| s.trim())
                .filter(|s| !s.is_empty())
                .ok_or_else(|| "Mailgun domain is required".to_string())?
                .to_string();

            let api_key = params
                .get("apiKey")
                .and_then(|v| v.as_str())
                .map(|s| s.trim())
                .filter(|s| !s.is_empty())
                .ok_or_else(|| "Mailgun API key is required".to_string())?
                .to_string();

            let region = params
                .get("region")
                .and_then(|v| v.as_str())
                .map(|s| s.trim())
                .filter(|s| !s.is_empty())
                .ok_or_else(|| "Mailgun region is required".to_string())?;

            let from_email = params
                .get("from")
                .and_then(|v| v.as_str())
                .map(|s| s.trim())
                .filter(|s| !s.is_empty())
                .ok_or_else(|| "From email is required".to_string())?;
            if !is_valid_email_address(from_email) {
                return Err("Invalid from email address".to_string());
            }

            let to_raw = params
                .get("to")
                .and_then(|v| v.as_str())
                .ok_or_else(|| "Recipient email(s) required".to_string())?;
            let recipients = parse_recipient_list(to_raw)?;

            let subject_raw = params.get("subject").and_then(|v| v.as_str()).unwrap_or("");
            let body_raw = params.get("body").and_then(|v| v.as_str()).unwrap_or("");
            let subject = templ_str(subject_raw, context);
            let body = templ_str(body_raw, context);

            let template = params
                .get("template")
                .and_then(|v| v.as_str())
                .map(|s| s.trim())
                .filter(|s| !s.is_empty())
                .map(|s| s.to_string());

            if template.is_none() {
                if subject.trim().is_empty() {
                    return Err(
                        "Subject is required for Mailgun emails without a template".to_string()
                    );
                }
                if body.trim().is_empty() {
                    return Err(
                        "Message body is required for Mailgun emails without a template"
                            .to_string(),
                    );
                }
            }

            let mut form_fields: Vec<(String, String)> = Vec::new();
            form_fields.push(("from".to_string(), from_email.to_string()));
            form_fields.push(("to".to_string(), recipients.join(", ")));

            if let Some(tpl) = template {
                form_fields.push(("template".to_string(), tpl));
                if let Some(vars) = params.get("variables").and_then(|v| v.as_array()) {
                    let mut resolved = serde_json::Map::new();
                    for pair in vars {
                        let Some(key) = pair.get("key").and_then(|v| v.as_str()).map(|s| s.trim())
                        else {
                            continue;
                        };
                        if key.is_empty() {
                            continue;
                        }
                        let value_raw = pair.get("value").and_then(|v| v.as_str()).unwrap_or("");
                        let templated = templ_str(value_raw, context);
                        resolved.insert(key.to_string(), Value::String(templated));
                    }
                    if !resolved.is_empty() {
                        let json_value = Value::Object(resolved);
                        if let Ok(serialized) = serde_json::to_string(&json_value) {
                            form_fields.push(("h:X-Mailgun-Variables".to_string(), serialized));
                        }
                    }
                }
            } else {
                form_fields.push(("subject".to_string(), subject));
                form_fields.push(("text".to_string(), body.clone()));
            }

            let default_base = if region.to_lowercase().contains("eu") {
                "https://api.eu.mailgun.net".to_string()
            } else {
                "https://api.mailgun.net".to_string()
            };

            let base = std::env::var("MAILGUN_API_BASE")
                .ok()
                .map(|v| v.trim().to_string())
                .filter(|v| !v.is_empty())
                .unwrap_or(default_base);

            let url = format!(
                "{}/v3/{}/messages",
                base.trim_end_matches('/'),
                domain.trim_matches('/')
            );

            let client = reqwest::Client::new();
            let resp = client
                .post(url)
                .basic_auth("api", Some(api_key))
                .form(&form_fields)
                .send()
                .await
                .map_err(|e| e.to_string())?;

            let status = resp.status();
            let headers = resp.headers().clone();
            let body_text = resp.text().await.map_err(|e| e.to_string())?;

            if !status.is_success() {
                return Err(format!(
                    "Mailgun request failed (status {}): {}",
                    status.as_u16(),
                    body_text
                ));
            }

            let mut message_id = headers
                .get("message-id")
                .and_then(|v| v.to_str().ok())
                .map(|s| s.to_string());
            if message_id.is_none() {
                if let Ok(json) = serde_json::from_str::<Value>(&body_text) {
                    message_id = json
                        .get("id")
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string());
                }
            }

            Ok((
                json!({
                    "sent": true,
                    "service": "Mailgun",
                    "status": status.as_u16(),
                    "message_id": message_id.clone()
                }),
                None,
            ))
        }
        "amazon_ses" => {
            let access_key = params
                .get("awsAccessKey")
                .and_then(|v| v.as_str())
                .map(|s| s.trim())
                .filter(|s| !s.is_empty())
                .ok_or_else(|| "AWS access key is required".to_string())?
                .to_string();

            let secret_key = params
                .get("awsSecretKey")
                .and_then(|v| v.as_str())
                .map(|s| s.trim())
                .filter(|s| !s.is_empty())
                .ok_or_else(|| "AWS secret key is required".to_string())?
                .to_string();

            let aws_region = params
                .get("awsRegion")
                .or_else(|| params.get("region"))
                .and_then(|v| v.as_str())
                .map(|s| s.trim())
                .filter(|s| !s.is_empty())
                .ok_or_else(|| "AWS region is required".to_string())?
                .to_string();

            let ses_version_raw = params
                .get("sesVersion")
                .and_then(|v| v.as_str())
                .map(|s| s.trim().to_lowercase());
            let ses_version = match ses_version_raw.as_deref() {
                Some("v1") | Some("ses v1") | Some("ses-v1") | Some("classic") => "v1",
                Some("v2") | Some("ses v2") | Some("ses-v2") | Some("api") => "v2",
                Some(other) => {
                    return Err(format!("Unsupported Amazon SES version: {}", other));
                }
                None => "v2",
            };

            let from_email = params
                .get("fromEmail")
                .or_else(|| params.get("from"))
                .and_then(|v| v.as_str())
                .map(|s| s.trim())
                .filter(|s| !s.is_empty())
                .ok_or_else(|| "From email is required".to_string())?;
            if !is_valid_email_address(from_email) {
                return Err("Invalid from email address".to_string());
            }
            let from_email = from_email.to_string();

            let to_raw = params
                .get("toEmail")
                .or_else(|| params.get("to"))
                .and_then(|v| v.as_str())
                .ok_or_else(|| "Recipient email(s) required".to_string())?;
            let recipients = parse_recipient_list(to_raw)?;

            let subject_raw = params.get("subject").and_then(|v| v.as_str()).unwrap_or("");
            let body_raw = params.get("body").and_then(|v| v.as_str()).unwrap_or("");
            let subject = templ_str(subject_raw, context);
            let body = templ_str(body_raw, context);

            let template = params
                .get("template")
                .and_then(|v| v.as_str())
                .map(|s| s.trim())
                .filter(|s| !s.is_empty())
                .map(|s| s.to_string());

            let mut template_data = serde_json::Map::new();
            if let Some(vars) = params.get("templateVariables").and_then(|v| v.as_array()) {
                for pair in vars {
                    let Some(key) = pair.get("key").and_then(|v| v.as_str()).map(|s| s.trim())
                    else {
                        continue;
                    };
                    if key.is_empty() {
                        continue;
                    }
                    let value_raw = pair.get("value").and_then(|v| v.as_str()).unwrap_or("");
                    let resolved = templ_str(value_raw, context);
                    template_data.insert(key.to_string(), Value::String(resolved));
                }
            }

            if template.is_none() {
                if subject.trim().is_empty() {
                    return Err(
                        "Subject is required for Amazon SES emails without a template".to_string(),
                    );
                }
                if body.trim().is_empty() {
                    return Err(
                        "Message body is required for Amazon SES emails without a template"
                            .to_string(),
                    );
                }
            }

            let (base_url, host) = determine_ses_endpoint(&aws_region)?;
            let client = reqwest::Client::new();

            match ses_version {
                "v1" => {
                    let mut form_fields: Vec<(String, String)> = Vec::new();
                    form_fields.push((
                        "Action".to_string(),
                        if template.is_some() {
                            "SendTemplatedEmail".to_string()
                        } else {
                            "SendEmail".to_string()
                        },
                    ));
                    form_fields.push(("Version".to_string(), "2010-12-01".to_string()));
                    form_fields.push(("Source".to_string(), from_email.clone()));
                    for (idx, email) in recipients.iter().enumerate() {
                        form_fields.push((
                            format!("Destination.ToAddresses.member.{}", idx + 1),
                            email.clone(),
                        ));
                    }

                    if let Some(tpl) = &template {
                        form_fields.push(("Template".to_string(), tpl.clone()));
                        let data = if template_data.is_empty() {
                            "{}".to_string()
                        } else {
                            serde_json::to_string(&Value::Object(template_data.clone()))
                                .map_err(|e| e.to_string())?
                        };
                        form_fields.push(("TemplateData".to_string(), data));
                    } else {
                        form_fields.push(("Message.Subject.Data".to_string(), subject.clone()));
                        form_fields.push(("Message.Body.Text.Data".to_string(), body.clone()));
                        form_fields.push(("Message.Body.Html.Data".to_string(), body.clone()));
                    }

                    let encoded = form_fields
                        .into_iter()
                        .map(|(k, v)| {
                            format!("{}={}", urlencoding::encode(&k), urlencoding::encode(&v))
                        })
                        .collect::<Vec<_>>()
                        .join("&");
                    let payload = encoded.into_bytes();

                    let signature = sign_aws_request(
                        &access_key,
                        &secret_key,
                        &aws_region,
                        "ses",
                        "POST",
                        "/",
                        "",
                        &host,
                        &payload,
                    )?;

                    let url = format!("{}/", base_url.trim_end_matches('/'));
                    let resp = client
                        .post(url)
                        .header(
                            "content-type",
                            "application/x-www-form-urlencoded; charset=utf-8",
                        )
                        .header("x-amz-date", signature.amz_date.clone())
                        .header("x-amz-content-sha256", signature.payload_hash.clone())
                        .header("authorization", signature.authorization.clone())
                        .body(payload)
                        .send()
                        .await
                        .map_err(|e| e.to_string())?;

                    let status = resp.status();
                    let text = resp.text().await.map_err(|e| e.to_string())?;

                    if !status.is_success() {
                        return Err(format!(
                            "Amazon SES request failed (status {}): {}",
                            status.as_u16(),
                            text
                        ));
                    }

                    let message_id = text
                        .split("<MessageId>")
                        .nth(1)
                        .and_then(|rest| rest.split("</MessageId>").next())
                        .map(|s| s.to_string());

                    Ok((
                        json!({
                            "sent": true,
                            "service": "Amazon SES",
                            "status": status.as_u16(),
                            "message_id": message_id.clone(),
                            "version": "v1"
                        }),
                        None,
                    ))
                }
                _ => {
                    let request_body = if let Some(tpl) = &template {
                        let data = if template_data.is_empty() {
                            "{}".to_string()
                        } else {
                            serde_json::to_string(&Value::Object(template_data.clone()))
                                .map_err(|e| e.to_string())?
                        };
                        json!({
                            "FromEmailAddress": from_email,
                            "Destination": {
                                "ToAddresses": recipients,
                            },
                            "Content": {
                                "Template": {
                                    "TemplateName": tpl,
                                    "TemplateData": data
                                }
                            }
                        })
                    } else {
                        json!({
                            "FromEmailAddress": from_email,
                            "Destination": {
                                "ToAddresses": recipients,
                            },
                            "Content": {
                                "Simple": {
                                    "Subject": { "Data": subject },
                                    "Body": {
                                        "Text": { "Data": body },
                                        "Html": { "Data": body }
                                    }
                                }
                            }
                        })
                    };

                    let payload = serde_json::to_vec(&request_body).map_err(|e| e.to_string())?;

                    let signature = sign_aws_request(
                        &access_key,
                        &secret_key,
                        &aws_region,
                        "ses",
                        "POST",
                        "/v2/email/outbound-emails",
                        "",
                        &host,
                        &payload,
                    )?;

                    let url = format!(
                        "{}/v2/email/outbound-emails",
                        base_url.trim_end_matches('/')
                    );
                    let resp = client
                        .post(url)
                        .header("content-type", "application/json")
                        .header("x-amz-date", signature.amz_date.clone())
                        .header("x-amz-content-sha256", signature.payload_hash.clone())
                        .header("authorization", signature.authorization.clone())
                        .body(payload)
                        .send()
                        .await
                        .map_err(|e| e.to_string())?;

                    let status = resp.status();
                    let text = resp.text().await.map_err(|e| e.to_string())?;

                    if !status.is_success() {
                        return Err(format!(
                            "Amazon SES request failed (status {}): {}",
                            status.as_u16(),
                            text
                        ));
                    }

                    let message_id = serde_json::from_str::<Value>(&text).ok().and_then(|v| {
                        v.get("MessageId")
                            .and_then(|m| m.as_str())
                            .map(|s| s.to_string())
                    });

                    Ok((
                        json!({
                            "sent": true,
                            "service": "Amazon SES",
                            "status": status.as_u16(),
                            "message_id": message_id.clone(),
                            "version": "v2"
                        }),
                        None,
                    ))
                }
            }
        }
        _ => Err(format!("Unsupported email service. Params: {}", params)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{
        Config, OAuthProviderConfig, OAuthSettings, StripeSettings, DEFAULT_WORKSPACE_MEMBER_LIMIT,
        DEFAULT_WORKSPACE_MONTHLY_RUN_LIMIT, RUNAWAY_LIMIT_5MIN,
    };
    use crate::db::{
        mock_db::{MockDb, NoopWorkflowRepository, NoopWorkspaceRepository},
        mock_stripe_event_log_repository::MockStripeEventLogRepository,
        workspace_connection_repository::NoopWorkspaceConnectionRepository,
    };
    use crate::services::oauth::account_service::OAuthAccountService;
    use crate::services::oauth::github::mock_github_oauth::MockGitHubOAuth;
    use crate::services::oauth::google::mock_google_oauth::MockGoogleOAuth;
    use crate::services::oauth::workspace_service::WorkspaceOAuthService;
    use crate::services::smtp_mailer::{MailError, Mailer, MockMailer, SmtpConfig, TlsMode};
    use crate::{
        state::{test_pg_pool, AppState},
        utils::jwt::JwtKeys,
    };
    use async_trait::async_trait;
    use axum::body::{Body, Bytes};
    use axum::extract::State;
    use axum::http::{header, HeaderMap, Method, StatusCode, Uri};
    use axum::response::Response;
    use axum::routing::post;
    use axum::Router;
    use base64::engine::general_purpose::STANDARD as BASE64;
    use base64::Engine;
    use once_cell::sync::Lazy;
    use reqwest::Client;
    use serde_json::{json, Value};
    use std::collections::HashMap;
    use std::net::SocketAddr;
    use std::sync::{Arc, Mutex, MutexGuard};
    use std::time::Duration;
    use tokio::net::TcpListener;
    use tokio::sync::mpsc::{unbounded_channel, UnboundedReceiver, UnboundedSender};
    use tokio::task::JoinHandle;
    use urlencoding::decode;

    use crate::engine::graph::Node;

    static ENV_LOCK: Lazy<Mutex<()>> = Lazy::new(|| Mutex::new(()));

    struct EnvGuard {
        key: &'static str,
        previous: Option<String>,
        _lock: MutexGuard<'static, ()>,
    }

    impl EnvGuard {
        fn set(key: &'static str, value: String) -> Self {
            let lock = ENV_LOCK.lock().expect("env mutex poisoned");
            let previous = std::env::var(key).ok();
            std::env::set_var(key, value);
            Self {
                key,
                previous,
                _lock: lock,
            }
        }
    }

    impl Drop for EnvGuard {
        fn drop(&mut self) {
            if let Some(previous) = self.previous.take() {
                std::env::set_var(self.key, previous);
            } else {
                std::env::remove_var(self.key);
            }
        }
    }

    fn test_config() -> Arc<Config> {
        Arc::new(Config {
            database_url: String::new(),
            frontend_origin: "http://localhost".into(),
            admin_origin: "http://localhost".into(),
            oauth: OAuthSettings {
                google: OAuthProviderConfig {
                    client_id: "stub".into(),
                    client_secret: "stub".into(),
                    redirect_uri: "http://localhost".into(),
                },
                github: OAuthProviderConfig {
                    client_id: "stub".into(),
                    client_secret: "stub".into(),
                    redirect_uri: "http://localhost".into(),
                },
                microsoft: OAuthProviderConfig {
                    client_id: "stub".into(),
                    client_secret: "stub".into(),
                    redirect_uri: "http://localhost".into(),
                },
                slack: OAuthProviderConfig {
                    client_id: "stub".into(),
                    client_secret: "stub".into(),
                    redirect_uri: "http://localhost".into(),
                },
                asana: OAuthProviderConfig {
                    client_id: "stub".into(),
                    client_secret: "stub".into(),
                    redirect_uri: "http://localhost".into(),
                },
                notion: OAuthProviderConfig {
                    client_id: "stub".into(),
                    client_secret: "stub".into(),
                    redirect_uri: "http://localhost".into(),
                },
                bitly: OAuthProviderConfig {
                    client_id: "stub".into(),
                    client_secret: "stub".into(),
                    redirect_uri: "http://localhost".into(),
                },
                raindrop: OAuthProviderConfig {
                    client_id: "stub".into(),
                    client_secret: "stub".into(),
                    redirect_uri: "http://localhost".into(),
                },
                token_encryption_key: vec![0u8; 32],
            },
            github_app: crate::config::GitHubAppSettings::default(),
            github_webhook_source_id: None,
            api_secrets_encryption_key: vec![1u8; 32],
            stripe: StripeSettings {
                client_id: "stub".into(),
                secret_key: "stub".into(),
                webhook_secret: "0123456789abcdef0123456789ABCDEF".into(),
            },
            auth_cookie_secure: true,
            jwt_issuer: "test-issuer".into(),
            jwt_audience: "test-audience".into(),
            workspace_member_limit: DEFAULT_WORKSPACE_MEMBER_LIMIT,
            workspace_monthly_run_limit: DEFAULT_WORKSPACE_MONTHLY_RUN_LIMIT,
            runaway_limit_5min: RUNAWAY_LIMIT_5MIN,
            webhook_ingress_dedupe_mode: crate::config::WebhookIngressDedupeMode::Off,
            webhook_verification_body_fields: Vec::new(),
            webhook_verification_header_fields: Vec::new(),
            webhook_event_type_fields: vec!["event_type".to_string(), "type".to_string()],
        })
    }

    fn test_jwt_keys() -> Arc<JwtKeys> {
        Arc::new(
            JwtKeys::from_secret("0123456789abcdef0123456789abcdef")
                .expect("test JWT secret should be valid"),
        )
    }

    fn test_state_with_mailer(mailer: Arc<dyn Mailer>) -> AppState {
        AppState {
            db: Arc::new(MockDb::default()),
            workflow_repo: Arc::new(NoopWorkflowRepository),
            workspace_repo: Arc::new(NoopWorkspaceRepository),
            workspace_connection_repo: Arc::new(NoopWorkspaceConnectionRepository),
            stripe_event_log_repo: Arc::new(MockStripeEventLogRepository::default()),
            db_pool: test_pg_pool(),
            mailer,
            google_oauth: Arc::new(MockGoogleOAuth::default()),
            github_oauth: Arc::new(MockGitHubOAuth::default()),
            oauth_accounts: OAuthAccountService::test_stub(),
            workspace_oauth: WorkspaceOAuthService::test_stub(),
            stripe: Arc::new(crate::services::stripe::MockStripeService::new()),
            integration_registry: crate::state::test_integration_registry(),
            http_client: Arc::new(Client::new()),
            config: test_config(),
            worker_id: Arc::new("worker".to_string()),
            worker_lease_seconds: 30,
            jwt_keys: test_jwt_keys(),
        }
    }

    fn test_state() -> AppState {
        test_state_with_mailer(Arc::new(MockMailer::default()))
    }

    #[derive(Clone)]
    struct HangingMailer {
        delay: Duration,
    }

    #[async_trait]
    impl Mailer for HangingMailer {
        async fn send_verification_email(&self, _to: &str, _token: &str) -> Result<(), MailError> {
            Ok(())
        }

        async fn send_reset_email(&self, _to: &str, _token: &str) -> Result<(), MailError> {
            Ok(())
        }

        async fn send_email_generic(
            &self,
            _to: &str,
            _subject: &str,
            _body: &str,
        ) -> Result<(), MailError> {
            Ok(())
        }

        async fn send_email_with_config(
            &self,
            _config: &SmtpConfig,
            _recipients: &[String],
            _subject: &str,
            _body: &str,
        ) -> Result<(), MailError> {
            tokio::time::sleep(self.delay).await;
            Ok(())
        }

        fn as_any(&self) -> &dyn std::any::Any {
            self
        }
    }

    #[tokio::test]
    async fn smtp_email_uses_custom_configuration_and_templates() {
        let state = test_state();
        let node = Node {
            id: "action-smtp".into(),
            kind: "action".into(),
            data: json!({
                "emailProvider": "SMTP",
                "params": {
                    "service": "SMTP",
                    "smtpHost": "smtp.example.com",
                    "smtpPort": 2525,
                    "smtpUser": "user@example.com",
                    "smtpPassword": "secret",
                    "from": "sender@example.com",
                    "to": "alice@example.com, bob@example.com",
                    "subject": "Hello {{ user.name }}",
                    "body": "Body for {{ user.name }}"
                }
            }),
        };

        let context = json!({ "user": { "name": "Alice" } });

        let (output, _) = execute_email(&node, &context, &state)
            .await
            .expect("smtp send should succeed");

        assert_eq!(output["sent"], true);
        assert_eq!(output["service"], "SMTP");
        assert_eq!(output["recipient_count"], 2);

        let mailer = state
            .mailer
            .as_any()
            .downcast_ref::<MockMailer>()
            .expect("mock mailer available");
        let records = mailer.sent_smtp_emails.lock().unwrap();
        assert_eq!(records.len(), 1);
        let record = &records[0];
        assert_eq!(record.config.host, "smtp.example.com");
        assert_eq!(record.config.port, 2525);
        assert_eq!(record.config.tls_mode, TlsMode::StartTls);
        assert_eq!(record.config.username.as_deref(), Some("user@example.com"));
        assert_eq!(record.config.from, "sender@example.com");
        assert_eq!(
            record.recipients,
            vec!["alice@example.com", "bob@example.com"]
        );
        assert_eq!(record.subject, "Hello Alice");
        assert_eq!(record.body, "Body for Alice");
    }

    #[tokio::test]
    async fn smtp_email_rejects_plaintext_configuration() {
        let state = test_state();
        let node = Node {
            id: "action-smtp-insecure".into(),
            kind: "action".into(),
            data: json!({
                "emailProvider": "SMTP",
                "params": {
                    "service": "SMTP",
                    "smtpHost": "smtp.example.com",
                    "smtpPort": 2525,
                    "smtpUser": "user@example.com",
                    "smtpPassword": "secret",
                    "smtpTls": false,
                    "from": "sender@example.com",
                    "to": "recipient@example.com",
                    "subject": "Hi",
                    "body": "Body"
                }
            }),
        };

        let error = execute_email(&node, &Value::Null, &state)
            .await
            .expect_err("plaintext SMTP configuration should be rejected");

        assert!(
            error.contains("TLS"),
            "expected TLS validation error, got: {}",
            error
        );
    }

    #[tokio::test]
    async fn smtp_email_defaults_to_tls_when_flag_omitted() {
        let state = test_state();
        let node = Node {
            id: "action-smtp-default".into(),
            kind: "action".into(),
            data: json!({
                "emailProvider": "SMTP",
                "params": {
                    "service": "SMTP",
                    "smtpHost": "smtp.example.com",
                    "smtpPort": 587,
                    "smtpUser": "user@example.com",
                    "smtpPassword": "secret",
                    "from": "sender@example.com",
                    "to": "recipient@example.com",
                    "subject": "Hi",
                    "body": "Body"
                }
            }),
        };

        let (output, _) = execute_email(&node, &Value::Null, &state)
            .await
            .expect("smtp send should succeed");

        assert_eq!(output["sent"], true);

        let mailer = state
            .mailer
            .as_any()
            .downcast_ref::<MockMailer>()
            .expect("mock mailer available");
        let records = mailer.sent_smtp_emails.lock().unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].config.tls_mode, TlsMode::StartTls);
    }

    #[tokio::test]
    async fn smtp_email_infers_implicit_tls_for_port_465_when_mode_omitted() {
        let state = test_state();
        let node = Node {
            id: "action-smtp-implicit".into(),
            kind: "action".into(),
            data: json!({
                "emailProvider": "SMTP",
                "params": {
                    "service": "SMTP",
                    "smtpHost": "smtp.example.com",
                    "smtpPort": 465,
                    "smtpUser": "user@example.com",
                    "smtpPassword": "secret",
                    "from": "sender@example.com",
                    "to": "recipient@example.com",
                    "subject": "Hi",
                    "body": "Body"
                }
            }),
        };

        let (output, _) = execute_email(&node, &Value::Null, &state)
            .await
            .expect("smtp send should succeed");

        assert_eq!(output["sent"], true);

        let mailer = state
            .mailer
            .as_any()
            .downcast_ref::<MockMailer>()
            .expect("mock mailer available");
        let records = mailer.sent_smtp_emails.lock().unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].config.tls_mode, TlsMode::Implicit);
    }

    #[tokio::test]
    async fn smtp_email_accepts_explicit_tls_mode_configuration() {
        let state = test_state();
        let node = Node {
            id: "action-smtp-explicit".into(),
            kind: "action".into(),
            data: json!({
                "emailProvider": "SMTP",
                "params": {
                    "service": "SMTP",
                    "smtpHost": "smtp.example.com",
                    "smtpPort": 465,
                    "smtpUser": "user@example.com",
                    "smtpPassword": "secret",
                    "smtpTlsMode": "implicit_tls",
                    "from": "sender@example.com",
                    "to": "recipient@example.com",
                    "subject": "Hi",
                    "body": "Body"
                }
            }),
        };

        let (output, _) = execute_email(&node, &Value::Null, &state)
            .await
            .expect("smtp send should succeed");

        assert_eq!(output["sent"], true);

        let mailer = state
            .mailer
            .as_any()
            .downcast_ref::<MockMailer>()
            .expect("mock mailer available");
        let records = mailer.sent_smtp_emails.lock().unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].config.tls_mode, TlsMode::Implicit);
    }

    #[tokio::test]
    async fn smtp_email_respects_node_timeout() {
        let state = test_state_with_mailer(Arc::new(HangingMailer {
            delay: Duration::from_millis(200),
        }));

        let node = Node {
            id: "action-smtp-timeout".into(),
            kind: "action".into(),
            data: json!({
                "emailProvider": "SMTP",
                "timeout": 25,
                "params": {
                    "service": "SMTP",
                    "smtpHost": "smtp.example.com",
                    "smtpPort": 2525,
                    "smtpUser": "user@example.com",
                    "smtpPassword": "secret",
                    "from": "sender@example.com",
                    "to": "recipient@example.com",
                    "subject": "Hi",
                    "body": "Body"
                }
            }),
        };

        let err = execute_email(&node, &Value::Null, &state)
            .await
            .expect_err("smtp send should respect timeout");

        assert!(err.contains("timed out"), "unexpected error: {err}");
        assert!(err.contains("smtp.example.com"), "missing host: {err}");
    }

    #[tokio::test]
    async fn smtp_email_rejects_invalid_from_address() {
        let state = test_state();
        let node = Node {
            id: "action-smtp-invalid".into(),
            kind: "action".into(),
            data: json!({
                "emailProvider": "SMTP",
                "params": {
                    "service": "SMTP",
                    "smtpHost": "smtp.example.com",
                    "smtpPort": "587",
                    "smtpUser": "user@example.com",
                    "smtpPassword": "secret",
                    "from": "invalid-from",
                    "to": "alice@example.com",
                    "subject": "Hi",
                    "body": "Body"
                }
            }),
        };

        let err = execute_email(&node, &Value::Null, &state)
            .await
            .expect_err("invalid from should error");

        assert!(err.contains("Invalid from email address"));
    }

    #[derive(Debug)]
    struct RecordedRequest {
        uri: Uri,
        headers: HeaderMap,
        body: Vec<u8>,
    }

    struct StubState<F>
    where
        F: Fn() -> Response<Body> + Send + Sync + 'static,
    {
        tx: UnboundedSender<RecordedRequest>,
        response_factory: Arc<F>,
    }

    impl<F> Clone for StubState<F>
    where
        F: Fn() -> Response<Body> + Send + Sync + 'static,
    {
        fn clone(&self) -> Self {
            Self {
                tx: self.tx.clone(),
                response_factory: Arc::clone(&self.response_factory),
            }
        }
    }

    async fn stub_handler<F>(
        State(state): State<StubState<F>>,
        _method: Method,
        uri: Uri,
        headers: HeaderMap,
        body: Bytes,
    ) -> Response<Body>
    where
        F: Fn() -> Response<Body> + Send + Sync + 'static,
    {
        let record = RecordedRequest {
            uri,
            headers,
            body: body.to_vec(),
        };
        let _ = state.tx.send(record);
        (state.response_factory)()
    }

    async fn spawn_stub_server<F>(
        response_factory: F,
    ) -> (
        SocketAddr,
        UnboundedReceiver<RecordedRequest>,
        JoinHandle<()>,
    )
    where
        F: Fn() -> Response<Body> + Send + Sync + 'static,
    {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (tx, rx) = unbounded_channel();
        let state = StubState {
            tx,
            response_factory: Arc::new(response_factory),
        };

        let app = Router::new()
            .route("/mail/send", post(stub_handler::<F>))
            .with_state(state);

        let server = axum::serve(listener, app.into_make_service());
        let handle = tokio::spawn(async move {
            if let Err(err) = server.await {
                eprintln!("stub server exited with error: {err}");
            }
        });
        (addr, rx, handle)
    }

    async fn spawn_mailgun_stub_server<F>(
        response_factory: F,
    ) -> (
        SocketAddr,
        UnboundedReceiver<RecordedRequest>,
        JoinHandle<()>,
    )
    where
        F: Fn() -> Response<Body> + Send + Sync + 'static,
    {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (tx, rx) = unbounded_channel();
        let state = StubState {
            tx,
            response_factory: Arc::new(response_factory),
        };

        let app = Router::new()
            .route("/v3/{domain}/messages", post(stub_handler::<F>))
            .with_state(state);

        let server = axum::serve(listener, app.into_make_service());
        let handle = tokio::spawn(async move {
            if let Err(err) = server.await {
                eprintln!("mailgun stub server exited with error: {err}");
            }
        });

        (addr, rx, handle)
    }

    async fn spawn_ses_stub_server<F>(
        response_factory: F,
    ) -> (
        SocketAddr,
        UnboundedReceiver<RecordedRequest>,
        JoinHandle<()>,
    )
    where
        F: Fn() -> Response<Body> + Send + Sync + 'static,
    {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (tx, rx) = unbounded_channel();
        let state = StubState {
            tx,
            response_factory: Arc::new(response_factory),
        };

        let app = Router::new()
            .route("/", post(stub_handler::<F>))
            .route("/v2/email/outbound-emails", post(stub_handler::<F>))
            .with_state(state);

        let server = axum::serve(listener, app.into_make_service());
        let handle = tokio::spawn(async move {
            if let Err(err) = server.await {
                eprintln!("ses stub server exited with error: {err}");
            }
        });

        (addr, rx, handle)
    }

    fn parse_form_body(body: &[u8]) -> HashMap<String, Vec<String>> {
        let mut map: HashMap<String, Vec<String>> = HashMap::new();
        let Ok(as_str) = String::from_utf8(body.to_vec()) else {
            return map;
        };

        for pair in as_str.split('&') {
            if pair.is_empty() {
                continue;
            }
            let mut parts = pair.splitn(2, '=');
            let key_enc = parts.next().unwrap_or("");
            let value_enc = parts.next().unwrap_or("");
            let key = decode(key_enc)
                .map(|v| v.into_owned())
                .unwrap_or_else(|_| key_enc.to_string());
            let value = decode(value_enc)
                .map(|v| v.into_owned())
                .unwrap_or_else(|_| value_enc.to_string());
            map.entry(key).or_default().push(value);
        }

        map
    }

    #[tokio::test]
    async fn sendgrid_plain_email_succeeds() {
        let (addr, mut rx, handle) = spawn_stub_server(|| {
            Response::builder()
                .status(StatusCode::ACCEPTED)
                .header("x-message-id", "abc123")
                .body(Body::from(Vec::<u8>::new()))
                .unwrap()
        })
        .await;

        let _guard = EnvGuard::set("SENDGRID_API_BASE", format!("http://{}", addr));
        let state = test_state();
        let node = Node {
            id: "action-1".into(),
            kind: "action".into(),
            data: json!({
                "emailProvider": "SendGrid",
                "params": {
                    "service": "SendGrid",
                    "apiKey": "SG.fake-key",
                    "from": "sender@example.com",
                    "to": "user@example.com",
                    "subject": "Hello {{user.name}}",
                    "body": "Body for {{user.name}}"
                }
            }),
        };

        let context = json!({ "user": { "name": "Alice" } });
        let (output, next) = execute_email(&node, &context, &state)
            .await
            .expect("sendgrid email should succeed");

        assert!(next.is_none());
        assert_eq!(output["sent"], true);
        assert_eq!(output["service"], "SendGrid");
        assert_eq!(output["status"], 202);
        assert_eq!(output["message_id"], "abc123");

        let req = rx.recv().await.expect("request should be recorded");
        handle.abort();

        assert_eq!(
            req.headers
                .get("authorization")
                .and_then(|v| v.to_str().ok()),
            Some("Bearer SG.fake-key"),
        );
        let body: Value = serde_json::from_slice(&req.body).expect("valid json body");
        assert_eq!(body["from"]["email"], "sender@example.com");
        assert_eq!(body["personalizations"][0]["subject"], "Hello Alice");
        assert_eq!(body["content"][0]["value"], "Body for Alice");
    }

    #[tokio::test]
    async fn sendgrid_template_email_includes_dynamic_data() {
        let (addr, mut rx, handle) = spawn_stub_server(|| {
            Response::builder()
                .status(StatusCode::ACCEPTED)
                .body(Body::from(Vec::<u8>::new()))
                .unwrap()
        })
        .await;

        let _guard = EnvGuard::set("SENDGRID_API_BASE", format!("http://{}", addr));
        let state = test_state();
        let node = Node {
            id: "action-2".into(),
            kind: "action".into(),
            data: json!({
                "emailProvider": "SendGrid",
                "params": {
                    "service": "SendGrid",
                    "apiKey": "SG.template",
                    "from": "sender@example.com",
                    "to": "user1@example.com, user2@example.com",
                    "templateId": "tmpl-123",
                    "substitutions": [
                        { "key": "firstName", "value": "{{ user.first }}" },
                        { "key": "account", "value": "{{ account.id }}" }
                    ]
                }
            }),
        };

        let context = json!({
            "user": { "first": "Bob" },
            "account": { "id": "A-100" }
        });

        let (output, _) = execute_email(&node, &context, &state)
            .await
            .expect("sendgrid template email should succeed");

        assert_eq!(output["sent"], true);
        assert_eq!(output["service"], "SendGrid");
        assert_eq!(output["status"], 202);

        let req = rx.recv().await.expect("request should be recorded");
        handle.abort();

        let body: Value = serde_json::from_slice(&req.body).expect("valid json body");
        assert_eq!(body["template_id"], "tmpl-123");
        assert!(body.get("content").is_none());
        let personalization = &body["personalizations"][0];
        let dynamic = personalization["dynamic_template_data"]
            .as_object()
            .unwrap();
        assert_eq!(dynamic.get("firstName").unwrap(), "Bob");
        assert_eq!(dynamic.get("account").unwrap(), "A-100");
        let to_emails = personalization["to"].as_array().unwrap();
        assert_eq!(to_emails.len(), 2);
    }

    #[tokio::test]
    async fn sendgrid_error_response_is_propagated() {
        let error_body = Arc::new(json!({ "errors": [{ "message": "Bad request" }] }).to_string());
        let (addr, mut rx, handle) = spawn_stub_server({
            let error_body = error_body.clone();
            move || {
                Response::builder()
                    .status(StatusCode::BAD_REQUEST)
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(error_body.as_str().to_owned()))
                    .unwrap()
            }
        })
        .await;

        let _guard = EnvGuard::set("SENDGRID_API_BASE", format!("http://{}", addr));
        let state = test_state();
        let node = Node {
            id: "action-3".into(),
            kind: "action".into(),
            data: json!({
                "emailProvider": "SendGrid",
                "params": {
                    "service": "SendGrid",
                    "apiKey": "SG.error",
                    "from": "sender@example.com",
                    "to": "user@example.com",
                    "subject": "Hi",
                    "body": "Body"
                }
            }),
        };

        let err = execute_email(&node, &Value::Null, &state)
            .await
            .expect_err("sendgrid call should fail");
        assert!(err.contains("status 400"));
        assert!(err.contains("Bad request"));

        let _ = rx.recv().await;
        handle.abort();
    }

    #[tokio::test]
    async fn sendgrid_duplicate_recipients_return_error() {
        let state = test_state();
        let node = Node {
            id: "action-4".into(),
            kind: "action".into(),
            data: json!({
                "emailProvider": "SendGrid",
                "params": {
                    "service": "SendGrid",
                    "apiKey": "SG.key",
                    "from": "sender@example.com",
                    "to": "user@example.com, user@example.com",
                    "subject": "Hi",
                    "body": "Body"
                }
            }),
        };

        let err = execute_email(&node, &Value::Null, &state)
            .await
            .expect_err("duplicate recipients should fail");
        assert!(err.contains("Duplicate recipient email"));
    }

    #[tokio::test]
    async fn mailgun_plain_email_succeeds() {
        let (addr, mut rx, handle) = spawn_mailgun_stub_server(|| {
            Response::builder()
                .status(StatusCode::OK)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(r#"{"id":"<2024.mailgun>"}"#))
                .unwrap()
        })
        .await;

        let _guard = EnvGuard::set("MAILGUN_API_BASE", format!("http://{}", addr));
        let state = test_state();
        let node = Node {
            id: "action-mailgun-1".into(),
            kind: "action".into(),
            data: json!({
                "emailProvider": "Mailgun",
                "params": {
                    "service": "Mailgun",
                    "domain": "mg.example.com",
                    "apiKey": "key-123",
                    "region": "US (api.mailgun.net)",
                    "from": "sender@example.com",
                    "to": "user@example.com",
                    "subject": "Hi",
                    "body": "Body"
                }
            }),
        };

        let (output, next) = execute_email(&node, &Value::Null, &state)
            .await
            .expect("mailgun email should succeed");

        assert_eq!(output["service"], "Mailgun");
        assert_eq!(output["status"], 200);
        assert_eq!(output["message_id"], "<2024.mailgun>");
        assert!(next.is_none());

        let req = rx.recv().await.expect("request should be recorded");
        handle.abort();

        let auth_header = req
            .headers
            .get(header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .expect("auth header present");
        assert!(auth_header.starts_with("Basic "));
        let token = &auth_header[6..];
        let decoded = BASE64
            .decode(token.as_bytes())
            .expect("valid base64 auth header");
        assert_eq!(String::from_utf8_lossy(&decoded), "api:key-123");

        let form = parse_form_body(&req.body);
        assert_eq!(
            form.get("subject").and_then(|v| v.first()),
            Some(&"Hi".to_string())
        );
        assert_eq!(
            form.get("text").and_then(|v| v.first()),
            Some(&"Body".to_string())
        );
    }

    #[tokio::test]
    async fn mailgun_template_email_includes_variables() {
        let (addr, mut rx, handle) = spawn_mailgun_stub_server(|| {
            Response::builder()
                .status(StatusCode::OK)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(r#"{"id":"<queued>"}"#))
                .unwrap()
        })
        .await;

        let _guard = EnvGuard::set("MAILGUN_API_BASE", format!("http://{}", addr));
        let state = test_state();
        let node = Node {
            id: "action-mailgun-2".into(),
            kind: "action".into(),
            data: json!({
                "emailProvider": "Mailgun",
                "params": {
                    "service": "Mailgun",
                    "domain": "mg.example.com",
                    "apiKey": "key-456",
                    "region": "EU (api.eu.mailgun.net)",
                    "from": "sender@example.com",
                    "to": "user1@example.com, user2@example.com",
                    "template": "welcome",
                    "variables": [
                        { "key": "firstName", "value": "{{ user.first }}" },
                        { "key": "account", "value": "{{ account.id }}" }
                    ]
                }
            }),
        };

        let context = json!({
            "user": { "first": "Bob" },
            "account": { "id": "A-100" }
        });

        let (output, next) = execute_email(&node, &context, &state)
            .await
            .expect("mailgun template email should succeed");

        assert_eq!(output["service"], "Mailgun");
        assert_eq!(output["status"], 200);
        assert_eq!(output["message_id"], "<queued>");
        assert!(next.is_none());

        let req = rx.recv().await.expect("request should be recorded");
        handle.abort();

        let form = parse_form_body(&req.body);
        assert_eq!(
            form.get("template").and_then(|v| v.first()),
            Some(&"welcome".to_string())
        );
        assert!(!form.contains_key("subject"));
        let vars_json = form
            .get("h:X-Mailgun-Variables")
            .and_then(|v| v.first())
            .expect("variables included");
        let vars: Value = serde_json::from_str(vars_json).expect("valid variables json");
        assert_eq!(vars["firstName"], "Bob");
        assert_eq!(vars["account"], "A-100");
        let to_values = form.get("to").and_then(|v| v.first()).unwrap();
        assert!(to_values.contains("user1@example.com"));
        assert!(to_values.contains("user2@example.com"));
    }

    #[tokio::test]
    async fn mailgun_error_response_is_propagated() {
        let error_body = Arc::new(json!({ "message": "Invalid domain" }).to_string());
        let (addr, mut rx, handle) = spawn_mailgun_stub_server({
            let error_body = error_body.clone();
            move || {
                Response::builder()
                    .status(StatusCode::BAD_REQUEST)
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(error_body.as_str().to_owned()))
                    .unwrap()
            }
        })
        .await;

        let _guard = EnvGuard::set("MAILGUN_API_BASE", format!("http://{}", addr));
        let state = test_state();
        let node = Node {
            id: "action-mailgun-3".into(),
            kind: "action".into(),
            data: json!({
                "emailProvider": "Mailgun",
                "params": {
                    "service": "Mailgun",
                    "domain": "mg.example.com",
                    "apiKey": "key-error",
                    "region": "US (api.mailgun.net)",
                    "from": "sender@example.com",
                    "to": "user@example.com",
                    "subject": "Hi",
                    "body": "Body"
                }
            }),
        };

        let err = execute_email(&node, &Value::Null, &state)
            .await
            .expect_err("mailgun call should fail");
        assert!(err.contains("status 400"));
        assert!(err.contains("Invalid domain"));

        let _ = rx.recv().await;
        handle.abort();
    }

    #[tokio::test]
    async fn mailgun_missing_subject_without_template_errors() {
        let state = test_state();
        let node = Node {
            id: "action-mailgun-4".into(),
            kind: "action".into(),
            data: json!({
                "emailProvider": "Mailgun",
                "params": {
                    "service": "Mailgun",
                    "domain": "mg.example.com",
                    "apiKey": "key-789",
                    "region": "US (api.mailgun.net)",
                    "from": "sender@example.com",
                    "to": "user@example.com",
                    "subject": "",
                    "body": ""
                }
            }),
        };

        let err = execute_email(&node, &Value::Null, &state)
            .await
            .expect_err("missing subject should fail");
        assert!(err.contains("Subject is required"));
    }

    #[tokio::test]
    async fn aws_ses_v2_plain_email_succeeds() {
        let (addr, mut rx, handle) = spawn_ses_stub_server(|| {
            Response::builder()
                .status(StatusCode::OK)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(r#"{"MessageId":"0001"}"#))
                .unwrap()
        })
        .await;

        let _guard = EnvGuard::set("AWS_SES_ENDPOINT", format!("http://{}", addr));
        let state = test_state();
        let node = Node {
            id: "action-ses-v2-1".into(),
            kind: "action".into(),
            data: json!({
                "emailProvider": "Amazon_SES",
                "params": {
                    "service": "Amazon SES",
                    "awsAccessKey": "AKIAFAKE",
                    "awsSecretKey": "secret",
                    "awsRegion": "us-east-1",
                    "sesVersion": "v2",
                    "fromEmail": "sender@example.com",
                    "toEmail": "recipient@example.com",
                    "subject": "Hello {{ user.name }}",
                    "body": "Body for {{ user.name }}"
                }
            }),
        };

        let context = json!({ "user": { "name": "Riley" } });
        let (output, next) = execute_email(&node, &context, &state)
            .await
            .expect("ses v2 email should succeed");

        assert_eq!(output["service"], "Amazon SES");
        assert_eq!(output["status"], 200);
        assert_eq!(output["version"], "v2");
        assert_eq!(output["message_id"], "0001");
        assert!(next.is_none());

        let req = rx.recv().await.expect("request should be recorded");
        handle.abort();

        assert_eq!(req.uri.path(), "/v2/email/outbound-emails");
        assert!(req.headers.contains_key("authorization"));
        assert!(req.headers.contains_key("x-amz-date"));

        let body: Value = serde_json::from_slice(&req.body).expect("valid json body");
        assert_eq!(
            body["Destination"]["ToAddresses"][0],
            "recipient@example.com"
        );
        assert_eq!(body["Content"]["Simple"]["Subject"]["Data"], "Hello Riley");
        assert_eq!(
            body["Content"]["Simple"]["Body"]["Text"]["Data"],
            "Body for Riley"
        );
    }

    #[tokio::test]
    async fn aws_ses_v2_template_email_uses_template_data() {
        let (addr, mut rx, handle) = spawn_ses_stub_server(|| {
            Response::builder()
                .status(StatusCode::OK)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(r#"{"MessageId":"tmpl-200"}"#))
                .unwrap()
        })
        .await;

        let _guard = EnvGuard::set("AWS_SES_ENDPOINT", format!("http://{}", addr));
        let state = test_state();
        let node = Node {
            id: "action-ses-v2-2".into(),
            kind: "action".into(),
            data: json!({
                "emailProvider": "Amazon_SES",
                "params": {
                    "service": "Amazon SES",
                    "awsAccessKey": "AKIAFAKE",
                    "awsSecretKey": "secret",
                    "awsRegion": "us-east-1",
                    "sesVersion": "v2",
                    "fromEmail": "sender@example.com",
                    "toEmail": "recipient@example.com",
                    "template": "welcome-email",
                    "templateVariables": [
                        { "key": "firstName", "value": "{{ user.first }}" },
                        { "key": "account", "value": "{{ account.id }}" }
                    ]
                }
            }),
        };

        let context = json!({
            "user": { "first": "Jamie" },
            "account": { "id": "ACC-9" }
        });

        let (output, _) = execute_email(&node, &context, &state)
            .await
            .expect("ses v2 template email should succeed");

        assert_eq!(output["version"], "v2");

        let req = rx.recv().await.expect("request should be recorded");
        handle.abort();

        let body: Value = serde_json::from_slice(&req.body).expect("valid json body");
        assert_eq!(body["Content"]["Template"]["TemplateName"], "welcome-email");
        let template_data = body["Content"]["Template"]["TemplateData"]
            .as_str()
            .expect("template data string");
        let data_json: Value = serde_json::from_str(template_data).expect("valid template data");
        assert_eq!(data_json["firstName"], "Jamie");
        assert_eq!(data_json["account"], "ACC-9");
    }

    #[tokio::test]
    async fn aws_ses_v1_plain_email_succeeds() {
        let (addr, mut rx, handle) = spawn_ses_stub_server(|| {
            Response::builder()
                .status(StatusCode::OK)
                .header(header::CONTENT_TYPE, "text/xml")
                .body(Body::from(
                    "<SendEmailResponse><SendEmailResult><MessageId>m-123</MessageId></SendEmailResult></SendEmailResponse>",
                ))
                .unwrap()
        })
        .await;

        let _guard = EnvGuard::set("AWS_SES_ENDPOINT", format!("http://{}", addr));
        let state = test_state();
        let node = Node {
            id: "action-ses-v1-1".into(),
            kind: "action".into(),
            data: json!({
                "emailProvider": "Amazon_SES",
                "params": {
                    "service": "Amazon SES",
                    "awsAccessKey": "AKIAFAKE",
                    "awsSecretKey": "secret",
                    "awsRegion": "us-east-1",
                    "sesVersion": "v1",
                    "fromEmail": "sender@example.com",
                    "toEmail": "recipient@example.com",
                    "subject": "Hello {{ user.name }}",
                    "body": "Plain body"
                }
            }),
        };

        let context = json!({ "user": { "name": "Sam" } });
        let (output, next) = execute_email(&node, &context, &state)
            .await
            .expect("ses v1 email should succeed");

        assert_eq!(output["version"], "v1");
        assert_eq!(output["message_id"], "m-123");
        assert!(next.is_none());

        let req = rx.recv().await.expect("request should be recorded");
        handle.abort();

        assert_eq!(req.uri.path(), "/");
        let form = parse_form_body(&req.body);
        assert_eq!(
            form.get("Action").and_then(|v| v.first()),
            Some(&"SendEmail".to_string())
        );
        assert_eq!(
            form.get("Message.Subject.Data").and_then(|v| v.first()),
            Some(&"Hello Sam".to_string())
        );
        assert_eq!(
            form.get("Message.Body.Text.Data").and_then(|v| v.first()),
            Some(&"Plain body".to_string())
        );
    }

    #[tokio::test]
    async fn aws_ses_v1_template_email_includes_template_data() {
        let (addr, mut rx, handle) = spawn_ses_stub_server(|| {
            Response::builder()
                .status(StatusCode::OK)
                .header(header::CONTENT_TYPE, "text/xml")
                .body(Body::from(
                    "<SendTemplatedEmailResponse><SendTemplatedEmailResult><MessageId>m-tmpl</MessageId></SendTemplatedEmailResult></SendTemplatedEmailResponse>",
                ))
                .unwrap()
        })
        .await;

        let _guard = EnvGuard::set("AWS_SES_ENDPOINT", format!("http://{}", addr));
        let state = test_state();
        let node = Node {
            id: "action-ses-v1-2".into(),
            kind: "action".into(),
            data: json!({
                "emailProvider": "Amazon_SES",
                "params": {
                    "service": "Amazon SES",
                    "awsAccessKey": "AKIAFAKE",
                    "awsSecretKey": "secret",
                    "awsRegion": "us-east-1",
                    "sesVersion": "v1",
                    "fromEmail": "sender@example.com",
                    "toEmail": "recipient@example.com",
                    "template": "welcome",
                    "templateVariables": [
                        { "key": "name", "value": "{{ user.name }}" }
                    ]
                }
            }),
        };

        let context = json!({ "user": { "name": "Skyler" } });
        let (output, _) = execute_email(&node, &context, &state)
            .await
            .expect("ses v1 templated email should succeed");

        assert_eq!(output["version"], "v1");

        let req = rx.recv().await.expect("request should be recorded");
        handle.abort();

        let form = parse_form_body(&req.body);
        assert_eq!(
            form.get("Action").and_then(|v| v.first()),
            Some(&"SendTemplatedEmail".to_string())
        );
        assert_eq!(
            form.get("Template").and_then(|v| v.first()),
            Some(&"welcome".to_string())
        );
        let data = form
            .get("TemplateData")
            .and_then(|v| v.first())
            .expect("template data present");
        let data_json: Value = serde_json::from_str(data).expect("valid template data json");
        assert_eq!(data_json["name"], "Skyler");
    }

    #[tokio::test]
    async fn aws_ses_missing_version_defaults_to_v2() {
        let (addr, mut rx, handle) = spawn_ses_stub_server(|| {
            Response::builder()
                .status(StatusCode::OK)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from("{\"MessageId\":\"m-456\"}"))
                .unwrap()
        })
        .await;

        let _guard = EnvGuard::set("AWS_SES_ENDPOINT", format!("http://{}", addr));
        let state = test_state();
        let node = Node {
            id: "action-ses-default-version".into(),
            kind: "action".into(),
            data: json!({
                "emailProvider": "Amazon_SES",
                "params": {
                    "service": "Amazon SES",
                    "awsAccessKey": "AKIAFAKE",
                    "awsSecretKey": "secret",
                    "awsRegion": "us-east-1",
                    "fromEmail": "sender@example.com",
                    "toEmail": "recipient@example.com",
                    "subject": "Hello",
                    "body": "Body"
                }
            }),
        };

        let (output, _) = execute_email(&node, &Value::Null, &state)
            .await
            .expect("ses should default to v2");

        assert_eq!(output["version"], "v2");

        let req = rx.recv().await.expect("request should be recorded");
        handle.abort();
        assert_eq!(req.uri.path(), "/v2/email/outbound-emails");
    }

    #[tokio::test]
    async fn aws_ses_invalid_version_is_rejected() {
        let state = test_state();
        let node = Node {
            id: "action-ses-invalid-version".into(),
            kind: "action".into(),
            data: json!({
                "emailProvider": "Amazon_SES",
                "params": {
                    "service": "Amazon SES",
                    "awsAccessKey": "AKIAFAKE",
                    "awsSecretKey": "secret",
                    "awsRegion": "us-east-1",
                    "sesVersion": "v3",
                    "fromEmail": "sender@example.com",
                    "toEmail": "recipient@example.com",
                    "subject": "Hello",
                    "body": "Body"
                }
            }),
        };

        let err = execute_email(&node, &Value::Null, &state)
            .await
            .expect_err("invalid version should error");

        assert!(err.contains("Unsupported Amazon SES version: v3"));
    }
}
