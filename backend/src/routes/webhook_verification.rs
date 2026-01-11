use axum::http::HeaderMap;
use serde_json::Value;

#[allow(dead_code)]
#[derive(Debug, Clone)]
pub enum VerificationMatch {
    BodyField(String),
    HeaderMatch {
        header: String,
        value: Option<String>,
    },
}

#[derive(Debug)]
pub enum VerificationOutcome {
    None,
    Single(VerificationMatch),
    Ambiguous(Vec<VerificationMatch>),
}

pub fn is_webhook_verification_request(
    body_fields: &[String],
    header_fields: &[(String, Option<String>)],
    headers: &HeaderMap,
    payload: &Value,
) -> VerificationOutcome {
    let mut matches = Vec::new();

    // Check body fields (presence-only)
    for field_name in body_fields {
        if payload.get(field_name).is_some() {
            matches.push(VerificationMatch::BodyField(field_name.clone()));
        }
    }

    // Check header fields
    for (header_name, expected_value) in header_fields {
        if let Some(header_value) = headers.get(header_name) {
            if let Ok(header_str) = header_value.to_str() {
                let trimmed_value = header_str.trim();
                match expected_value {
                    Some(expected) => {
                        if trimmed_value == expected.trim() {
                            matches.push(VerificationMatch::HeaderMatch {
                                header: header_name.clone(),
                                value: Some(expected.clone()),
                            });
                        }
                    }
                    None => {
                        matches.push(VerificationMatch::HeaderMatch {
                            header: header_name.clone(),
                            value: None,
                        });
                    }
                }
            }
        }
    }

    match matches.len() {
        0 => VerificationOutcome::None,
        1 => VerificationOutcome::Single(matches.into_iter().next().unwrap()),
        _ => VerificationOutcome::Ambiguous(matches),
    }
}

// Helper functions for logging
pub fn match_type_string(match_detail: &VerificationMatch) -> &'static str {
    match match_detail {
        VerificationMatch::BodyField(_) => "body_field",
        VerificationMatch::HeaderMatch { .. } => "header_match",
    }
}

pub fn indicator_source(match_detail: &VerificationMatch) -> &'static str {
    match match_detail {
        VerificationMatch::BodyField(_) => "body",
        VerificationMatch::HeaderMatch { .. } => "header",
    }
}

pub fn indicator_key(match_detail: &VerificationMatch) -> &str {
    match match_detail {
        VerificationMatch::BodyField(field) => field,
        VerificationMatch::HeaderMatch { header, .. } => header,
    }
}

pub fn indicator_value(
    match_detail: &VerificationMatch,
    payload: &Value,
    headers: &HeaderMap,
) -> String {
    match match_detail {
        VerificationMatch::BodyField(field) => {
            // Return debug string of payload[field] if present, otherwise "null"
            payload
                .get(field)
                .map(|value| format!("{:?}", value))
                .unwrap_or_else(|| "null".to_string())
        }
        VerificationMatch::HeaderMatch { header, .. } => {
            // Return actual header value string
            headers
                .get(header)
                .and_then(|value| value.to_str().ok())
                .map(|value| value.to_string())
                .unwrap_or_else(|| "null".to_string())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::{HeaderName, HeaderValue};
    use serde_json::json;

    fn create_test_header_map(headers: &[(&str, &str)]) -> HeaderMap {
        let mut map = HeaderMap::new();
        for &(name, value) in headers {
            let header_name = HeaderName::from_bytes(name.as_bytes()).unwrap();
            map.insert(header_name, HeaderValue::from_str(value).unwrap());
        }
        map
    }

    #[test]
    fn no_indicators_returns_none() {
        let headers = create_test_header_map(&[]);
        let payload = json!({});

        let outcome = is_webhook_verification_request(&[], &[], &headers, &payload);
        assert!(matches!(outcome, VerificationOutcome::None));
    }

    #[test]
    fn single_body_field_presence() {
        let headers = create_test_header_map(&[]);
        let payload = json!({"verification_token": "test"});

        let outcome = is_webhook_verification_request(
            &["verification_token".to_string()],
            &[],
            &headers,
            &payload,
        );

        if let VerificationOutcome::Single(VerificationMatch::BodyField(field)) = outcome {
            assert_eq!(field, "verification_token");
        } else {
            panic!("Expected Single BodyField match");
        }
    }

    #[test]
    fn single_header_with_expected_value() {
        let headers = create_test_header_map(&[("x-github-event", "ping")]);
        let payload = json!({});

        let outcome = is_webhook_verification_request(
            &[],
            &[("x-github-event".to_string(), Some("ping".to_string()))],
            &headers,
            &payload,
        );

        if let VerificationOutcome::Single(VerificationMatch::HeaderMatch { header, value }) =
            outcome
        {
            assert_eq!(header, "x-github-event");
            assert_eq!(value, Some("ping".to_string()));
        } else {
            panic!("Expected Single HeaderMatch with value");
        }
    }

    #[test]
    fn single_header_presence_only() {
        let headers = create_test_header_map(&[("x-webhook-signature", "v1=abc123")]);
        let payload = json!({});

        let outcome = is_webhook_verification_request(
            &[],
            &[("x-webhook-signature".to_string(), None)],
            &headers,
            &payload,
        );

        if let VerificationOutcome::Single(VerificationMatch::HeaderMatch { header, value }) =
            outcome
        {
            assert_eq!(header, "x-webhook-signature");
            assert_eq!(value, None);
        } else {
            panic!("Expected Single HeaderMatch without value");
        }
    }

    #[test]
    fn multiple_body_fields_ambiguous() {
        let headers = create_test_header_map(&[]);
        let payload = json!({"verification_token": "test", "challenge": "value"});

        let outcome = is_webhook_verification_request(
            &["verification_token".to_string(), "challenge".to_string()],
            &[],
            &headers,
            &payload,
        );

        assert!(matches!(outcome, VerificationOutcome::Ambiguous(_)));
    }

    #[test]
    fn body_and_header_ambiguous() {
        let headers = create_test_header_map(&[("x-github-event", "ping")]);
        let payload = json!({"verification_token": "test"});

        let outcome = is_webhook_verification_request(
            &["verification_token".to_string()],
            &[("x-github-event".to_string(), Some("ping".to_string()))],
            &headers,
            &payload,
        );

        assert!(matches!(outcome, VerificationOutcome::Ambiguous(_)));
    }

    #[test]
    fn null_body_value_accepted() {
        let headers = create_test_header_map(&[]);
        let payload = json!({"verification_token": null});

        let outcome = is_webhook_verification_request(
            &["verification_token".to_string()],
            &[],
            &headers,
            &payload,
        );

        if let VerificationOutcome::Single(VerificationMatch::BodyField(field)) = outcome {
            assert_eq!(field, "verification_token");
        } else {
            panic!("Expected Single BodyField match with null value");
        }
    }

    #[test]
    fn empty_string_body_value_accepted() {
        let headers = create_test_header_map(&[]);
        let payload = json!({"verification_token": ""});

        let outcome = is_webhook_verification_request(
            &["verification_token".to_string()],
            &[],
            &headers,
            &payload,
        );

        if let VerificationOutcome::Single(VerificationMatch::BodyField(field)) = outcome {
            assert_eq!(field, "verification_token");
        } else {
            panic!("Expected Single BodyField match with empty string value");
        }
    }

    #[test]
    fn header_value_trimming() {
        let headers = create_test_header_map(&[("x-github-event", "  ping  ")]);
        let payload = json!({});

        let outcome = is_webhook_verification_request(
            &[],
            &[("x-github-event".to_string(), Some("ping".to_string()))],
            &headers,
            &payload,
        );

        if let VerificationOutcome::Single(VerificationMatch::HeaderMatch { header, value }) =
            outcome
        {
            assert_eq!(header, "x-github-event");
            assert_eq!(value, Some("ping".to_string()));
        } else {
            panic!("Expected Single HeaderMatch with trimmed value");
        }
    }

    #[test]
    fn event_type_ignored_for_matching() {
        let headers = create_test_header_map(&[("x-github-event", "ping")]);
        let payload = json!({"event_type": "push", "verification_token": "test"});

        // event_type should not affect verification detection
        let outcome = is_webhook_verification_request(
            &["verification_token".to_string()],
            &[],
            &headers,
            &payload,
        );

        if let VerificationOutcome::Single(VerificationMatch::BodyField(field)) = outcome {
            assert_eq!(field, "verification_token");
        } else {
            panic!("Expected Single BodyField match, event_type should be ignored");
        }
    }

    #[test]
    fn verification_no_indicators() {
        let headers = HeaderMap::new();
        let payload = json!({});

        let outcome = is_webhook_verification_request(&[], &[], &headers, &payload);
        assert!(matches!(outcome, VerificationOutcome::None));
    }

    #[test]
    fn verification_single_body_field() {
        let headers = HeaderMap::new();
        let payload = json!({"verification_token": "test"});

        let outcome = is_webhook_verification_request(
            &["verification_token".to_string()],
            &[],
            &headers,
            &payload,
        );

        if let VerificationOutcome::Single(VerificationMatch::BodyField(field)) = outcome {
            assert_eq!(field, "verification_token");
        } else {
            panic!("Expected Single BodyField match");
        }
    }

    #[test]
    fn verification_ambiguous_multiple_fields() {
        let headers = HeaderMap::new();
        let payload = json!({"verification_token": "test", "challenge": "value"});

        let outcome = is_webhook_verification_request(
            &["verification_token".to_string(), "challenge".to_string()],
            &[],
            &headers,
            &payload,
        );

        assert!(matches!(outcome, VerificationOutcome::Ambiguous(_)));
    }
}
