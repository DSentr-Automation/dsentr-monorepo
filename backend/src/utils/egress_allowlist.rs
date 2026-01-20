pub(crate) fn normalize_egress_allowlist(entries: Vec<String>) -> (Vec<String>, Vec<String>) {
    let mut allowed = Vec::new();
    let mut rejected = Vec::new();

    for entry in entries {
        let normalized = entry.trim().to_ascii_lowercase();
        if normalized.is_empty() {
            rejected.push(normalized);
            continue;
        }

        if normalized.contains("://")
            || normalized.contains('/')
            || normalized.contains('?')
            || normalized.contains('#')
            || normalized.contains(':')
        {
            rejected.push(normalized);
            continue;
        }

        if normalized.contains('*') {
            match normalized.strip_prefix("*.") {
                Some(suffix) if !suffix.is_empty() && !suffix.contains('*') => {}
                _ => {
                    rejected.push(normalized);
                    continue;
                }
            }
        }

        allowed.push(normalized);
    }

    (allowed, rejected)
}

#[cfg(test)]
mod tests {
    use super::normalize_egress_allowlist;

    #[test]
    fn normalize_egress_allowlist_accepts_hosts_and_wildcards() {
        let entries = vec![
            "Example.com".to_string(),
            " *.Sub.Example.com ".to_string(),
            "*.example.org".to_string(),
        ];

        let (allowed, rejected) = normalize_egress_allowlist(entries);

        assert_eq!(
            allowed,
            vec![
                "example.com".to_string(),
                "*.sub.example.com".to_string(),
                "*.example.org".to_string(),
            ]
        );
        assert!(rejected.is_empty());
    }

    #[test]
    fn normalize_egress_allowlist_rejects_invalid_entries() {
        let entries = vec![
            " ".to_string(),
            "http://example.com".to_string(),
            "example.com/path".to_string(),
            "example.com?query=1".to_string(),
            "example.com#hash".to_string(),
            "example.com:443".to_string(),
            "*example.com".to_string(),
            "*.example.*".to_string(),
            "*.".to_string(),
        ];

        let (allowed, rejected) = normalize_egress_allowlist(entries);

        assert!(allowed.is_empty());
        assert_eq!(
            rejected,
            vec![
                "".to_string(),
                "http://example.com".to_string(),
                "example.com/path".to_string(),
                "example.com?query=1".to_string(),
                "example.com#hash".to_string(),
                "example.com:443".to_string(),
                "*example.com".to_string(),
                "*.example.*".to_string(),
                "*.".to_string(),
            ]
        );
    }
}
