use std::env;

use crate::utils::encryption::{decode_key, EncryptionError};
use thiserror::Error;

pub const DEFAULT_WORKSPACE_MEMBER_LIMIT: i64 = 8;
pub const DEFAULT_WORKSPACE_MONTHLY_RUN_LIMIT: i64 = 20_000;
pub const RUNAWAY_LIMIT_5MIN: i64 = 500;

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("missing required environment variable: {name}")]
    MissingEnvVar { name: &'static str },
    #[error("failed to decode secret for {name}: {source}")]
    SecretDecode {
        name: &'static str,
        #[source]
        source: EncryptionError,
    },
    #[error("invalid value for {name}: {reason}")]
    InvalidEnvVar { name: &'static str, reason: String },
}

#[derive(Clone, Debug)]
pub struct OAuthProviderConfig {
    pub client_id: String,
    pub client_secret: String,
    pub redirect_uri: String,
}

#[derive(Clone, Debug, Default)]
pub struct GitHubAppSettings {
    pub app_id: Option<i64>,
    pub private_key: Option<String>,
    pub user_oauth_enabled: bool,
    pub user_token_refresh_enabled: bool,
}

impl GitHubAppSettings {
    pub fn is_configured(&self) -> bool {
        self.app_id.is_some()
            && self
                .private_key
                .as_deref()
                .map(|key| !key.trim().is_empty())
                .unwrap_or(false)
    }
}

#[derive(Clone, Debug)]
#[allow(dead_code)]
pub struct StripeSettings {
    pub client_id: String,
    pub secret_key: String,
    pub webhook_secret: String,
}

#[derive(Clone, Debug)]
pub struct OAuthSettings {
    pub google: OAuthProviderConfig,
    pub github: OAuthProviderConfig,
    pub microsoft: OAuthProviderConfig,
    pub slack: OAuthProviderConfig,
    pub asana: OAuthProviderConfig,
    pub notion: OAuthProviderConfig,
    pub bitly: OAuthProviderConfig,
    pub raindrop: OAuthProviderConfig,
    pub token_encryption_key: Vec<u8>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WebhookIngressDedupeMode {
    Off,
    LogOnly,
    Enforce,
}

#[derive(Clone, Debug)]
pub struct Config {
    pub database_url: String,
    pub frontend_origin: String,
    pub admin_origin: String,
    pub oauth: OAuthSettings,
    pub github_app: GitHubAppSettings,
    pub github_webhook_source_id: Option<String>,
    pub api_secrets_encryption_key: Vec<u8>,
    #[allow(dead_code)]
    pub stripe: StripeSettings,
    pub auth_cookie_secure: bool,
    pub jwt_issuer: String,
    pub jwt_audience: String,
    pub workspace_member_limit: i64,
    pub workspace_monthly_run_limit: i64,
    pub runaway_limit_5min: i64,
    pub webhook_ingress_dedupe_mode: WebhookIngressDedupeMode,
    pub webhook_verification_body_fields: Vec<String>,
    pub webhook_verification_header_fields: Vec<(String, Option<String>)>,
    pub webhook_event_type_fields: Vec<String>,
}

impl Config {
    pub fn from_env() -> Result<Self, ConfigError> {
        // Allow an explicit backend-only override so frontend tooling that disables
        // dotenv globally doesn't prevent the backend from loading `backend/.env`.
        let dotenv_disabled_backend = env::var("DOTENV_DISABLE_BACKEND")
            .ok()
            .map(|v| matches!(v.to_ascii_lowercase().as_str(), "1" | "true"))
            .unwrap_or(false);

        let dotenv_disabled = if dotenv_disabled_backend {
            true
        } else {
            env::var("DOTENV_DISABLE")
                .ok()
                .map(|value| {
                    let normalized = value.to_ascii_lowercase();
                    matches!(normalized.as_str(), "1" | "true")
                })
                .unwrap_or(false)
        };

        // Prefer loading `backend/.env` from the crate manifest directory when present.
        // This ensures local backend development loads its `.env` even if a global
        // process-level `DOTENV_DISABLE` is set by other tooling (e.g., frontend).
        let manifest_dir = env!("CARGO_MANIFEST_DIR");
        let env_path = std::path::Path::new(manifest_dir).join(".env");
        if env_path.exists() && !dotenv_disabled_backend {
            match dotenvy::from_path(&env_path) {
                Ok(_) => {
                    eprintln!("Loaded backend .env from {}", env_path.display());
                }
                Err(err) => {
                    eprintln!(
                        "Failed to load backend .env from {}: {err}",
                        env_path.display()
                    );
                }
            }
        } else if !dotenv_disabled {
            match dotenvy::dotenv() {
                Ok(_) => eprintln!("Loaded .env via dotenvy::dotenv()"),
                Err(err) => eprintln!("dotenvy::dotenv() failed: {err}"),
            }
        }

        fn require_env(name: &'static str) -> Result<String, ConfigError> {
            env::var(name).map_err(|_| ConfigError::MissingEnvVar { name })
        }

        let database_url = require_env("DATABASE_URL")?;
        let frontend_origin = require_env("FRONTEND_ORIGIN")?;
        let admin_origin = env::var("ADMIN_ORIGIN").unwrap_or_else(|_| frontend_origin.clone());

        let google = OAuthProviderConfig {
            client_id: require_env("GOOGLE_INTEGRATIONS_CLIENT_ID")?,
            client_secret: require_env("GOOGLE_INTEGRATIONS_CLIENT_SECRET")?,
            redirect_uri: require_env("GOOGLE_INTEGRATIONS_REDIRECT_URI")?,
        };

        let github = OAuthProviderConfig {
            client_id: require_env("GITHUB_INTEGRATIONS_CLIENT_ID")?,
            client_secret: require_env("GITHUB_INTEGRATIONS_CLIENT_SECRET")?,
            redirect_uri: require_env("GITHUB_INTEGRATIONS_REDIRECT_URI")?,
        };

        let microsoft = OAuthProviderConfig {
            client_id: require_env("MICROSOFT_INTEGRATIONS_CLIENT_ID")?,
            client_secret: require_env("MICROSOFT_INTEGRATIONS_CLIENT_SECRET")?,
            redirect_uri: require_env("MICROSOFT_INTEGRATIONS_REDIRECT_URI")?,
        };

        let slack = OAuthProviderConfig {
            client_id: require_env("SLACK_INTEGRATIONS_CLIENT_ID")?,
            client_secret: require_env("SLACK_INTEGRATIONS_CLIENT_SECRET")?,
            redirect_uri: require_env("SLACK_INTEGRATIONS_REDIRECT_URI")?,
        };

        let asana = OAuthProviderConfig {
            client_id: require_env("ASANA_INTEGRATIONS_CLIENT_ID")?,
            client_secret: require_env("ASANA_INTEGRATIONS_CLIENT_SECRET")?,
            redirect_uri: require_env("ASANA_INTEGRATIONS_REDIRECT_URI")?,
        };
        let notion = OAuthProviderConfig {
            client_id: require_env("NOTION_INTEGRATIONS_CLIENT_ID")?,
            client_secret: require_env("NOTION_INTEGRATIONS_CLIENT_SECRET")?,
            redirect_uri: require_env("NOTION_INTEGRATIONS_REDIRECT_URI")?,
        };
        let bitly = OAuthProviderConfig {
            client_id: require_env("BITLY_INTEGRATIONS_CLIENT_ID")?,
            client_secret: require_env("BITLY_INTEGRATIONS_CLIENT_SECRET")?,
            redirect_uri: require_env("BITLY_INTEGRATIONS_REDIRECT_URI")?,
        };
        let raindrop = OAuthProviderConfig {
            client_id: require_env("RAINDROP_INTEGRATIONS_CLIENT_ID")?,
            client_secret: require_env("RAINDROP_INTEGRATIONS_CLIENT_SECRET")?,
            redirect_uri: require_env("RAINDROP_INTEGRATIONS_REDIRECT_URI")?,
        };

        let encryption_key_b64 = require_env("OAUTH_TOKEN_ENCRYPTION_KEY")?;
        let token_encryption_key =
            decode_key(&encryption_key_b64).map_err(|source| ConfigError::SecretDecode {
                name: "OAUTH_TOKEN_ENCRYPTION_KEY",
                source,
            })?;

        let github_app_id = parse_optional_env_i64("GITHUB_APP_ID")?;
        let github_app_private_key = env::var("GITHUB_APP_PRIVATE_KEY")
            .ok()
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty())
            .map(|value| normalize_multiline_pem(&value));
        let github_app_user_token_refresh_enabled =
            parse_env_bool("GITHUB_APP_USER_TOKEN_REFRESH_ENABLED", false)?;
        let github_app_user_oauth_enabled = parse_env_bool("GITHUB_APP_USER_OAUTH_ENABLED", false)?;
        let github_webhook_source_id = parse_optional_env_string("GITHUB_WEBHOOK_SOURCE_ID");

        let api_secrets_key_b64 = require_env("API_SECRETS_ENCRYPTION_KEY")?;
        let api_secrets_encryption_key =
            decode_key(&api_secrets_key_b64).map_err(|source| ConfigError::SecretDecode {
                name: "API_SECRETS_ENCRYPTION_KEY",
                source,
            })?;

        let stripe = StripeSettings {
            client_id: require_env("STRIPE_CLIENT_ID")?,
            secret_key: require_env("STRIPE_SECRET_KEY")?,
            webhook_secret: require_env("STRIPE_WEBHOOK_SECRET")?,
        };

        let auth_cookie_secure = env::var("AUTH_COOKIE_SECURE")
            .ok()
            .map(|value| match value.to_ascii_lowercase().as_str() {
                "1" | "true" | "yes" | "on" => true,
                "0" | "false" | "no" | "off" => false,
                _ => true,
            })
            .unwrap_or(true);

        let jwt_issuer = require_env("JWT_ISSUER")?;
        let jwt_audience = require_env("JWT_AUDIENCE")?;
        let workspace_member_limit =
            parse_positive_env_i64("WORKSPACE_MEMBER_LIMIT", DEFAULT_WORKSPACE_MEMBER_LIMIT)?;
        let workspace_monthly_run_limit = parse_positive_env_i64(
            "WORKSPACE_MONTHLY_RUN_LIMIT",
            DEFAULT_WORKSPACE_MONTHLY_RUN_LIMIT,
        )?;
        let runaway_limit_5min = parse_positive_env_i64("RUNAWAY_LIMIT_5MIN", RUNAWAY_LIMIT_5MIN)?;
        let webhook_ingress_dedupe_mode =
            parse_webhook_ingress_dedupe_mode("WEBHOOK_INGRESS_DEDUPE_MODE")?;
        let webhook_verification_body_fields =
            parse_webhook_verification_body_fields("WEBHOOK_VERIFICATION_BODY_FIELDS")?;
        let webhook_verification_header_fields =
            parse_webhook_verification_header_fields("WEBHOOK_VERIFICATION_HEADER_FIELDS")?;
        let webhook_event_type_fields =
            parse_webhook_event_type_fields("WEBHOOK_EVENT_TYPE_FIELDS")?;

        Ok(Config {
            database_url,
            frontend_origin,
            admin_origin,
            oauth: OAuthSettings {
                google,
                github,
                microsoft,
                slack,
                asana,
                notion,
                bitly,
                raindrop,
                token_encryption_key,
            },
            github_app: GitHubAppSettings {
                app_id: github_app_id,
                private_key: github_app_private_key,
                user_oauth_enabled: github_app_user_oauth_enabled,
                user_token_refresh_enabled: github_app_user_token_refresh_enabled,
            },
            github_webhook_source_id,
            api_secrets_encryption_key,
            stripe,
            auth_cookie_secure,
            jwt_issuer,
            jwt_audience,
            workspace_member_limit,
            workspace_monthly_run_limit,
            runaway_limit_5min,
            webhook_ingress_dedupe_mode,
            webhook_verification_body_fields,
            webhook_verification_header_fields,
            webhook_event_type_fields,
        })
    }
}

fn parse_positive_env_i64(name: &'static str, default: i64) -> Result<i64, ConfigError> {
    match env::var(name) {
        Ok(raw) => {
            let trimmed = raw.trim();
            if trimmed.is_empty() {
                return Ok(default);
            }
            let value = trimmed
                .parse::<i64>()
                .map_err(|err| ConfigError::InvalidEnvVar {
                    name,
                    reason: err.to_string(),
                })?;
            if value <= 0 {
                return Err(ConfigError::InvalidEnvVar {
                    name,
                    reason: "must be greater than zero".to_string(),
                });
            }
            Ok(value)
        }
        Err(_) => Ok(default),
    }
}

fn parse_optional_env_i64(name: &'static str) -> Result<Option<i64>, ConfigError> {
    match env::var(name) {
        Ok(raw) => {
            let trimmed = raw.trim();
            if trimmed.is_empty() {
                return Ok(None);
            }
            let value = trimmed
                .parse::<i64>()
                .map_err(|err| ConfigError::InvalidEnvVar {
                    name,
                    reason: err.to_string(),
                })?;
            Ok(Some(value))
        }
        Err(_) => Ok(None),
    }
}

fn parse_optional_env_string(name: &'static str) -> Option<String> {
    match env::var(name) {
        Ok(raw) => {
            let trimmed = raw.trim();
            if trimmed.is_empty() {
                None
            } else {
                Some(trimmed.to_string())
            }
        }
        Err(_) => None,
    }
}

fn parse_env_bool(name: &'static str, default: bool) -> Result<bool, ConfigError> {
    match env::var(name) {
        Ok(raw) => {
            let normalized = raw.trim().to_ascii_lowercase();
            if normalized.is_empty() {
                return Ok(default);
            }
            match normalized.as_str() {
                "1" | "true" | "yes" | "on" => Ok(true),
                "0" | "false" | "no" | "off" => Ok(false),
                _ => Err(ConfigError::InvalidEnvVar {
                    name,
                    reason: "must be '1', '0', 'true', 'false', 'yes', 'no', 'on', or 'off'"
                        .to_string(),
                }),
            }
        }
        Err(_) => Ok(default),
    }
}

fn normalize_multiline_pem(value: &str) -> String {
    value.replace("\\n", "\n").replace("\r\n", "\n")
}

fn parse_webhook_ingress_dedupe_mode(
    name: &'static str,
) -> Result<WebhookIngressDedupeMode, ConfigError> {
    match env::var(name) {
        Ok(raw) => {
            let normalized = raw.trim().to_ascii_lowercase();
            if normalized.is_empty() {
                return Ok(WebhookIngressDedupeMode::Off);
            }
            match normalized.as_str() {
                "off" | "false" | "0" => Ok(WebhookIngressDedupeMode::Off),
                "log" | "log-only" | "log_only" | "logonly" => {
                    Ok(WebhookIngressDedupeMode::LogOnly)
                }
                "enforce" | "on" | "true" | "1" => Ok(WebhookIngressDedupeMode::Enforce),
                _ => Err(ConfigError::InvalidEnvVar {
                    name,
                    reason: "must be off, log-only, or enforce".to_string(),
                }),
            }
        }
        Err(_) => Ok(WebhookIngressDedupeMode::Off),
    }
}

fn parse_webhook_verification_body_fields(name: &'static str) -> Result<Vec<String>, ConfigError> {
    match env::var(name) {
        Ok(value) => {
            let trimmed = value.trim();
            if trimmed.is_empty() {
                return Ok(Vec::new());
            }
            Ok(trimmed
                .split(',')
                .map(|token| token.trim().to_string())
                .filter(|token| !token.is_empty())
                .collect())
        }
        Err(_) => Ok(Vec::new()),
    }
}

fn parse_webhook_verification_header_fields(
    name: &'static str,
) -> Result<Vec<(String, Option<String>)>, ConfigError> {
    match env::var(name) {
        Ok(value) => {
            let trimmed = value.trim();
            if trimmed.is_empty() {
                return Ok(Vec::new());
            }
            Ok(trimmed
                .split(',')
                .map(|token| token.trim())
                .filter(|token| !token.is_empty())
                .map(|token| {
                    if let Some((header, value)) = token.split_once(':') {
                        (header.trim().to_string(), Some(value.trim().to_string()))
                    } else {
                        (token.to_string(), None)
                    }
                })
                .collect())
        }
        Err(_) => Ok(Vec::new()),
    }
}

fn parse_webhook_event_type_fields(name: &'static str) -> Result<Vec<String>, ConfigError> {
    match env::var(name) {
        Ok(value) => {
            let trimmed = value.trim();
            if trimmed.is_empty() {
                return Ok(Vec::new());
            }

            Ok(trimmed
                .split(',')
                .map(|token| token.trim().to_string())
                .filter(|token| !token.is_empty())
                .collect())
        }
        Err(_) => Ok(Vec::new()),
    }
}

#[cfg(test)]
mod tests {
    use super::{
        Config, ConfigError, DEFAULT_WORKSPACE_MEMBER_LIMIT, DEFAULT_WORKSPACE_MONTHLY_RUN_LIMIT,
        RUNAWAY_LIMIT_5MIN,
    };
    use base64::Engine as _;
    use std::env;
    use std::sync::Mutex;
    use std::{panic, panic::UnwindSafe};

    const REQUIRED_VARS: [&str; 33] = [
        "DATABASE_URL",
        "FRONTEND_ORIGIN",
        "GOOGLE_INTEGRATIONS_CLIENT_ID",
        "GOOGLE_INTEGRATIONS_CLIENT_SECRET",
        "GOOGLE_INTEGRATIONS_REDIRECT_URI",
        "GITHUB_INTEGRATIONS_CLIENT_ID",
        "GITHUB_INTEGRATIONS_CLIENT_SECRET",
        "GITHUB_INTEGRATIONS_REDIRECT_URI",
        "MICROSOFT_INTEGRATIONS_CLIENT_ID",
        "MICROSOFT_INTEGRATIONS_CLIENT_SECRET",
        "MICROSOFT_INTEGRATIONS_REDIRECT_URI",
        "SLACK_INTEGRATIONS_CLIENT_ID",
        "SLACK_INTEGRATIONS_CLIENT_SECRET",
        "SLACK_INTEGRATIONS_REDIRECT_URI",
        "OAUTH_TOKEN_ENCRYPTION_KEY",
        "API_SECRETS_ENCRYPTION_KEY",
        "STRIPE_CLIENT_ID",
        "STRIPE_SECRET_KEY",
        "STRIPE_WEBHOOK_SECRET",
        "JWT_ISSUER",
        "JWT_AUDIENCE",
        "ASANA_INTEGRATIONS_CLIENT_ID",
        "ASANA_INTEGRATIONS_CLIENT_SECRET",
        "ASANA_INTEGRATIONS_REDIRECT_URI",
        "NOTION_INTEGRATIONS_CLIENT_ID",
        "NOTION_INTEGRATIONS_CLIENT_SECRET",
        "NOTION_INTEGRATIONS_REDIRECT_URI",
        "BITLY_INTEGRATIONS_CLIENT_ID",
        "BITLY_INTEGRATIONS_CLIENT_SECRET",
        "BITLY_INTEGRATIONS_REDIRECT_URI",
        "RAINDROP_INTEGRATIONS_CLIENT_ID",
        "RAINDROP_INTEGRATIONS_CLIENT_SECRET",
        "RAINDROP_INTEGRATIONS_REDIRECT_URI",
    ];

    const OPTIONAL_VARS: [&str; 10] = [
        "AUTH_COOKIE_SECURE",
        "WORKSPACE_MEMBER_LIMIT",
        "WORKSPACE_MONTHLY_RUN_LIMIT",
        "RUNAWAY_LIMIT_5MIN",
        "ADMIN_ORIGIN",
        "WEBHOOK_INGRESS_DEDUPE_MODE",
        "GITHUB_APP_ID",
        "GITHUB_APP_PRIVATE_KEY",
        "GITHUB_APP_USER_OAUTH_ENABLED",
        "GITHUB_APP_USER_TOKEN_REFRESH_ENABLED",
    ]; // allow tests to run without ambient overrides

    static ENV_MUTEX: Mutex<()> = Mutex::new(());

    fn with_env<F, R>(f: F) -> R
    where
        F: FnOnce() -> R + UnwindSafe,
    {
        let guard = ENV_MUTEX.lock().unwrap();
        let snapshot: Vec<(&'static str, Option<String>)> = REQUIRED_VARS
            .iter()
            .map(|&key| (key, env::var(key).ok()))
            .collect();
        let optional_snapshot: Vec<(&'static str, Option<String>)> = OPTIONAL_VARS
            .iter()
            .map(|&key| (key, env::var(key).ok()))
            .collect();
        let dotenv_disable_snapshot = env::var("DOTENV_DISABLE").ok();
        let dotenv_disable_backend_snapshot = env::var("DOTENV_DISABLE_BACKEND").ok();

        env::set_var("DOTENV_DISABLE", "1");
        env::set_var("DOTENV_DISABLE_BACKEND", "1");
        for key in REQUIRED_VARS.iter() {
            env::remove_var(key);
        }
        for key in OPTIONAL_VARS.iter() {
            env::remove_var(key);
        }

        let result = panic::catch_unwind(f);

        for (key, value) in snapshot {
            if let Some(v) = value {
                env::set_var(key, v);
            } else {
                env::remove_var(key);
            }
        }
        for (key, value) in optional_snapshot {
            if let Some(v) = value {
                env::set_var(key, v);
            } else {
                env::remove_var(key);
            }
        }
        match dotenv_disable_snapshot {
            Some(value) => env::set_var("DOTENV_DISABLE", value),
            None => env::remove_var("DOTENV_DISABLE"),
        }
        match dotenv_disable_backend_snapshot {
            Some(value) => env::set_var("DOTENV_DISABLE_BACKEND", value),
            None => env::remove_var("DOTENV_DISABLE_BACKEND"),
        }

        drop(guard);

        match result {
            Ok(value) => value,
            Err(payload) => panic::resume_unwind(payload),
        }
    }

    fn populate_defaults() {
        env::set_var("DATABASE_URL", "postgres://localhost/db");
        env::set_var("FRONTEND_ORIGIN", "http://localhost:3000");
        env::remove_var("ADMIN_ORIGIN");
        env::set_var("GOOGLE_INTEGRATIONS_CLIENT_ID", "google-client-id");
        env::set_var("GOOGLE_INTEGRATIONS_CLIENT_SECRET", "google-client-secret");
        env::set_var(
            "GOOGLE_INTEGRATIONS_REDIRECT_URI",
            "http://localhost/google",
        );
        env::set_var("GITHUB_INTEGRATIONS_CLIENT_ID", "github-client-id");
        env::set_var("GITHUB_INTEGRATIONS_CLIENT_SECRET", "github-client-secret");
        env::set_var(
            "GITHUB_INTEGRATIONS_REDIRECT_URI",
            "http://localhost/github",
        );
        env::set_var("MICROSOFT_INTEGRATIONS_CLIENT_ID", "microsoft-client-id");
        env::set_var(
            "MICROSOFT_INTEGRATIONS_CLIENT_SECRET",
            "microsoft-client-secret",
        );
        env::set_var(
            "MICROSOFT_INTEGRATIONS_REDIRECT_URI",
            "http://localhost/microsoft",
        );
        env::set_var("SLACK_INTEGRATIONS_CLIENT_ID", "slack-client-id");
        env::set_var("SLACK_INTEGRATIONS_CLIENT_SECRET", "slack-client-secret");
        env::set_var("SLACK_INTEGRATIONS_REDIRECT_URI", "http://localhost/slack");
        env::set_var("ASANA_INTEGRATIONS_CLIENT_ID", "asana-client-id");
        env::set_var("ASANA_INTEGRATIONS_CLIENT_SECRET", "asana-client-secret");
        env::set_var("ASANA_INTEGRATIONS_REDIRECT_URI", "http://localhost/asana");
        env::set_var("NOTION_INTEGRATIONS_CLIENT_ID", "notion-client-id");
        env::set_var("NOTION_INTEGRATIONS_CLIENT_SECRET", "notion-client-secret");
        env::set_var(
            "NOTION_INTEGRATIONS_REDIRECT_URI",
            "http://localhost/notion",
        );
        env::set_var("BITLY_INTEGRATIONS_CLIENT_ID", "bitly-client-id");
        env::set_var("BITLY_INTEGRATIONS_CLIENT_SECRET", "bitly-client-secret");
        env::set_var("BITLY_INTEGRATIONS_REDIRECT_URI", "http://localhost/bitly");
        env::set_var("RAINDROP_INTEGRATIONS_CLIENT_ID", "raindrop-client-id");
        env::set_var(
            "RAINDROP_INTEGRATIONS_CLIENT_SECRET",
            "raindrop-client-secret",
        );
        env::set_var(
            "RAINDROP_INTEGRATIONS_REDIRECT_URI",
            "http://localhost/raindrop",
        );
        let key = base64::engine::general_purpose::STANDARD.encode([0u8; 32]);
        env::set_var("OAUTH_TOKEN_ENCRYPTION_KEY", key);
        env::set_var("GITHUB_APP_ID", "4242");
        env::set_var(
            "GITHUB_APP_PRIVATE_KEY",
            "-----BEGIN PRIVATE KEY-----\\nline\\n-----END PRIVATE KEY-----",
        );
        env::set_var("GITHUB_APP_USER_TOKEN_REFRESH_ENABLED", "true");
        env::set_var("GITHUB_APP_USER_OAUTH_ENABLED", "true");
        env::set_var(
            "API_SECRETS_ENCRYPTION_KEY",
            base64::engine::general_purpose::STANDARD.encode([1u8; 32]),
        );
        env::set_var("STRIPE_CLIENT_ID", "stripe-client-id");
        env::set_var("STRIPE_SECRET_KEY", "stripe-secret");
        env::set_var("STRIPE_WEBHOOK_SECRET", "stripe-webhook");
        env::set_var("JWT_ISSUER", "dsentr.test");
        env::set_var("JWT_AUDIENCE", "dsentr.api");
        env::set_var(
            "WORKSPACE_MEMBER_LIMIT",
            DEFAULT_WORKSPACE_MEMBER_LIMIT.to_string(),
        );
        env::set_var(
            "WORKSPACE_MONTHLY_RUN_LIMIT",
            DEFAULT_WORKSPACE_MONTHLY_RUN_LIMIT.to_string(),
        );
        env::set_var("RUNAWAY_LIMIT_5MIN", RUNAWAY_LIMIT_5MIN.to_string());
    }

    #[test]
    fn reports_missing_environment_variables() {
        with_env(|| match Config::from_env() {
            Err(ConfigError::MissingEnvVar { name }) => {
                assert_eq!(name, "DATABASE_URL");
            }
            Err(other) => panic!("expected missing env var error, got {other:?}"),
            Ok(_) => panic!("expected missing env var error, got Ok"),
        });
    }

    #[test]
    fn loads_configuration_from_environment() {
        with_env(|| {
            populate_defaults();
            let config = Config::from_env().expect("config should load");
            assert_eq!(config.database_url, "postgres://localhost/db");
            assert_eq!(config.frontend_origin, "http://localhost:3000");
            assert_eq!(config.admin_origin, "http://localhost:3000");
            assert_eq!(config.oauth.google.client_id, "google-client-id");
            assert_eq!(config.oauth.token_encryption_key.len(), 32);
            assert_eq!(config.github_app.app_id, Some(4242));
            assert!(config
                .github_app
                .private_key
                .as_deref()
                .unwrap_or("")
                .contains("BEGIN PRIVATE KEY"));
            assert!(config.github_app.user_token_refresh_enabled);
            assert!(config.github_app.user_oauth_enabled);
            assert!(config.auth_cookie_secure);
            assert_eq!(config.jwt_issuer, "dsentr.test");
            assert_eq!(config.jwt_audience, "dsentr.api");
            assert_eq!(
                config.workspace_member_limit,
                DEFAULT_WORKSPACE_MEMBER_LIMIT
            );
            assert_eq!(
                config.workspace_monthly_run_limit,
                DEFAULT_WORKSPACE_MONTHLY_RUN_LIMIT
            );
            assert_eq!(config.runaway_limit_5min, RUNAWAY_LIMIT_5MIN);
        });
    }

    #[test]
    fn admin_origin_respects_override() {
        with_env(|| {
            populate_defaults();
            env::set_var("ADMIN_ORIGIN", "https://admin.example.com");
            let config = Config::from_env().expect("config should load");
            assert_eq!(config.admin_origin, "https://admin.example.com");
        });
    }

    #[test]
    fn cookie_secure_respects_false_override() {
        with_env(|| {
            populate_defaults();
            env::set_var("AUTH_COOKIE_SECURE", "false");
            let config = Config::from_env().expect("config should load");
            assert!(!config.auth_cookie_secure);
        });
    }

    #[test]
    fn rejects_invalid_workspace_limits() {
        with_env(|| {
            populate_defaults();
            env::set_var("WORKSPACE_MEMBER_LIMIT", "not-a-number");
            match Config::from_env() {
                Err(ConfigError::InvalidEnvVar { name, .. }) => {
                    assert_eq!(name, "WORKSPACE_MEMBER_LIMIT");
                }
                other => panic!("expected invalid env error, got {other:?}"),
            }
        });

        with_env(|| {
            populate_defaults();
            env::set_var("WORKSPACE_MONTHLY_RUN_LIMIT", "0");
            match Config::from_env() {
                Err(ConfigError::InvalidEnvVar { name, .. }) => {
                    assert_eq!(name, "WORKSPACE_MONTHLY_RUN_LIMIT");
                }
                other => panic!("expected invalid env error, got {other:?}"),
            }
        });
    }

    #[test]
    fn surfaces_token_decode_errors() {
        with_env(|| {
            populate_defaults();
            env::set_var("OAUTH_TOKEN_ENCRYPTION_KEY", "not-base64");
            match Config::from_env() {
                Err(ConfigError::SecretDecode { name, .. }) => {
                    assert_eq!(name, "OAUTH_TOKEN_ENCRYPTION_KEY");
                }
                Err(other) => panic!("expected decode error, got {other:?}"),
                Ok(_) => panic!("expected decode error, got Ok"),
            }
        });
    }

    #[test]
    fn surfaces_api_secrets_decode_errors() {
        with_env(|| {
            populate_defaults();
            env::set_var("API_SECRETS_ENCRYPTION_KEY", "short");
            match Config::from_env() {
                Err(ConfigError::SecretDecode { name, .. }) => {
                    assert_eq!(name, "API_SECRETS_ENCRYPTION_KEY");
                }
                Err(other) => panic!("expected decode error, got {other:?}"),
                Ok(_) => panic!("expected decode error, got Ok"),
            }
        });
    }
}
