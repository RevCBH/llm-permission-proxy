use std::{collections::BTreeSet, env};

#[derive(Clone, Debug)]
pub struct Config {
    pub bind_addr: String,
    pub database_url: String,
    pub jwt_secret: String,
    pub jwt_issuer: String,
    pub jwt_audience: String,
    pub bootstrap_jwt_secret: String,
    pub bootstrap_jwt_issuer: String,
    pub bootstrap_jwt_audience: String,
    pub mtls_binding_shared_secret: String,
    pub approval_link_secret: String,
    pub resume_token_secret: String,
    pub base_url: String,
    pub callback_allowed_hosts: BTreeSet<String>,
    pub callback_max_retries: u32,
    pub callback_batch_size: u32,
    pub callback_worker_interval_secs: u64,
    pub approval_ttl_seconds: i64,
    pub approval_nonce_ttl_seconds: i64,
    pub webauthn_rp_id: String,
    pub webauthn_origin: String,
    pub cloudflare_api_token: Option<String>,
    pub cloudflare_api_base: String,
    pub allow_insecure_defaults: bool,
}

impl Config {
    pub fn from_env() -> Self {
        Self::from_lookup(|key| env::var(key).ok())
    }

    fn from_lookup<F>(lookup: F) -> Self
    where
        F: Fn(&str) -> Option<String>,
    {
        let allow_insecure_defaults = parse_bool(lookup("ALLOW_INSECURE_DEFAULTS"), false);

        let jwt_secret = lookup("JWT_SECRET")
            .unwrap_or_else(|| default_or_empty("dev-change-me", allow_insecure_defaults));
        let bootstrap_jwt_secret = lookup("BOOTSTRAP_JWT_SECRET").unwrap_or_else(|| {
            default_or_empty("dev-bootstrap-change-me", allow_insecure_defaults)
        });
        let mtls_binding_shared_secret =
            lookup("MTLS_BINDING_SHARED_SECRET").unwrap_or_else(|| {
                default_or_empty("dev-mtls-binding-change-me", allow_insecure_defaults)
            });
        let approval_link_secret = lookup("APPROVAL_LINK_SECRET").unwrap_or_else(|| {
            default_or_empty("dev-approval-link-change-me", allow_insecure_defaults)
        });
        let resume_token_secret = lookup("RESUME_TOKEN_SECRET").unwrap_or_else(|| {
            default_or_empty("dev-resume-token-change-me", allow_insecure_defaults)
        });

        let callback_allowed_hosts_raw =
            lookup("CALLBACK_ALLOWED_HOSTS").unwrap_or_else(|| "localhost".to_string());
        let callback_allowed_hosts = parse_callback_allowlist(callback_allowed_hosts_raw);

        Self {
            bind_addr: lookup("BIND_ADDR").unwrap_or_else(|| "127.0.0.1:8080".to_string()),
            database_url: lookup("DATABASE_URL")
                .unwrap_or_else(|| "sqlite://data/proxy.db".to_string()),
            jwt_secret,
            jwt_issuer: lookup("JWT_ISSUER").unwrap_or_else(|| "llm-permission-proxy".to_string()),
            jwt_audience: lookup("JWT_AUDIENCE").unwrap_or_else(|| "llm-proxy-api".to_string()),
            bootstrap_jwt_secret,
            bootstrap_jwt_issuer: lookup("BOOTSTRAP_JWT_ISSUER")
                .unwrap_or_else(|| "llm-permission-proxy-bootstrap".to_string()),
            bootstrap_jwt_audience: lookup("BOOTSTRAP_JWT_AUDIENCE")
                .unwrap_or_else(|| "llm-proxy-bootstrap".to_string()),
            mtls_binding_shared_secret,
            approval_link_secret,
            resume_token_secret,
            base_url: lookup("BASE_URL").unwrap_or_else(|| "http://localhost:8080".to_string()),
            callback_allowed_hosts,
            callback_max_retries: parse_u32_with_bounds(lookup("CALLBACK_MAX_RETRIES"), 5, 1, 20),
            callback_batch_size: parse_u32_with_bounds(lookup("CALLBACK_BATCH_SIZE"), 50, 1, 500),
            callback_worker_interval_secs: parse_u64_with_bounds(
                lookup("CALLBACK_WORKER_INTERVAL_SECS"),
                2,
                1,
                60,
            ),
            approval_ttl_seconds: parse_i64_with_bounds(
                lookup("APPROVAL_TTL_SECONDS"),
                600,
                60,
                3600,
            ),
            approval_nonce_ttl_seconds: parse_i64_with_bounds(
                lookup("APPROVAL_NONCE_TTL_SECONDS"),
                90,
                30,
                300,
            ),
            webauthn_rp_id: lookup("WEBAUTHN_RP_ID").unwrap_or_else(|| "localhost".to_string()),
            webauthn_origin: lookup("WEBAUTHN_ORIGIN")
                .unwrap_or_else(|| "http://localhost:8080".to_string()),
            cloudflare_api_token: lookup("CLOUDFLARE_API_TOKEN"),
            cloudflare_api_base: lookup("CLOUDFLARE_API_BASE")
                .unwrap_or_else(|| "https://api.cloudflare.com/client/v4".to_string()),
            allow_insecure_defaults,
        }
    }

    pub fn validate_security(&self) -> anyhow::Result<()> {
        if self.allow_insecure_defaults {
            return Ok(());
        }

        ensure_nonempty("JWT_SECRET", &self.jwt_secret)?;
        ensure_nonempty("BOOTSTRAP_JWT_SECRET", &self.bootstrap_jwt_secret)?;
        ensure_nonempty(
            "MTLS_BINDING_SHARED_SECRET",
            &self.mtls_binding_shared_secret,
        )?;
        ensure_nonempty("APPROVAL_LINK_SECRET", &self.approval_link_secret)?;
        ensure_nonempty("RESUME_TOKEN_SECRET", &self.resume_token_secret)?;

        if self.jwt_secret == "dev-change-me" {
            anyhow::bail!("JWT_SECRET uses insecure default value");
        }
        if self.bootstrap_jwt_secret == "dev-bootstrap-change-me" {
            anyhow::bail!("BOOTSTRAP_JWT_SECRET uses insecure default value");
        }
        if self.callback_allowed_hosts.is_empty() {
            anyhow::bail!("CALLBACK_ALLOWED_HOSTS must contain at least one hostname");
        }

        Ok(())
    }

    pub fn is_callback_host_allowed(&self, host: &str) -> bool {
        self.callback_allowed_hosts
            .contains(&host.to_ascii_lowercase())
    }
}

fn ensure_nonempty(name: &str, value: &str) -> anyhow::Result<()> {
    if value.trim().is_empty() {
        anyhow::bail!("{name} is required");
    }
    Ok(())
}

fn default_or_empty(value: &str, allow_insecure_defaults: bool) -> String {
    if allow_insecure_defaults {
        value.to_string()
    } else {
        String::new()
    }
}

fn parse_callback_allowlist(raw: String) -> BTreeSet<String> {
    raw.split(',')
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .map(|v| v.to_ascii_lowercase())
        .collect()
}

fn parse_bool(value: Option<String>, default: bool) -> bool {
    match value.as_deref().map(str::trim).map(str::to_ascii_lowercase) {
        Some(v) if v == "1" || v == "true" || v == "yes" || v == "on" => true,
        Some(v) if v == "0" || v == "false" || v == "no" || v == "off" => false,
        _ => default,
    }
}

fn parse_u32_with_bounds(value: Option<String>, default: u32, min: u32, max: u32) -> u32 {
    value
        .and_then(|raw| raw.parse::<u32>().ok())
        .map(|parsed| parsed.clamp(min, max))
        .unwrap_or(default)
}

fn parse_u64_with_bounds(value: Option<String>, default: u64, min: u64, max: u64) -> u64 {
    value
        .and_then(|raw| raw.parse::<u64>().ok())
        .map(|parsed| parsed.clamp(min, max))
        .unwrap_or(default)
}

fn parse_i64_with_bounds(value: Option<String>, default: i64, min: i64, max: i64) -> i64 {
    value
        .and_then(|raw| raw.parse::<i64>().ok())
        .map(|parsed| parsed.clamp(min, max))
        .unwrap_or(default)
}

#[cfg(test)]
mod tests {
    use super::Config;

    #[test]
    fn from_lookup_uses_defaults() {
        let cfg = Config::from_lookup(|_| None);
        assert_eq!(cfg.bind_addr, "127.0.0.1:8080");
        assert_eq!(cfg.database_url, "sqlite://data/proxy.db");
        assert_eq!(cfg.callback_max_retries, 5);
        assert_eq!(cfg.callback_batch_size, 50);
        assert_eq!(cfg.approval_ttl_seconds, 600);
        assert_eq!(cfg.approval_nonce_ttl_seconds, 90);
        assert!(cfg.callback_allowed_hosts.contains("localhost"));
    }

    #[test]
    fn from_lookup_parses_and_clamps_numeric_values() {
        let cfg = Config::from_lookup(|key| match key {
            "CALLBACK_MAX_RETRIES" => Some("999".to_string()),
            "CALLBACK_BATCH_SIZE" => Some("0".to_string()),
            "CALLBACK_WORKER_INTERVAL_SECS" => Some("120".to_string()),
            "APPROVAL_TTL_SECONDS" => Some("10".to_string()),
            "APPROVAL_NONCE_TTL_SECONDS" => Some("1000".to_string()),
            _ => None,
        });
        assert_eq!(cfg.callback_max_retries, 20);
        assert_eq!(cfg.callback_batch_size, 1);
        assert_eq!(cfg.callback_worker_interval_secs, 60);
        assert_eq!(cfg.approval_ttl_seconds, 60);
        assert_eq!(cfg.approval_nonce_ttl_seconds, 300);
    }

    #[test]
    fn from_lookup_ignores_invalid_numeric_values() {
        let cfg = Config::from_lookup(|key| match key {
            "CALLBACK_MAX_RETRIES" => Some("abc".to_string()),
            "APPROVAL_TTL_SECONDS" => Some("not-a-number".to_string()),
            _ => None,
        });
        assert_eq!(cfg.callback_max_retries, 5);
        assert_eq!(cfg.approval_ttl_seconds, 600);
    }

    #[test]
    fn validate_security_allows_explicit_insecure_mode() {
        let cfg = Config::from_lookup(|key| match key {
            "ALLOW_INSECURE_DEFAULTS" => Some("true".to_string()),
            _ => None,
        });
        assert!(cfg.validate_security().is_ok());
    }

    #[test]
    fn validate_security_rejects_missing_secrets_when_not_insecure() {
        let cfg = Config::from_lookup(|key| match key {
            "CALLBACK_ALLOWED_HOSTS" => Some("proxy.example".to_string()),
            _ => None,
        });
        assert!(cfg.validate_security().is_err());
    }

    #[test]
    fn callback_allowlist_parses_multiple_hosts() {
        let cfg = Config::from_lookup(|key| match key {
            "CALLBACK_ALLOWED_HOSTS" => {
                Some("proxy.example, CALLBACK.EXAMPLE , api.example".to_string())
            }
            _ => None,
        });
        assert!(cfg.is_callback_host_allowed("proxy.example"));
        assert!(cfg.is_callback_host_allowed("callback.example"));
        assert!(cfg.is_callback_host_allowed("api.example"));
        assert!(!cfg.is_callback_host_allowed("other.example"));
    }
}
