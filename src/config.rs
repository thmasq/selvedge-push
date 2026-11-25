use std::fmt;
use std::net::SocketAddr;
use std::time::Duration;

use thiserror::Error;
use url::Url;
use zeroize::Zeroizing;

/// Secret string that is zeroized on drop and never printed in `Debug`.
#[derive(Clone)]
pub struct SecretString(Zeroizing<String>);

impl SecretString {
    #[must_use]
    pub fn new(value: String) -> Self {
        Self(Zeroizing::new(value))
    }

    #[must_use]
    pub fn expose(&self) -> &str {
        self.0.as_str()
    }
}

impl fmt::Debug for SecretString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[REDACTED]")
    }
}

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("missing required environment variable: {0}")]
    Missing(&'static str),

    #[error("invalid value for {var}: {reason}")]
    Invalid { var: &'static str, reason: String },
}

#[derive(Debug, Clone)]
pub struct Config {
    pub vapid_subject: String,
    /// Normalized base URL without trailing slash (e.g. `https://selvedge.example.com`).
    pub app_base_url: String,
    pub allowed_app_id: String,
    pub bind_addr: SocketAddr,
    pub cors_allowed_origin: String,
    pub heartbeat_ttl: Duration,
    pub max_heartbeats: usize,
    pub push_ttl_secs: u32,
    pub outbound_timeout: Duration,
    pub max_concurrent_pushes: usize,
    pub max_debounce_batches: usize,
    pub debounce_max_wait: Duration,
    pub rejected_cache_ttl: Duration,
    pub max_rejected_hashes: usize,
}

impl Config {
    /// Loads configuration and the raw VAPID private key from process
    /// environment variables.
    ///
    /// # Errors
    /// Returns [`ConfigError`] if any required variable is missing or invalid.
    pub fn from_env() -> Result<(Self, SecretString), ConfigError> {
        Self::from_lookup(|key| std::env::var(key).ok())
    }

    /// Loads configuration and the raw VAPID private key using a custom
    /// key-lookup function.
    ///
    /// # Errors
    /// Returns [`ConfigError`] if any required variable is missing or invalid.
    pub fn from_lookup<F>(lookup: F) -> Result<(Self, SecretString), ConfigError>
    where
        F: Fn(&str) -> Option<String>,
    {
        let vapid_private_key =
            SecretString::new(required_non_empty(&lookup, "VAPID_PRIVATE_KEY")?);
        let vapid_subject = required_non_empty(&lookup, "VAPID_SUBJECT")?;
        if !vapid_subject.starts_with("mailto:") && !vapid_subject.starts_with("https://") {
            return Err(ConfigError::Invalid {
                var: "VAPID_SUBJECT",
                reason: "must start with 'mailto:' or 'https://'".into(),
            });
        }

        let app_base_url_raw = required_non_empty(&lookup, "APP_BASE_URL")?;
        let parsed_app_url = Url::parse(&app_base_url_raw).map_err(|e| ConfigError::Invalid {
            var: "APP_BASE_URL",
            reason: e.to_string(),
        })?;
        if !matches!(parsed_app_url.scheme(), "https" | "http")
            || parsed_app_url.host_str().is_none()
        {
            return Err(ConfigError::Invalid {
                var: "APP_BASE_URL",
                reason: "must be an http(s) URL with a valid host".into(),
            });
        }
        let app_base_url = app_base_url_raw.trim_end_matches('/').to_owned();

        let default_origin = parsed_app_url.origin().ascii_serialization();
        let cors_allowed_origin = match optional_non_empty(&lookup, "CORS_ALLOWED_ORIGIN") {
            Some(raw) => {
                let parsed = Url::parse(&raw).map_err(|e| ConfigError::Invalid {
                    var: "CORS_ALLOWED_ORIGIN",
                    reason: e.to_string(),
                })?;
                if !matches!(parsed.scheme(), "https" | "http")
                    || parsed.host_str().is_none()
                    || !matches!(parsed.path(), "" | "/")
                    || parsed.query().is_some()
                    || parsed.fragment().is_some()
                    || !parsed.username().is_empty()
                    || parsed.password().is_some()
                {
                    return Err(ConfigError::Invalid {
                        var: "CORS_ALLOWED_ORIGIN",
                        reason: "must be a bare http(s) origin (e.g. https://selvedge.example.com)"
                            .into(),
                    });
                }
                parsed.origin().ascii_serialization()
            }
            None => default_origin,
        };

        let allowed_app_id = optional_non_empty(&lookup, "ALLOWED_APP_ID")
            .unwrap_or_else(|| "org.selvedge.web".to_owned());

        let bind_addr: SocketAddr = optional_non_empty(&lookup, "BIND_ADDR")
            .unwrap_or_else(|| "127.0.0.1:8085".to_owned())
            .parse()
            .map_err(|e| ConfigError::Invalid {
                var: "BIND_ADDR",
                reason: format!("{e}"),
            })?;

        let heartbeat_ttl_secs = parse_positive_u64(&lookup, "HEARTBEAT_TTL_SECS", 90)?;
        let max_heartbeats = parse_positive_usize(&lookup, "MAX_HEARTBEATS", 10_000)?;
        let push_ttl_secs = parse_u32(&lookup, "PUSH_TTL_SECS", 86_400)?;
        let outbound_timeout_secs = parse_positive_u64(&lookup, "OUTBOUND_TIMEOUT_SECS", 5)?;
        let max_concurrent_pushes = parse_positive_usize(&lookup, "MAX_CONCURRENT_PUSHES", 64)?;
        let max_debounce_batches = parse_positive_usize(&lookup, "MAX_DEBOUNCE_BATCHES", 10_000)?;
        let debounce_max_wait_secs = parse_positive_u64(&lookup, "DEBOUNCE_MAX_WAIT_SECS", 10)?;
        let rejected_cache_ttl_secs = parse_positive_u64(&lookup, "REJECTED_CACHE_TTL_SECS", 3600)?;
        let max_rejected_hashes = parse_positive_usize(&lookup, "MAX_REJECTED_HASHES", 10_000)?;

        Ok((
            Self {
                vapid_subject,
                app_base_url,
                allowed_app_id,
                bind_addr,
                cors_allowed_origin,
                heartbeat_ttl: Duration::from_secs(heartbeat_ttl_secs),
                max_heartbeats,
                push_ttl_secs,
                outbound_timeout: Duration::from_secs(outbound_timeout_secs),
                max_concurrent_pushes,
                max_debounce_batches,
                debounce_max_wait: Duration::from_secs(debounce_max_wait_secs),
                rejected_cache_ttl: Duration::from_secs(rejected_cache_ttl_secs),
                max_rejected_hashes,
            },
            vapid_private_key,
        ))
    }

    /// URL used for Declarative Web Push `notification.navigate`.
    #[must_use]
    pub fn navigate_url(&self) -> String {
        format!("{}/", self.app_base_url)
    }
}

fn required_non_empty<F>(lookup: &F, var: &'static str) -> Result<String, ConfigError>
where
    F: Fn(&str) -> Option<String>,
{
    match lookup(var) {
        Some(v) if !v.trim().is_empty() => Ok(v.trim().to_owned()),
        _ => Err(ConfigError::Missing(var)),
    }
}

fn optional_non_empty<F>(lookup: &F, var: &'static str) -> Option<String>
where
    F: Fn(&str) -> Option<String>,
{
    lookup(var).and_then(|v| {
        let trimmed = v.trim();
        if trimmed.is_empty() {
            None
        } else {
            Some(trimmed.to_owned())
        }
    })
}

fn parse_positive_u64<F>(lookup: &F, var: &'static str, default: u64) -> Result<u64, ConfigError>
where
    F: Fn(&str) -> Option<String>,
{
    let Some(raw) = optional_non_empty(lookup, var) else {
        return Ok(default);
    };
    let val: u64 = raw.parse().map_err(|e| ConfigError::Invalid {
        var,
        reason: format!("{e}"),
    })?;
    if val == 0 {
        return Err(ConfigError::Invalid {
            var,
            reason: "must be greater than 0".into(),
        });
    }
    Ok(val)
}

fn parse_positive_usize<F>(
    lookup: &F,
    var: &'static str,
    default: usize,
) -> Result<usize, ConfigError>
where
    F: Fn(&str) -> Option<String>,
{
    let Some(raw) = optional_non_empty(lookup, var) else {
        return Ok(default);
    };
    let val: usize = raw.parse().map_err(|e| ConfigError::Invalid {
        var,
        reason: format!("{e}"),
    })?;
    if val == 0 {
        return Err(ConfigError::Invalid {
            var,
            reason: "must be greater than 0".into(),
        });
    }
    Ok(val)
}

fn parse_u32<F>(lookup: &F, var: &'static str, default: u32) -> Result<u32, ConfigError>
where
    F: Fn(&str) -> Option<String>,
{
    let Some(raw) = optional_non_empty(lookup, var) else {
        return Ok(default);
    };
    raw.parse().map_err(|e| ConfigError::Invalid {
        var,
        reason: format!("{e}"),
    })
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;

    fn base_env() -> HashMap<&'static str, &'static str> {
        HashMap::from([
            ("VAPID_PRIVATE_KEY", "super-secret-key"),
            ("VAPID_SUBJECT", "mailto:admin@example.com"),
            ("APP_BASE_URL", "https://selvedge.example.com/"),
        ])
    }

    #[test]
    fn loads_defaults_and_redacts_secret() {
        let env = base_env();
        let (cfg, secret) = Config::from_lookup(|k| env.get(k).map(|v| (*v).to_owned())).unwrap();

        assert_eq!(cfg.app_base_url, "https://selvedge.example.com");
        assert_eq!(cfg.navigate_url(), "https://selvedge.example.com/");
        assert_eq!(cfg.cors_allowed_origin, "https://selvedge.example.com");
        assert_eq!(cfg.allowed_app_id, "org.selvedge.web");
        assert_eq!(cfg.bind_addr, "127.0.0.1:8085".parse().unwrap());
        assert_eq!(cfg.heartbeat_ttl, Duration::from_secs(90));
        assert_eq!(cfg.max_heartbeats, 10_000);
        assert_eq!(cfg.push_ttl_secs, 86_400);
        assert_eq!(cfg.outbound_timeout, Duration::from_secs(5));
        assert_eq!(cfg.max_concurrent_pushes, 64);

        let debug_str = format!("{secret:?}");
        assert!(!debug_str.contains("super-secret-key"));
        assert!(debug_str.contains("[REDACTED]"));
    }

    #[test]
    fn rejects_invalid_subject() {
        let mut env = base_env();
        env.insert("VAPID_SUBJECT", "admin@example.com");
        let err = Config::from_lookup(|k| env.get(k).map(|v| (*v).to_owned())).unwrap_err();
        assert!(matches!(
            err,
            ConfigError::Invalid {
                var: "VAPID_SUBJECT",
                ..
            }
        ));
    }

    #[test]
    fn rejects_zero_limits() {
        let mut env = base_env();
        env.insert("MAX_CONCURRENT_PUSHES", "0");
        let err = Config::from_lookup(|k| env.get(k).map(|v| (*v).to_owned())).unwrap_err();
        assert!(matches!(
            err,
            ConfigError::Invalid {
                var: "MAX_CONCURRENT_PUSHES",
                ..
            }
        ));
    }

    #[test]
    fn rejects_invalid_cors_origin() {
        for bad in [
            "*",
            "https://selvedge.example.com/path",
            "ftp://example.com",
        ] {
            let mut env = base_env();
            env.insert("CORS_ALLOWED_ORIGIN", bad);
            let err = Config::from_lookup(|k| env.get(k).map(|v| (*v).to_owned())).unwrap_err();
            assert!(matches!(
                err,
                ConfigError::Invalid {
                    var: "CORS_ALLOWED_ORIGIN",
                    ..
                }
            ));
        }
    }
}
