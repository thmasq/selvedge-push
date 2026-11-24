use thiserror::Error;
use url::{Host, Url};

#[derive(Debug, Error, PartialEq, Eq)]
pub enum SsrfError {
    #[error("invalid URL")]
    InvalidUrl,

    #[error("scheme must be https")]
    InvalidScheme,

    #[error("credentials in URL are not allowed")]
    CredentialsNotAllowed,

    #[error("port must be default 443")]
    InvalidPort,

    #[error("IP literal hosts are not allowed")]
    IpHostNotAllowed,

    #[error("host is not in browser vendor allowlist")]
    DisallowedHost,
}

/// A Web Push endpoint URL that has passed strict SSRF validation.
#[derive(Debug, Clone)]
pub struct ValidatedPushUrl {
    url: Url,
    host: String,
}

impl ValidatedPushUrl {
    /// Parses and validates a `pushkey` URL against the browser-vendor allowlist.
    ///
    /// # Errors
    /// Returns [`SsrfError`] if the URL fails scheme, credential, port, IP-literal,
    /// or vendor-domain validation.
    pub fn parse(raw: &str) -> Result<Self, SsrfError> {
        let url = Url::parse(raw).map_err(|_| SsrfError::InvalidUrl)?;

        if url.scheme() != "https" {
            return Err(SsrfError::InvalidScheme);
        }

        if !url.username().is_empty() || url.password().is_some() {
            return Err(SsrfError::CredentialsNotAllowed);
        }

        if let Some(port) = url.port()
            && port != 443
        {
            return Err(SsrfError::InvalidPort);
        }

        let domain = match url.host() {
            Some(Host::Domain(domain)) => domain,
            Some(Host::Ipv4(_) | Host::Ipv6(_)) => return Err(SsrfError::IpHostNotAllowed),
            None => return Err(SsrfError::InvalidUrl),
        };

        let host = domain.to_ascii_lowercase();

        if !is_allowed_vendor_host(&host) {
            return Err(SsrfError::DisallowedHost);
        }

        Ok(Self { url, host })
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        self.url.as_str()
    }

    #[must_use]
    pub const fn url(&self) -> &Url {
        &self.url
    }

    /// Safe to log — contains only the normalized allowlisted vendor hostname.
    #[must_use]
    pub fn host(&self) -> &str {
        &self.host
    }

    /// VAPID `aud` claim: `https://<host>` (always default port 443).
    #[must_use]
    pub fn vapid_audience(&self) -> String {
        format!("https://{}", self.host)
    }
}

fn is_allowed_vendor_host(host: &str) -> bool {
    if host == "fcm.googleapis.com" {
        return true;
    }

    if host == "push.services.mozilla.com"
        || has_valid_subdomain(host, ".push.services.mozilla.com")
    {
        return true;
    }

    if host == "web.push.apple.com" || has_valid_subdomain(host, ".push.apple.com") {
        return true;
    }

    if has_valid_subdomain(host, ".notify.windows.com") {
        return true;
    }

    false
}

/// Returns true iff `host` ends with `dot_suffix` (e.g. `".notify.windows.com"`)
/// and the subdomain prefix is non-empty with no empty labels (no leading/trailing/double dots).
fn has_valid_subdomain(host: &str, dot_suffix: &str) -> bool {
    let Some(prefix) = host.strip_suffix(dot_suffix) else {
        return false;
    };
    !prefix.is_empty()
        && !prefix.starts_with('.')
        && !prefix.ends_with('.')
        && !prefix.contains("..")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_valid_vendor_urls() {
        let valid = [
            "https://fcm.googleapis.com/fcm/send/abc123",
            "https://FCM.GOOGLEAPIS.COM:443/fcm/send/abc123",
            "https://push.services.mozilla.com/wpush/v2/token",
            "https://updates.push.services.mozilla.com/wpush/v2/token",
            "https://web.push.apple.com/Q123456",
            "https://api.push.apple.com/3/device/abc",
            "https://wns2-bl2p.notify.windows.com/w/?token=xyz",
        ];

        for raw in valid {
            let parsed = ValidatedPushUrl::parse(raw)
                .unwrap_or_else(|e| panic!("expected {raw} to be valid, got {e:?}"));
            assert!(parsed.vapid_audience().starts_with("https://"));
        }
    }

    #[test]
    fn rejects_non_https_schemes() {
        assert_eq!(
            ValidatedPushUrl::parse("http://fcm.googleapis.com/fcm/send/abc").unwrap_err(),
            SsrfError::InvalidScheme
        );
        assert_eq!(
            ValidatedPushUrl::parse("ftp://fcm.googleapis.com/fcm/send/abc").unwrap_err(),
            SsrfError::InvalidScheme
        );
    }

    #[test]
    fn rejects_ip_literals() {
        for raw in [
            "https://127.0.0.1/push",
            "https://192.168.1.1/push",
            "https://[::1]/push",
            "https://[fe80::1]/push",
        ] {
            assert_eq!(
                ValidatedPushUrl::parse(raw).unwrap_err(),
                SsrfError::IpHostNotAllowed,
                "expected IP rejection for {raw}"
            );
        }
    }

    #[test]
    fn rejects_non_443_ports() {
        for raw in [
            "https://fcm.googleapis.com:8443/fcm/send/abc",
            "https://fcm.googleapis.com:80/fcm/send/abc",
            "https://web.push.apple.com:8080/abc",
        ] {
            assert_eq!(
                ValidatedPushUrl::parse(raw).unwrap_err(),
                SsrfError::InvalidPort,
                "expected port rejection for {raw}"
            );
        }
    }

    #[test]
    fn rejects_credentials() {
        assert_eq!(
            ValidatedPushUrl::parse("https://user@fcm.googleapis.com/fcm/send/abc").unwrap_err(),
            SsrfError::CredentialsNotAllowed
        );
        assert_eq!(
            ValidatedPushUrl::parse("https://user:pass@fcm.googleapis.com/fcm/send/abc")
                .unwrap_err(),
            SsrfError::CredentialsNotAllowed
        );
    }

    #[test]
    fn rejects_disallowed_and_spoofed_domains() {
        for raw in [
            "https://evil.com/push",
            "https://fcm.googleapis.com.evil.com/push",
            "https://fcm.googleapis.com./fcm/send/abc123",
            "https://notfcm.googleapis.com/push",
            "https://sub.fcm.googleapis.com/push",
            "https://notify.windows.com/push",
            "https://evilpush.apple.com/push",
            "https://push.apple.com/push",
            "https://fcm.googleapis.com../push",
        ] {
            assert_eq!(
                ValidatedPushUrl::parse(raw).unwrap_err(),
                SsrfError::DisallowedHost,
                "expected host rejection for {raw}"
            );
        }
    }
}
