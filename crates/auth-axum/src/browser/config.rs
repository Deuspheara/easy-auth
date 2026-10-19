use auth_core::{Error, Secret};
use axum::http::HeaderValue;
use url::Url;

#[derive(Clone)]
pub struct BrowserConfig {
    origin: String,
    pub(super) secure: bool,
}
impl BrowserConfig {
    pub fn new(public_url: &str, development: bool) -> auth_core::Result<Self> {
        let url = Url::parse(public_url).map_err(|_| Error::InvalidInput)?;
        let loopback = matches!(url.host_str(), Some("localhost" | "127.0.0.1" | "[::1]"));
        let secure = url.scheme() == "https";
        if !url.username().is_empty()
            || url.password().is_some()
            || url.query().is_some()
            || url.fragment().is_some()
            || url.path() != "/"
            || url.host_str().is_none()
            || !(secure || development && loopback && url.scheme() == "http")
        {
            return Err(Error::InvalidInput);
        }
        Ok(Self {
            origin: url.origin().ascii_serialization(),
            secure,
        })
    }
    pub fn origin(&self) -> &str {
        &self.origin
    }
    pub(crate) fn session_name(&self) -> &'static str {
        if self.secure {
            "__Host-auth-session"
        } else {
            "auth-session"
        }
    }
    pub(crate) fn browser_name(&self) -> &'static str {
        if self.secure {
            "__Host-auth-browser"
        } else {
            "auth-browser"
        }
    }
    pub(crate) fn reset_name(&self) -> &'static str {
        if self.secure {
            "__Host-auth-reset"
        } else {
            "auth-reset"
        }
    }
    pub(crate) fn change_name(&self) -> &'static str {
        if self.secure {
            "__Host-auth-email-change"
        } else {
            "auth-email-change"
        }
    }
    pub(crate) fn deletion_name(&self) -> &'static str {
        if self.secure {
            "__Host-auth-delete"
        } else {
            "auth-delete"
        }
    }
    #[cfg(feature = "passkey-enrollment")]
    pub(crate) fn passkey_name(&self) -> &'static str {
        if self.secure {
            "__Host-auth-passkey"
        } else {
            "auth-passkey"
        }
    }
    #[cfg(feature = "passkey-signup")]
    pub(crate) fn attachment_name(&self) -> &'static str {
        if self.secure {
            "__Host-auth-attach"
        } else {
            "auth-attach"
        }
    }
    pub(crate) fn cookie(&self, name: &str, secret: Option<&Secret>, max_age: u32) -> HeaderValue {
        let value = format!(
            "{name}={}; Path=/; HttpOnly; SameSite=Lax; Max-Age={max_age}{}",
            secret.map(Secret::expose).unwrap_or(""),
            if self.secure { "; Secure" } else { "" }
        );
        // Names and canonical base64url secrets are controlled by this module.
        HeaderValue::from_str(&value).expect("controlled cookie is a valid header")
    }
}
