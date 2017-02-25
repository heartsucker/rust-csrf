//! Module containing the core functionality for CSRF protection.

use std::collections::HashSet;
use std::str;

use protobuf;
use protobuf::Message;
use ring::rand::SystemRandom;
use rustc_serialize::base64::{ToBase64, FromBase64, STANDARD};
use time;

use error::CsrfError;
use serial::{CsrfTokenTransport, CsrfCookieTransport};

/// The name of the cookie for the CSRF validation data and signature.
pub const CSRF_COOKIE_NAME: &'static str = "csrf";

/// The name of the form field for the CSRF token.
pub const CSRF_FORM_FIELD: &'static str = "csrf-token";

/// The name of the HTTP header for the CSRF token.
pub const CSRF_HEADER: &'static str = "X-CSRF-Token";

/// The name of the query parameter for the CSRF token.
pub const CSRF_QUERY_STRING: &'static str = "csrf-token";

/// A decoded CSRF cookie.
#[derive(Debug, Eq, PartialEq)]
pub struct CsrfCookie {
    expires: u64,
    nonce: Vec<u8>,
    signature: Vec<u8>,
}

impl CsrfCookie {
    pub fn new(expires: u64, nonce: Vec<u8>, signature: Vec<u8>) -> Self {
        CsrfCookie {
            expires: expires,
            nonce: nonce,
            signature: signature,
        }
    }

    pub fn b64_string(&self) -> Result<String, CsrfError> {
        let mut transport = CsrfCookieTransport::new();
        transport.set_expires(self.expires);
        transport.set_nonce(self.nonce.clone());
        transport.set_signature(self.signature.clone());
        transport.write_to_bytes()
            .map_err(|_| CsrfError::Undefined("could not write transport bytes".to_string()))
            .map(|bytes| bytes.to_base64(STANDARD))
    }

    pub fn parse_b64(string: &str) -> Result<Self, CsrfError> {
        let bytes = string.as_bytes().from_base64().map_err(|_| CsrfError::NotBase64)?;
        protobuf::core::parse_from_bytes::<CsrfCookieTransport>(&bytes)
            .map(|mut transport| {
                CsrfCookie::new(transport.get_expires(),
                                transport.take_nonce(),
                                transport.take_signature())
            })
            .map_err(|_| CsrfError::Undefined("could not parse transport bytes".to_string()))
    }
}

/// The configuation used to initialize `CsrfProtection`.
pub struct CsrfConfig {
    ttl_seconds: i64,
    protected_methods: HashSet<Method>,
}

impl CsrfConfig {
    pub fn build() -> CsrfConfigBuilder {
        CsrfConfigBuilder { config: CsrfConfig::default() }
    }
}

impl Default for CsrfConfig {
    fn default() -> Self {
        let protected_methods: HashSet<Method> =
            vec![Method::Post, Method::Put, Method::Patch, Method::Delete]
                .iter()
                .cloned()
                .collect();
        CsrfConfig {
            ttl_seconds: 3600,
            protected_methods: protected_methods,
        }
    }
}

/// A utility to help build a `CsrfConfig` in an API backwards compatible way.
pub struct CsrfConfigBuilder {
    config: CsrfConfig,
}

impl CsrfConfigBuilder {
    /// Set the TTL in seconds for CSRF cookies and tokens.
    pub fn ttl_seconds(mut self, ttl_seconds: i64) -> Self {
        self.config.ttl_seconds = ttl_seconds;
        self
    }

    /// Set the HTTP methods that are require CSRF protection.
    pub fn protected_methods(mut self, protected_methods: HashSet<Method>) -> Self {
        self.config.protected_methods = protected_methods;
        self
    }

    /// Validate and build the `CsrfConfig`.
    // TODO explain error cases.
    pub fn finish(self) -> Result<CsrfConfig, String> {
        let config = self.config;
        if config.ttl_seconds < 0 {
            return Err("ttl_seconds was negative".to_string());
        }

        if config.protected_methods.is_empty() {
            return Err("protected_methods cannot be empty".to_string());
        }
        Ok(config)
    }
}

/// Wrapper type of HTTP methods for cross libary configuration.
#[derive(Debug, Eq, PartialEq, Clone, Hash)]
pub enum Method {
    Connect,
    Delete,
    Get,
    Head,
    Options,
    Patch,
    Post,
    Put,
    Trace,
    Extension(String),
}

/// An encoded CSRF token.
///
/// # Examples
/// ```ignore
/// use csrf::CsrfToken;
///
/// let token = /* code omitted */;
/// token.b64_string()
/// // CiDR/7m9X/3CVATatXBK72R7Clbvg2DwO74nO3oAO6BsYQ==
/// ```
#[derive(Eq, PartialEq, Debug)]
pub struct CsrfToken {
    nonce: Vec<u8>,
}

impl CsrfToken {
    pub fn new(nonce: Vec<u8>) -> Self {
        CsrfToken { nonce: nonce }
    }

    pub fn b64_string(&self) -> Result<String, CsrfError> {
        let mut transport = CsrfTokenTransport::new();
        transport.set_nonce(self.nonce.clone());
        transport.write_to_bytes()
            .map(|bytes| bytes.to_base64(STANDARD))
            .map_err(|_| CsrfError::Undefined("could not write bytes to base64".to_string()))
    }

    pub fn parse_b64(string: &str) -> Result<Self, CsrfError> {
        let bytes = string.as_bytes().from_base64().map_err(|_| CsrfError::NotBase64)?;
        let mut transport =
            protobuf::core::parse_from_bytes::<CsrfTokenTransport>(&bytes)
            .map_err(|_| CsrfError::Undefined("could not decode bytes to struct".to_string()))?;

        let token = CsrfToken { nonce: transport.take_nonce() };
        Ok(token)
    }
}

/// Base trait that allows an application to be wrapped with CSRF protection.
pub trait CsrfProtection: Sized + Send + Sync {
    fn rng(&self) -> &SystemRandom;

    fn sign_bytes(&self, bytes: &[u8]) -> Vec<u8>;

    // TODO single source this
    fn verify_token_pair(&self, token: &CsrfToken, cookie: &CsrfCookie) -> bool;

    fn generate_token_pair(&self, ttl_seconds: i64) -> Result<(CsrfToken, CsrfCookie), CsrfError> {
        let expires = time::precise_time_ns() + (ttl_seconds as u64) * 1_000_000;
        let mut nonce = vec![0u8; 64];
        self.rng().fill(&mut nonce).map_err(|_| CsrfError::RngError)?;
        let sig = self.sign_bytes(&nonce);
        Ok((CsrfToken::new(nonce.clone()), CsrfCookie::new(expires, nonce, sig.to_vec())))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_csrf_token_serde() {
        let token = CsrfToken::new(b"fake nonce".to_vec());
        let parsed = CsrfToken::parse_b64(&token.b64_string().unwrap()).unwrap();
        assert_eq!(token, parsed)
    }

    #[test]
    fn test_csrf_cookie_serde() {
        let cookie = CsrfCookie::new(502, b"fake nonce".to_vec(), b"fake signature".to_vec());
        let parsed = CsrfCookie::parse_b64(&cookie.b64_string().unwrap()).unwrap();
        assert_eq!(cookie, parsed);
    }

    #[test]
    fn test_config() {
        // ttl of 0 is allowed
        assert!(CsrfConfig::build().ttl_seconds(0).finish().is_ok());

        // negative ttl is not allowed
        assert!(CsrfConfig::build().ttl_seconds(-1).finish().is_err());

        // empty set of protected methods is not allowed
        assert!(CsrfConfig::build().protected_methods(HashSet::new()).finish().is_err())
    }
}
