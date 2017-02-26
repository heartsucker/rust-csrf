//! Module containing the core functionality for CSRF protection.

use std::str;

use chrono::Duration;
use cookie::Cookie;
use iron::headers::{SetCookie, Cookie as IronCookie};
use iron::middleware::{AroundMiddleware, Handler};
use iron::prelude::*;
use iron::status;
use iron::typemap;
use ring::hmac;
use ring::hmac::SigningKey;
use ring::rand::SystemRandom;
use ring::signature;
use ring::signature::Ed25519KeyPair;
use time;
use untrusted;
use urlencoded::{UrlEncodedQuery, UrlEncodedBody};

use core::{CSRF_HEADER, CSRF_COOKIE_NAME, CSRF_FORM_FIELD, CSRF_QUERY_STRING, CsrfProtection, CsrfCookie, CsrfToken, CsrfConfig, Method};
use error::{CsrfError};

// TODO why doesn't this show up in the docs?
/// The HTTP header for the CSRF token.
header! { (XCsrfToken, CSRF_HEADER) => [String] }

impl From<CsrfError> for IronError {
    fn from(err: CsrfError) -> IronError {
        IronError {
            response: Response::with((status::Forbidden, format!("{}", err))),
            error: Box::new(err),
        }
    }
}

/// Uses the Ed25519 DSA to sign and verify cookies.
pub struct Ed25519CsrfProtection {
    // TODO make these refs?
    key_pair: Ed25519KeyPair,
    pub_key: Vec<u8>,
    _rng: SystemRandom,
}

impl Ed25519CsrfProtection {
    pub fn new(key_pair: Ed25519KeyPair, pub_key: Vec<u8>) -> Self {
        Ed25519CsrfProtection {
            key_pair: key_pair,
            pub_key: pub_key,
            _rng: SystemRandom::new(),
        }
    }
}

impl CsrfProtection for Ed25519CsrfProtection {
    fn rng(&self) -> &SystemRandom {
        &self._rng
    }

    fn sign_bytes(&self, bytes: &[u8]) -> Vec<u8> {
        Vec::from(self.key_pair.sign(bytes).as_slice())
    }

    fn verify_token_pair(&self, token: &CsrfToken, cookie: &CsrfCookie) -> bool {
        let msg = untrusted::Input::from(token.nonce.as_slice());
        let sig = untrusted::Input::from(&cookie.signature);
        let valid_sig = signature::verify(&signature::ED25519,
                                          untrusted::Input::from(&self.pub_key),
                                          msg,
                                          sig)
            .is_ok();
        let nonces_match = token.nonce == cookie.nonce;
        let not_expired = cookie.expires > time::precise_time_ns();
        valid_sig && nonces_match && not_expired
    }
}

/// Uses HMAC to sign and verify cookies.
pub struct HmacCsrfProtection {
    // TODO make these refs?
    key: SigningKey,
    _rng: SystemRandom,
}

impl HmacCsrfProtection {
    pub fn new(key: SigningKey) -> Self {
        HmacCsrfProtection {
            key: key,
            _rng: SystemRandom::new(),
        }
    }
}

impl CsrfProtection for HmacCsrfProtection {
    fn rng(&self) -> &SystemRandom {
        &self._rng
    }

    fn sign_bytes(&self, bytes: &[u8]) -> Vec<u8> {
        let sig = hmac::sign(&self.key, bytes);
        Vec::from(sig.as_ref())
    }

    fn verify_token_pair(&self, token: &CsrfToken, cookie: &CsrfCookie) -> bool {
        let valid_sig = hmac::verify_with_own_key(&self.key, &token.nonce, &cookie.signature)
            .is_ok();
        let nonces_match = token.nonce == cookie.nonce;
        let not_expired = cookie.expires > time::precise_time_ns();
        valid_sig && nonces_match && not_expired
    }
}

impl typemap::Key for CsrfToken {
    type Value = CsrfToken;
}

struct CsrfHandler<P: CsrfProtection, H: Handler> {
    protect: P,
    config: CsrfConfig,
    handler: H,
}

impl<P: CsrfProtection, H: Handler> CsrfHandler<P, H> {
    fn new(protect: P, config: CsrfConfig, handler: H) -> Self {
        CsrfHandler {
            protect: protect,
            config: config,
            handler: handler,
        }
    }

    fn validate_request(&self, mut request: &mut Request) -> IronResult<Option<Response>> {
        if self.config.protected_methods.contains(&Method::from(&request.method)) {
            let token_opt = self.extract_csrf_token(&mut request);
            let cookie_opt = self.extract_csrf_cookie(&request);

            match (token_opt, cookie_opt) {
                (Some(token), Some(cookie)) => {
                    if self.protect.verify_token_pair(&token, &cookie) {
                        Ok(None)
                    } else {
                        // TODO differentiate between server error and validation error
                        Ok(Some(Response::with((status::Forbidden, "CSRF Error"))))
                    }
                }
                _ => Ok(Some(Response::with((status::Forbidden, "CSRF Error")))),
            }
        } else {
            Ok(None)
        }
    }

    fn extract_csrf_cookie(&self, request: &Request) -> Option<CsrfCookie> {
        request.headers
            .get::<IronCookie>()
            .and_then(|raw_cookie| {
                raw_cookie.0
                    .iter()
                    .filter_map(|c| {
                        Cookie::parse_encoded(c.clone())
                            .ok()
                            .and_then(|cookie| match cookie.name_value() {
                                (CSRF_COOKIE_NAME, value) => Some(value.to_string()),
                                _ => None,
                            })
                    })
                    .collect::<Vec<String>>()
                    .first()
                    .and_then(|string| CsrfCookie::parse_b64(string).ok())
            })
    }

    fn extract_csrf_token(&self, mut request: &mut Request) -> Option<CsrfToken> {
        let f_token = self.extract_csrf_token_from_form_url_encoded(&mut request);
        let q_token = self.extract_csrf_token_from_query(&mut request);
        let h_token = self.extract_csrf_token_from_headers(&mut request);

        f_token.or(q_token).or(h_token)
    }

    fn extract_csrf_token_from_form_url_encoded(&self, mut request: &mut Request) -> Option<CsrfToken> {
        let token = request.get_ref::<UrlEncodedBody>()
            .ok()
            .and_then(|form| form.get(CSRF_FORM_FIELD))
            .and_then(|v| v.first())
            .and_then(|token_str| CsrfToken::parse_b64(token_str).ok());

        // TODO remove token from form

        token
    }

    fn extract_csrf_token_from_query(&self, mut request: &mut Request) -> Option<CsrfToken> {
        let token = request.get_ref::<UrlEncodedQuery>()
            .ok()
            .and_then(|query| query.get(CSRF_QUERY_STRING))
            .and_then(|v| v.first())
            .and_then(|token_str| CsrfToken::parse_b64(token_str).ok());

        // TODO remove token from query

        token
    }

    fn extract_csrf_token_from_headers(&self, mut request: &mut Request) -> Option<CsrfToken> {
        let token = request.headers
            .get::<XCsrfToken>()
            .and_then(|token_str| CsrfToken::parse_b64(token_str).ok());

        let _ = request.headers.remove::<XCsrfToken>();

        token
    }
}

impl<P: CsrfProtection + Sized + 'static, H: Handler> Handler for CsrfHandler<P, H> {
    fn handle(&self, mut request: &mut Request) -> IronResult<Response> {
        // before
        if let Some(response) = self.validate_request(request)? {
            return Ok(response)
        }
        // TODO should this reuse the old nonce?
        let (token, csrf_cookie) = self.protect.generate_token_pair(self.config.ttl_seconds)?;
        let _ = request.extensions.insert::<CsrfToken>(token);

        // main
        let mut response = self.handler.handle(&mut request)?;

        // after
        let nonce_str = csrf_cookie.b64_string().map_err(|_| CsrfError::NotBase64)?;
        let cookie = Cookie::build("csrf", nonce_str)
            .path("/")
            //.http_only(true)
            .max_age(Duration::seconds(self.config.ttl_seconds))
            .finish();
        let mut cookies = vec![format!("{}", cookie.encoded())]; // TODO is this formatting dumb?

        // TODO write a test to ensure other cookies are not over written / deleted
        {
            if let Some(set_cookie) = response.headers.get::<SetCookie>() {
                cookies.extend(set_cookie.0.clone())
            }
        }
        response.headers.set(SetCookie(cookies));

        Ok(response)
    }
}

/// An implementation of `iron::Middleware` that provides transparent wrapping of an application
/// with CSRF protection.
// TODO example
pub struct CsrfProtectionMiddleware<P: CsrfProtection> {
    protect: P,
    config: CsrfConfig,
}

impl<P: CsrfProtection + Sized + 'static> CsrfProtectionMiddleware<P> {
    pub fn new(protect: P, config: CsrfConfig) -> Self {
        CsrfProtectionMiddleware {
            protect: protect,
            config: config,
        }
    }
}

impl<P: CsrfProtection + Sized + 'static> AroundMiddleware for CsrfProtectionMiddleware<P> {
    fn around(self, handler: Box<Handler>) -> Box<Handler> {
        Box::new(CsrfHandler::new(self.protect, self.config, handler))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;
    use hyper::header::Headers;
    use hyper::method::Method;
    use iron_test::request as mock_request;
    use iron_test::response::extract_body_to_string;
    use ring::digest;
    use ring::signature::Ed25519KeyPair;
    use urlencoding::encode as url_encode;

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

    fn test_protection<P: CsrfProtection>(protect: P) {
        // check token validates
        let (token, cookie) = protect.generate_token_pair(300).unwrap();
        assert!(protect.verify_token_pair(&token, &cookie));

        // check modified token doesn't validate
        let (mut token, cookie) = protect.generate_token_pair(300).unwrap();
        token.nonce[0] = token.nonce[0] ^ 0x07;
        assert!(!protect.verify_token_pair(&token, &cookie));

        // check modified cookie doesn't validate
        let (token, mut cookie) = protect.generate_token_pair(300).unwrap();
        cookie.nonce[0] = cookie.nonce[0] ^ 0x07;
        assert!(!protect.verify_token_pair(&token, &cookie));

        // check modified signature doesn't validate
        let (token, mut cookie) = protect.generate_token_pair(300).unwrap();
        cookie.signature[0] = cookie.signature[0] ^ 0x07;
        assert!(!protect.verify_token_pair(&token, &cookie));

        // check the token is invalid with ttl = 0 for tokens that are never valid
        let (token, cookie) = protect.generate_token_pair(0).unwrap();
        assert!(!protect.verify_token_pair(&token, &cookie));

        // TODO set ttl = 1, sleep 2, check validation fails
    }

    fn mock_handler(request: &mut Request) -> IronResult<Response> {
        // TODO check that CSRF token isn't in header/form/query
        // TODO check that CSRF cookie isn't in header
        let token = request.extensions.get::<CsrfToken>()
            .and_then(|t| t.b64_string().ok())
            .unwrap_or("".to_string());
        Ok(Response::with((status::Ok, token)))
    }

    fn test_middleware<P: CsrfProtection + 'static>(protect: P) {
        let config = CsrfConfig::default();
        let middleware = CsrfProtectionMiddleware::new(protect, config);
        let handler = middleware.around(Box::new(mock_handler));

        // do one GET to get the token
        let response = mock_request::get("http://localhost/", Headers::new(), &handler).unwrap();
        assert_eq!(response.status, Some(status::Ok));

        let (csrf_token, csrf_cookie) = {
            let headers = response.headers.clone();
            let set_cookie = headers.get::<SetCookie>().unwrap();
            let cookie = Cookie::parse(set_cookie.0[0].clone()).unwrap();
            (extract_body_to_string(response), format!("{}", cookie))
        };

        let body_methods = vec![Method::Post, Method::Put, Method::Patch, Method::Connect, Method::Extension("WAT".to_string())];

        let all_methods = vec![Method::Get,
                               Method::Post,
                               Method::Put,
                               Method::Patch,
                               Method::Delete,
                               Method::Options,
                               Method::Connect,
                               Method::Trace,
                               Method::Extension("WAT".to_string())];

        ///////////////////////////////////////////////////////////////////////////////////

        let path = "http://localhost/";
        let mut headers = Headers::new();
        headers.set(IronCookie(vec!(csrf_cookie.clone())));
        let body = "";

        let response = mock_request::get(path, headers.clone(), &handler).unwrap();
        assert_eq!(response.status, Some(status::Ok));

        let response = mock_request::head(path, headers.clone(), &handler).unwrap();
        assert_eq!(response.status, Some(status::Ok));

        let response = mock_request::head(path, headers.clone(), &handler).unwrap();
        assert_eq!(response.status, Some(status::Ok));

        let response = mock_request::request(Method::Trace, path, body, headers.clone(), &handler)
            .unwrap();
        assert_eq!(response.status, Some(status::Ok));

        let response =
            mock_request::request(Method::Connect, path, body, headers.clone(), &handler).unwrap();
        assert_eq!(response.status, Some(status::Ok));

        let response = mock_request::request(Method::Extension("WAT".to_string()),
                                             path,
                                             body,
                                             headers.clone(),
                                             &handler)
            .unwrap();
        assert_eq!(response.status, Some(status::Ok));

        let response = mock_request::post(path, headers.clone(), body, &handler).unwrap();
        assert_eq!(response.status, Some(status::Forbidden));

        let response = mock_request::put(path, headers.clone(), body, &handler).unwrap();
        assert_eq!(response.status, Some(status::Forbidden));

        let response = mock_request::put(path, headers.clone(), body, &handler).unwrap();
        assert_eq!(response.status, Some(status::Forbidden));

        let response = mock_request::patch(path, headers.clone(), body, &handler).unwrap();
        assert_eq!(response.status, Some(status::Forbidden));

        ///////////////////////////////////////////////////////////////////////////////////

        let path = "http://localhost/";
        let mut headers = Headers::new();
        headers.set(IronCookie(vec!(csrf_cookie.clone())));
        headers.set(XCsrfToken(csrf_token.clone()));
        let body = "";

        for verb in all_methods.iter().cloned() {
            let response = mock_request::request(verb, path, body, headers.clone(), &handler)
                .unwrap();
            assert_eq!(response.status, Some(status::Ok));
        }

        ///////////////////////////////////////////////////////////////////////////////////

        let path = format!("http://localhost/?{}={}",
                           CSRF_QUERY_STRING,
                           url_encode(&csrf_token));
        let path = path.as_str();
        let mut headers = Headers::new();
        headers.set(IronCookie(vec!(csrf_cookie.clone())));
        let body = "";

        for verb in all_methods.iter().cloned() {
            let response = mock_request::request(verb, path, body, headers.clone(), &handler)
                .unwrap();
            assert_eq!(response.status, Some(status::Ok));
        }

        ///////////////////////////////////////////////////////////////////////////////////

        let path = "http://localhost/";
        let mut headers = Headers::new();
        headers.set(IronCookie(vec!(csrf_cookie.clone())));
        headers.set_raw("content-type", vec!(b"application/x-www-form-urlencoded".to_vec()));
        let body = format!("{}={}", CSRF_QUERY_STRING, url_encode(&csrf_token));
        let body = body.as_str();

        for verb in body_methods.iter().cloned() {
            let response = mock_request::request(verb, path, body, headers.clone(), &handler)
                .unwrap();
            assert_eq!(response.status, Some(status::Ok));
        }
    }

    #[test]
    fn test_ed25519_csrf_protection() {
        let rng = SystemRandom::new();
        let (_, key_bytes) = Ed25519KeyPair::generate_serializable(&rng).unwrap();

        let key_pair = Ed25519KeyPair::from_bytes(&key_bytes.private_key, &key_bytes.public_key)
            .unwrap();
        let protect = Ed25519CsrfProtection::new(key_pair, key_bytes.public_key.to_vec());
        test_protection(protect);

        let key_pair = Ed25519KeyPair::from_bytes(&key_bytes.private_key, &key_bytes.public_key)
            .unwrap();
        let protect = Ed25519CsrfProtection::new(key_pair, key_bytes.public_key.to_vec());
        test_middleware(protect);

        let key_pair = Ed25519KeyPair::from_bytes(&key_bytes.private_key, &key_bytes.public_key)
            .unwrap();
        let protect = Ed25519CsrfProtection::new(key_pair, key_bytes.public_key.to_vec());
        let (token, _) = protect.generate_token_pair(300).unwrap();
        let (_, cookie) = protect.generate_token_pair(300).unwrap();
        assert!(!protect.verify_token_pair(&token, &cookie));
    }

    #[test]
    fn test_hmac_csrf_protection() {
        let rng = SystemRandom::new();

        let key = hmac::SigningKey::generate(&digest::SHA512, &rng).unwrap();
        let protect = HmacCsrfProtection::new(key);
        test_protection(protect);

        let key = hmac::SigningKey::generate(&digest::SHA512, &rng).unwrap();
        let protect = HmacCsrfProtection::new(key);
        test_middleware(protect);

        let key = hmac::SigningKey::generate(&digest::SHA512, &rng).unwrap();
        let protect = HmacCsrfProtection::new(key);
        let (token, _) = protect.generate_token_pair(300).unwrap();
        let (_, cookie) = protect.generate_token_pair(300).unwrap();
        assert!(!protect.verify_token_pair(&token, &cookie));
    }

    // TODO test form extraction
    // TODO test query extraction
    // TODO test headers extraction
    // TODO test that verifies protected_method feature/configuration
}
