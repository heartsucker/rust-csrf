//! Module containing the core functionality for CSRF protection

use std::error::Error;
use std::{fmt, mem, str};

use crypto::aead::{AeadEncryptor, AeadDecryptor};
use crypto::aes::KeySize;
use crypto::aes_gcm::AesGcm;
use crypto::chacha20poly1305::ChaCha20Poly1305;
use crypto::scrypt::{scrypt, ScryptParams};
use ring::rand::SystemRandom;
use rustc_serialize::base64::{self, ToBase64};
use time;
#[cfg(feature = "iron")]
use typemap;


/// The name of the cookie for the CSRF validation data and signature.
pub const CSRF_COOKIE_NAME: &'static str = "csrf";

/// The name of the form field for the CSRF token.
pub const CSRF_FORM_FIELD: &'static str = "csrf-token";

/// The name of the HTTP header for the CSRF token.
pub const CSRF_HEADER: &'static str = "X-CSRF-Token";

/// The name of the query parameter for the CSRF token.
pub const CSRF_QUERY_STRING: &'static str = "csrf-token";

/// An `enum` of all CSRF related errors.
#[derive(Debug)]
pub enum CsrfError {
    InternalError,
    ValidationFailure,
}

impl Error for CsrfError {
    fn description(&self) -> &str {
        match *self {
            CsrfError::InternalError => "CSRF library error",
            CsrfError::ValidationFailure => "CSRF validation failed",
        }
    }
}

impl fmt::Display for CsrfError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self)
    }
}

/// A signed, encrypted CSRF token that is suitable to be displayed to end users.
#[derive(Eq, PartialEq, Debug)]
pub struct CsrfToken {
    bytes: Vec<u8>,
}

impl CsrfToken {
    pub fn new(bytes: Vec<u8>) -> Self {
        // TODO make this returna  Result and check that bytes is long enough
        CsrfToken { bytes: bytes }
    }

    /// Retrieve the CSRF token as a base64 encoded string.
    pub fn b64_string(&self) -> String {
        self.bytes.to_base64(base64::STANDARD)
    }

    /// Retrieve the CSRF token as a URL safe base64 encoded string.
    pub fn b64_url_string(&self) -> String {
        self.bytes.to_base64(base64::URL_SAFE)
    }
}

/// A signed, encrypted CSRF cookie that is suitable to be displayed to end users.
#[derive(Debug, Eq, PartialEq)]
pub struct CsrfCookie {
    bytes: Vec<u8>,
}

impl CsrfCookie {
    pub fn new(bytes: Vec<u8>) -> Self {
        CsrfCookie { bytes: bytes }
    }

    pub fn b64_string(&self) -> String {
        self.bytes.to_base64(base64::STANDARD)
    }
}

/// Internal represenation of an unencrypted CSRF token. This is not suitable to send to end users.
#[derive(Clone, Debug)]
pub struct UnencryptedCsrfToken {
    token: Vec<u8>,
}

impl UnencryptedCsrfToken {
    pub fn new(token: Vec<u8>) -> Self {
        UnencryptedCsrfToken { token: token }
    }

    pub fn token(&self) -> &[u8] {
        self.token.as_slice()
    }
}

/// Internal represenation of an unencrypted CSRF cookie. This is not suitable to send to end users.
#[derive(Clone, Debug)]
pub struct UnencryptedCsrfCookie {
    expires: i64,
    token: Vec<u8>,
}

impl UnencryptedCsrfCookie {
    pub fn new(expires: i64, token: Vec<u8>) -> Self {
        UnencryptedCsrfCookie {
            expires: expires,
            token: token,
        }
    }
}

/// The base trait that allows a developer to add CSRF protection to an application.
pub trait CsrfProtection: Send + Sync {
    /// Use a key derivation function (KDF) to generate key material.
    ///
    /// # Panics
    /// This function may panic if the underlying crypto library fails catastrophically.
    fn from_password(password: &[u8]) -> Self;

    /// Given a nonce and a time to live (TTL), create a cookie to send to the end user.
    fn generate_cookie(&self, nonce: &[u8], ttl_seconds: i64) -> Result<CsrfCookie, CsrfError>;

    /// Given a nonce, create a token to send to the end user.
    fn generate_token(&self, nonce: &[u8]) -> Result<CsrfToken, CsrfError>;

    /// Given a decoded byte array, deserialize, decrypt, and verify the cookie.
    fn parse_cookie(&self, cookie: &[u8]) -> Result<UnencryptedCsrfCookie, CsrfError>;

    /// Given a decoded byte array, deserialize, decrypt, and verify the token.
    fn parse_token(&self, token: &[u8]) -> Result<UnencryptedCsrfToken, CsrfError>;

    /// Provide a random number generator for other functions.
    fn rng(&self) -> &SystemRandom;

    /// Given a token pair that has been parsed, decoded, decrypted, and verified, return whether
    /// or not the token matches the cookie and they have not expired.
    fn verify_token_pair(&self,
                         token: &UnencryptedCsrfToken,
                         cookie: &UnencryptedCsrfCookie)
                         -> bool {
        let tokens_match = token.token == cookie.token;
        let not_expired = cookie.expires > time::precise_time_s() as i64;
        tokens_match && not_expired
    }

    /// Given a buffer, fill it with random bytes or error if this is not possible.
    fn random_bytes(&self, buf: &mut [u8]) -> Result<(), CsrfError> {
        self.rng()
            .fill(buf)
            .map_err(|_| {
                warn!("Failed to get random bytes");
                CsrfError::InternalError
            })
    }

    // TODO stop using token to describe the "nonce" and the token itself
    /// Given an optional previous token and a TTL, generate a matching token and cookie pair.
    fn generate_token_pair(&self,
                           previous_token: Option<Vec<u8>>,
                           ttl_seconds: i64)
                           -> Result<(CsrfToken, CsrfCookie), CsrfError> {
        let mut token = vec![0; 64];
        match previous_token {
            Some(ref previous) if previous.len() == 64 => {
                for i in 0..64 {
                    token[i] = previous[i];
                }
            }
            _ => self.random_bytes(&mut token)?,
        }

        match (self.generate_token(&token), self.generate_cookie(&token, ttl_seconds)) {
            (Ok(t), Ok(c)) => Ok((t, c)),
            _ => Err(CsrfError::ValidationFailure),
        }
    }
}

/// Uses AES-GCM to provide signed, encrypted CSRF tokens and cookies.
pub struct AesGcmCsrfProtection {
    rng: SystemRandom,
    aead_key: [u8; 32],
}

impl AesGcmCsrfProtection {
    /// Given an AES256 key, return an `AesGcmCsrfProtection` instance.
    pub fn from_key(aead_key: [u8; 32]) -> Self {
        AesGcmCsrfProtection {
            rng: SystemRandom::new(),
            aead_key: aead_key,
        }
    }

    fn aead<'a>(&self, nonce: &[u8; 12]) -> AesGcm<'a> {
        AesGcm::new(KeySize::KeySize256, &self.aead_key, nonce, &[])
    }
}

impl CsrfProtection for AesGcmCsrfProtection {
    /// Using `scrypt` with params `n=12`, `r=8`, `p=1`, generate the key material used for the
    /// underlying crypto functions.
    ///
    /// # Panics
    /// This function may panic if the underlying crypto library fails catastrophically.
    fn from_password(password: &[u8]) -> Self {
        let params = if cfg!(test) {
            // scrypt is *slow*, so use these params for testing
            ScryptParams::new(1, 8, 1)
        } else {
            ScryptParams::new(12, 8, 1)
        };

        let salt = b"rust-csrf-scrypt-salt";
        let mut aead_key = [0; 32];
        info!("Generating key material. This may take some time.");
        scrypt(password, salt, &params, &mut aead_key);
        info!("Key material generated.");

        AesGcmCsrfProtection::from_key(aead_key)
    }

    fn rng(&self) -> &SystemRandom {
        &self.rng
    }

    fn generate_cookie(&self, token: &[u8], ttl_seconds: i64) -> Result<CsrfCookie, CsrfError> {
        let expires = time::precise_time_s() as i64 + ttl_seconds;
        let expires_bytes = unsafe { mem::transmute::<i64, [u8; 8]>(expires) };

        let mut nonce = [0; 12];
        self.random_bytes(&mut nonce)?;

        let mut padding = [0; 16];
        self.random_bytes(&mut padding)?;

        let mut plaintext = [0; 88];

        for i in 0..16 {
            plaintext[i] = padding[i];
        }
        for i in 0..8 {
            plaintext[i + 16] = expires_bytes[i];
        }
        for i in 0..64 {
            plaintext[i + 24] = token[i];
        }

        let mut ciphertext = [0; 88];
        let mut tag = [0; 16];
        let mut aead = self.aead(&nonce);

        aead.encrypt(&plaintext, &mut ciphertext, &mut tag);

        let mut transport = [0; 116];

        for i in 0..88 {
            transport[i] = ciphertext[i];
        }
        for i in 0..12 {
            transport[i + 88] = nonce[i];
        }
        for i in 0..16 {
            transport[i + 100] = tag[i];
        }

        Ok(CsrfCookie::new(transport.to_vec()))
    }

    fn generate_token(&self, token: &[u8]) -> Result<CsrfToken, CsrfError> {
        let mut nonce = [0; 12];
        self.random_bytes(&mut nonce)?;

        let mut padding = [0; 16];
        self.random_bytes(&mut padding)?;

        let mut plaintext = [0; 80];

        for i in 0..16 {
            plaintext[i] = padding[i];
        }
        for i in 0..64 {
            plaintext[i + 16] = token[i];
        }

        let mut ciphertext = [0; 80];
        let mut tag = vec![0; 16];
        let mut aead = self.aead(&nonce);

        aead.encrypt(&plaintext, &mut ciphertext, &mut tag);

        let mut transport = [0; 108];

        for i in 0..80 {
            transport[i] = ciphertext[i];
        }
        for i in 0..12 {
            transport[i + 80] = nonce[i];
        }
        for i in 0..16 {
            transport[i + 92] = tag[i];
        }

        Ok(CsrfToken::new(transport.to_vec()))
    }

    fn parse_cookie(&self, cookie: &[u8]) -> Result<UnencryptedCsrfCookie, CsrfError> {
        if cookie.len() != 116 {
            return Err(CsrfError::ValidationFailure);
        }

        let mut ciphertext = [0; 88];
        let mut nonce = [0; 12];
        let mut tag = [0; 16];

        for i in 0..88 {
            ciphertext[i] = cookie[i];
        }
        for i in 0..12 {
            nonce[i] = cookie[i + 88];
        }
        for i in 0..16 {
            tag[i] = cookie[i + 100];
        }

        let mut plaintext = [0; 88];
        let mut aead = self.aead(&nonce);
        if !aead.decrypt(&ciphertext, &mut plaintext, &tag) {
            info!("Failed to decrypt CSRF cookie");
            return Err(CsrfError::ValidationFailure);
        }

        let mut expires_bytes = [0; 8];
        let mut token = [0; 64];

        // skip 16 bytes of padding
        for i in 0..8 {
            expires_bytes[i] = plaintext[i + 16];
        }
        for i in 0..64 {
            token[i] = plaintext[i + 24];
        }

        let expires = unsafe { mem::transmute::<[u8; 8], i64>(expires_bytes) };

        Ok(UnencryptedCsrfCookie::new(expires, token.to_vec()))
    }

    fn parse_token(&self, token: &[u8]) -> Result<UnencryptedCsrfToken, CsrfError> {
        if token.len() != 108 {
            return Err(CsrfError::ValidationFailure);
        }

        let mut ciphertext = [0; 80];
        let mut nonce = [0; 12];
        let mut tag = [0; 16];

        for i in 0..80 {
            ciphertext[i] = token[i];
        }
        for i in 0..12 {
            nonce[i] = token[i + 80];
        }
        for i in 0..16 {
            tag[i] = token[i + 92];
        }

        let mut plaintext = [0; 80];
        let mut aead = self.aead(&nonce);
        if !aead.decrypt(&ciphertext, &mut plaintext, &tag) {
            info!("Failed to decrypt CSRF token");
            return Err(CsrfError::ValidationFailure);
        }

        let mut token = [0; 64];

        // skip 16 bytes of padding
        for i in 0..64 {
            token[i] = plaintext[i + 16];
        }

        Ok(UnencryptedCsrfToken::new(token.to_vec()))
    }
}


/// Uses ChaCha20Poly1305 to provide signed, encrypted CSRF tokens and cookies.
pub struct ChaCha20Poly1305CsrfProtection {
    rng: SystemRandom,
    aead_key: [u8; 32],
}

impl ChaCha20Poly1305CsrfProtection {
    // TODO
    pub fn from_key(aead_key: [u8; 32]) -> Self {
        ChaCha20Poly1305CsrfProtection {
            rng: SystemRandom::new(),
            aead_key: aead_key,
        }
    }

    fn aead(&self, nonce: &[u8; 8]) -> ChaCha20Poly1305 {
        ChaCha20Poly1305::new(&self.aead_key, nonce, &[])
    }
}

impl CsrfProtection for ChaCha20Poly1305CsrfProtection {
    /// Using `scrypt` with params `n=12`, `r=8`, `p=1`, generate the key material used for the
    /// underlying crypto functions.
    ///
    /// # Panics
    /// This function may panic if the underlying crypto library fails catastrophically.
    fn from_password(password: &[u8]) -> Self {
        let params = if cfg!(test) {
            // scrypt is *slow*, so use these params for testing
            ScryptParams::new(1, 8, 1)
        } else {
            ScryptParams::new(12, 8, 1)
        };

        let salt = b"rust-csrf-scrypt-salt";
        let mut aead_key = [0; 32];
        info!("Generating key material. This may take some time.");
        scrypt(password, salt, &params, &mut aead_key);
        info!("Key material generated.");

        ChaCha20Poly1305CsrfProtection::from_key(aead_key)
    }

    fn rng(&self) -> &SystemRandom {
        &self.rng
    }

    fn generate_cookie(&self, token: &[u8], ttl_seconds: i64) -> Result<CsrfCookie, CsrfError> {
        let expires = time::precise_time_s() as i64 + ttl_seconds;
        let expires_bytes = unsafe { mem::transmute::<i64, [u8; 8]>(expires) };

        let mut nonce = [0; 8];
        self.random_bytes(&mut nonce)?;

        let mut padding = [0; 16];
        self.random_bytes(&mut padding)?;

        let mut plaintext = [0; 88];

        for i in 0..16 {
            plaintext[i] = padding[i];
        }
        for i in 0..8 {
            plaintext[i + 16] = expires_bytes[i];
        }
        for i in 0..64 {
            plaintext[i + 24] = token[i];
        }

        let mut ciphertext = [0; 88];
        let mut tag = [0; 16];
        let mut aead = self.aead(&nonce);

        aead.encrypt(&plaintext, &mut ciphertext, &mut tag);

        let mut transport = [0; 112];

        for i in 0..88 {
            transport[i] = ciphertext[i];
        }
        for i in 0..8 {
            transport[i + 88] = nonce[i];
        }
        for i in 0..16 {
            transport[i + 96] = tag[i];
        }

        Ok(CsrfCookie::new(transport.to_vec()))
    }

    fn generate_token(&self, token: &[u8]) -> Result<CsrfToken, CsrfError> {
        let mut nonce = [0; 8];
        self.random_bytes(&mut nonce)?;

        let mut padding = [0; 16];
        self.random_bytes(&mut padding)?;

        let mut plaintext = [0; 80];

        for i in 0..16 {
            plaintext[i] = padding[i];
        }
        for i in 0..64 {
            plaintext[i + 16] = token[i];
        }

        let mut ciphertext = [0; 80];
        let mut tag = vec![0; 16];
        let mut aead = self.aead(&nonce);

        aead.encrypt(&plaintext, &mut ciphertext, &mut tag);

        let mut transport = [0; 104];

        for i in 0..80 {
            transport[i] = ciphertext[i];
        }
        for i in 0..8 {
            transport[i + 80] = nonce[i];
        }
        for i in 0..16 {
            transport[i + 88] = tag[i];
        }

        Ok(CsrfToken::new(transport.to_vec()))
    }

    fn parse_cookie(&self, cookie: &[u8]) -> Result<UnencryptedCsrfCookie, CsrfError> {
        if cookie.len() != 112 {
            return Err(CsrfError::ValidationFailure);
        }

        let mut ciphertext = [0; 88];
        let mut nonce = [0; 8];
        let mut tag = [0; 16];

        for i in 0..88 {
            ciphertext[i] = cookie[i];
        }
        for i in 0..8 {
            nonce[i] = cookie[i + 88];
        }
        for i in 0..16 {
            tag[i] = cookie[i + 96];
        }

        let mut plaintext = [0; 88];
        let mut aead = self.aead(&nonce);
        if !aead.decrypt(&ciphertext, &mut plaintext, &tag) {
            info!("Failed to decrypt CSRF cookie");
            return Err(CsrfError::ValidationFailure);
        }

        let mut expires_bytes = [0; 8];
        let mut token = [0; 64];

        // skip 16 bytes of padding
        for i in 0..8 {
            expires_bytes[i] = plaintext[i + 16];
        }
        for i in 0..64 {
            token[i] = plaintext[i + 24];
        }

        let expires = unsafe { mem::transmute::<[u8; 8], i64>(expires_bytes) };

        Ok(UnencryptedCsrfCookie::new(expires, token.to_vec()))
    }

    fn parse_token(&self, token: &[u8]) -> Result<UnencryptedCsrfToken, CsrfError> {
        if token.len() != 104 {
            return Err(CsrfError::ValidationFailure);
        }

        let mut ciphertext = [0; 80];
        let mut nonce = [0; 8];
        let mut tag = [0; 16];

        for i in 0..80 {
            ciphertext[i] = token[i];
        }
        for i in 0..8 {
            nonce[i] = token[i + 80];
        }
        for i in 0..16 {
            tag[i] = token[i + 88];
        }

        let mut plaintext = [0; 80];
        let mut aead = self.aead(&nonce);
        if !aead.decrypt(&ciphertext, &mut plaintext, &tag) {
            info!("Failed to decrypt CSRF token");
            return Err(CsrfError::ValidationFailure);
        }

        let mut token = [0; 64];

        // skip 16 bytes of padding
        for i in 0..64 {
            token[i] = plaintext[i + 16];
        }

        Ok(UnencryptedCsrfToken::new(token.to_vec()))
    }
}

#[cfg(feature = "iron")]
impl typemap::Key for CsrfToken {
    type Value = CsrfToken;
}

#[cfg(test)]
mod tests {
    // TODO write test that ensures encrypted messages don't contain the plaintext
    // TODO test that checks tokens are repeated when given Some
    // TODO use macros for writing all of these

    macro_rules! test_cases {
        ($strct: ident, $md: ident) => {
            mod $md {
                use $crate::core::{CsrfProtection, $strct};
                use rustc_serialize::base64::FromBase64;

                #[test]
                fn from_password() {
                    let _ = $strct::from_password(b"correct horse battery staple");
                }

                #[test]
                fn verification_succeeds() {
                    let protect = $strct::from_key(*b"01234567012345670123456701234567");
                    let (token, cookie) = protect.generate_token_pair(None, 300)
                        .expect("couldn't generate token/cookie pair");
                    let token = token.b64_string().from_base64().expect("token not base64");
                    let token = protect.parse_token(&token).expect("token not parsed");
                    let cookie = cookie.b64_string().from_base64().expect("cookie not base64");
                    let cookie = protect.parse_cookie(&cookie).expect("cookie not parsed");
                    assert!(protect.verify_token_pair(&token, &cookie),
                            "could not verify token/cookie pair");
                }

                #[test]
                fn modified_cookie_sig_fails() {
                    let protect = $strct::from_key(*b"01234567012345670123456701234567");
                    let (_, mut cookie) = protect.generate_token_pair(None, 300)
                        .expect("couldn't generate token/cookie pair");
                    let cookie_len = cookie.bytes.len();
                    cookie.bytes[cookie_len - 1] ^= 0x01;
                    let cookie = cookie.b64_string().from_base64().expect("cookie not base64");
                    assert!(protect.parse_cookie(&cookie).is_err());
                }

                #[test]
                fn modified_cookie_value_fails() {
                    let protect = $strct::from_key(*b"01234567012345670123456701234567");
                    let (_, mut cookie) = protect.generate_token_pair(None, 300)
                        .expect("couldn't generate token/cookie pair");
                    cookie.bytes[0] ^= 0x01;
                    let cookie = cookie.b64_string().from_base64().expect("cookie not base64");
                    assert!(protect.parse_cookie(&cookie).is_err());
                }

                #[test]
                fn modified_token_sig_fails() {
                    let protect = $strct::from_key(*b"01234567012345670123456701234567");
                    let (mut token, _) = protect.generate_token_pair(None, 300)
                        .expect("couldn't generate token/token pair");
                    let token_len = token.bytes.len();
                    token.bytes[token_len - 1] ^= 0x01;
                    let token = token.b64_string().from_base64().expect("token not base64");
                    assert!(protect.parse_token(&token).is_err());
                }

                #[test]
                fn modified_token_value_fails() {
                    let protect = $strct::from_key(*b"01234567012345670123456701234567");
                    let (mut token, _) = protect.generate_token_pair(None, 300)
                        .expect("couldn't generate token/token pair");
                    token.bytes[0] ^= 0x01;
                    let token = token.b64_string().from_base64().expect("token not base64");
                    assert!(protect.parse_token(&token).is_err());
                }

                #[test]
                fn mismatched_cookie_token_fail() {
                    let protect = $strct::from_key(*b"01234567012345670123456701234567");
                    let (token, _) = protect.generate_token_pair(None, 300)
                        .expect("couldn't generate token/token pair");
                    let (_, cookie) = protect.generate_token_pair(None, 300)
                        .expect("couldn't generate token/token pair");

                    let token = token.b64_string().from_base64().expect("token not base64");
                    let token = protect.parse_token(&token).expect("token not parsed");
                    let cookie = cookie.b64_string().from_base64().expect("cookie not base64");
                    let cookie = protect.parse_cookie(&cookie).expect("cookie not parsed");
                    assert!(!protect.verify_token_pair(&token, &cookie),
                            "verified token/cookie pair when failure expected");
                }

                #[test]
                fn expired_token_fail() {
                    let protect = $strct::from_key(*b"01234567012345670123456701234567");
                    let (token, cookie) = protect.generate_token_pair(None, -1)
                        .expect("couldn't generate token/cookie pair");
                    let token = token.b64_string().from_base64().expect("token not base64");
                    let token = protect.parse_token(&token).expect("token not parsed");
                    let cookie = cookie.b64_string().from_base64().expect("cookie not base64");
                    let cookie = protect.parse_cookie(&cookie).expect("cookie not parsed");
                    assert!(!protect.verify_token_pair(&token, &cookie),
                            "verified token/cookie pair when failure expected");
                }
            }
        }
    }

    test_cases!(AesGcmCsrfProtection, aesgcm);
    test_cases!(ChaCha20Poly1305CsrfProtection, chacha20poly1305);
}
