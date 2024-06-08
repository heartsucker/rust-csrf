//! Module containing the core functionality for CSRF protection

use std::{borrow::Cow, error::Error, fmt, io::Cursor};

use aead::{generic_array::GenericArray, Aead, Key, KeyInit};
use aes_gcm::Aes256Gcm;
use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use chacha20poly1305::ChaCha20Poly1305;
use chrono::{prelude::*, Duration};
use data_encoding::{BASE64, BASE64URL};
use hmac::{Hmac, Mac};
use rand::RngCore;
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

/// An `enum` of all CSRF related errors.
#[derive(Debug, Hash, Eq, PartialEq, Clone)]
pub enum CsrfError {
    /// There was an internal error.
    InternalError,
    /// There was CSRF token validation failure.
    ValidationFailure(String),
    /// There was a CSRF token encryption failure.
    EncryptionFailure(String),
}

impl Error for CsrfError {}

impl fmt::Display for CsrfError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            CsrfError::InternalError => write!(f, "Library error"),
            CsrfError::ValidationFailure(err) => write!(f, "Validation failed: {err}"),
            CsrfError::EncryptionFailure(err) => write!(f, "Encryption failed: {err}"),
        }
    }
}

/// A signed, encrypted CSRF token that is suitable to be displayed to end users.
#[derive(Eq, PartialEq, Debug, Clone, Hash)]
pub struct CsrfToken {
    bytes: Vec<u8>,
}

impl CsrfToken {
    /// Create a new token from the given bytes.
    pub fn new(bytes: Vec<u8>) -> Self {
        // TODO make this return a Result and check that bytes is long enough
        CsrfToken { bytes }
    }

    /// Retrieve the CSRF token as a base64 encoded string.
    pub fn b64_string(&self) -> String {
        BASE64.encode(&self.bytes)
    }

    /// Retrieve the CSRF token as a URL safe base64 encoded string.
    pub fn b64_url_string(&self) -> String {
        BASE64URL.encode(&self.bytes)
    }

    /// Get be raw value of this token.
    pub fn value(&self) -> &[u8] {
        &self.bytes
    }
}

/// A signed, encrypted CSRF cookie that is suitable to be displayed to end users.
#[derive(Debug, Eq, PartialEq, Clone, Hash)]
pub struct CsrfCookie {
    bytes: Vec<u8>,
}

impl CsrfCookie {
    /// Create a new cookie from the given token bytes.
    pub fn new(bytes: Vec<u8>) -> Self {
        // TODO make this return a Result and check that bytes is long enough
        CsrfCookie { bytes }
    }

    /// Get the base64 value of this cookie.
    pub fn b64_string(&self) -> String {
        BASE64.encode(&self.bytes)
    }

    /// Get be raw value of this cookie.
    pub fn value(&self) -> &[u8] {
        &self.bytes
    }
}

/// Internal represenation of an unencrypted CSRF token. This is not suitable to send to end users.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct UnencryptedCsrfToken {
    token: Vec<u8>,
}

impl UnencryptedCsrfToken {
    /// Create a new unenrypted token.
    pub fn new(token: Vec<u8>) -> Self {
        UnencryptedCsrfToken { token }
    }

    /// Retrieve the token value as bytes.
    #[deprecated]
    pub fn token(&self) -> &[u8] {
        &self.token
    }

    /// Retrieve the token value as bytes.
    pub fn value(&self) -> &[u8] {
        &self.token
    }
}

/// Internal represenation of an unencrypted CSRF cookie. This is not suitable to send to end users.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct UnencryptedCsrfCookie {
    expires: i64,
    token: Vec<u8>,
}

impl UnencryptedCsrfCookie {
    /// Create a new unenrypted cookie.
    pub fn new(expires: i64, token: Vec<u8>) -> Self {
        UnencryptedCsrfCookie { expires, token }
    }

    /// Retrieve the token value as bytes.
    pub fn value(&self) -> &[u8] {
        &self.token
    }
}

/// The base trait that allows a developer to add CSRF protection to an application.
pub trait CsrfProtection: Send + Sync {
    /// Given a nonce and a time to live (TTL), create a cookie to send to the end user.
    fn generate_cookie(
        &self,
        token_value: &[u8; 64],
        ttl_seconds: i64,
    ) -> Result<CsrfCookie, CsrfError>;

    /// Given a nonce, create a token to send to the end user.
    fn generate_token(&self, token_value: &[u8; 64]) -> Result<CsrfToken, CsrfError>;

    /// Given a decoded byte array, deserialize, decrypt, and verify the cookie.
    fn parse_cookie(&self, cookie: &[u8]) -> Result<UnencryptedCsrfCookie, CsrfError>;

    /// Given a decoded byte array, deserialize, decrypt, and verify the token.
    fn parse_token(&self, token: &[u8]) -> Result<UnencryptedCsrfToken, CsrfError>;

    /// Given a token pair that has been parsed, decoded, decrypted, and verified, return whether
    /// or not the token matches the cookie and they have not expired.
    fn verify_token_pair(
        &self,
        token: &UnencryptedCsrfToken,
        cookie: &UnencryptedCsrfCookie,
    ) -> Result<(), CsrfError> {
        if token.token != cookie.token {
            return Err(CsrfError::ValidationFailure(format!(
                "Token did not match cookie: T: {:?}, C: {:?}",
                BASE64.encode(&token.token),
                BASE64.encode(&cookie.token)
            )));
        }

        let now = Utc::now().timestamp();
        if cookie.expires <= now {
            return Err(CsrfError::ValidationFailure(format!(
                "Cookie expired. Expiration: {}, Current time: {}",
                cookie.expires, now
            )));
        }

        Ok(())
    }

    /// Given a buffer, fill it with random bytes or error if this is not possible.
    fn random_bytes(&self, buf: &mut [u8]) -> Result<(), CsrfError> {
        // TODO We had to get rid of `ring` because of `gcc` conflicts with `rust-crypto`, and
        // `ring`'s RNG didn't require mutability. Now create a new one per call which is not a
        // great idea.
        rand::rngs::OsRng.fill_bytes(buf);
        Ok(())
    }

    /// Given an optional previous token and a TTL, generate a matching token and cookie pair.
    fn generate_token_pair(
        &self,
        previous_token_value: Option<&[u8; 64]>,
        ttl_seconds: i64,
    ) -> Result<(CsrfToken, CsrfCookie), CsrfError> {
        let token: Cow<[u8; 64]> = match previous_token_value {
            Some(v) => Cow::Borrowed(v),
            None => {
                let mut new_token = [0; 64];
                self.random_bytes(&mut new_token)
                    .expect("Error filling random bytes");
                Cow::Owned(new_token)
            }
        };

        let generated_token = self.generate_token(&token)?;
        let generated_cookie = self.generate_cookie(&token, ttl_seconds)?;
        Ok((generated_token, generated_cookie))
    }
}

/// Uses HMAC to provide authenticated CSRF tokens and cookies.
pub struct HmacCsrfProtection {
    hmac_key: [u8; 32],
}

impl HmacCsrfProtection {
    /// Given an HMAC key, return an `HmacCsrfProtection` instance.
    pub fn from_key(hmac_key: [u8; 32]) -> Self {
        HmacCsrfProtection { hmac_key }
    }

    fn hmac(&self) -> HmacSha256 {
        <HmacSha256 as Mac>::new_from_slice(&self.hmac_key).expect("HMAC can take key of any size")
    }
}

impl CsrfProtection for HmacCsrfProtection {
    fn generate_cookie(
        &self,
        token_value: &[u8; 64],
        ttl_seconds: i64,
    ) -> Result<CsrfCookie, CsrfError> {
        let expires = (Utc::now() + Duration::seconds(ttl_seconds)).timestamp();
        let mut expires_bytes = [0u8; 8];
        (&mut expires_bytes[..])
            .write_i64::<BigEndian>(expires)
            .map_err(|_| CsrfError::InternalError)?;

        let mut hmac = self.hmac();
        hmac.update(&expires_bytes);
        hmac.update(token_value);
        let mac = hmac.finalize();
        let code = mac.into_bytes();

        let mut transport = [0; 104];
        transport[0..32].copy_from_slice(&code);
        transport[32..40].copy_from_slice(&expires_bytes);
        transport[40..].copy_from_slice(token_value);

        Ok(CsrfCookie::new(transport.to_vec()))
    }

    fn generate_token(&self, token_value: &[u8; 64]) -> Result<CsrfToken, CsrfError> {
        let mut hmac = self.hmac();
        hmac.update(token_value);
        let mac = hmac.finalize();
        let code = mac.into_bytes();

        let mut transport = [0; 96];
        transport[0..32].copy_from_slice(&code);
        transport[32..].copy_from_slice(token_value);

        Ok(CsrfToken::new(transport.to_vec()))
    }

    fn parse_cookie(&self, cookie: &[u8]) -> Result<UnencryptedCsrfCookie, CsrfError> {
        if cookie.len() != 104 {
            return Err(CsrfError::ValidationFailure(format!(
                "Cookie wrong size. Not parsed. Cookie length {} != 104",
                cookie.len()
            )));
        }

        let mut hmac = self.hmac();
        hmac.update(&cookie[32..]);

        hmac.verify_slice(&cookie[0..32])
            .map_err(|err| CsrfError::ValidationFailure(format!("Cookie had bad MAC: {err}")))?;

        let mut cur = Cursor::new(&cookie[32..40]);
        let expires = cur
            .read_i64::<BigEndian>()
            .map_err(|_| CsrfError::InternalError)?;
        Ok(UnencryptedCsrfCookie::new(expires, cookie[40..].to_vec()))
    }

    fn parse_token(&self, token: &[u8]) -> Result<UnencryptedCsrfToken, CsrfError> {
        if token.len() != 96 {
            return Err(CsrfError::ValidationFailure(format!(
                "Token too small. Not parsed. Token length {} != 96",
                token.len()
            )));
        }

        let mut hmac = self.hmac();
        hmac.update(&token[32..]);

        hmac.verify_slice(&token[0..32])
            .map_err(|err| CsrfError::ValidationFailure(format!("Token had bad MAC: {err}")))?;

        Ok(UnencryptedCsrfToken::new(token[32..].to_vec()))
    }
}

/// Uses AES-GCM to provide signed, encrypted CSRF tokens and cookies.
pub struct AesGcmCsrfProtection {
    aead_key: [u8; 32],
}

impl AesGcmCsrfProtection {
    /// Given an AES256 key, return an `AesGcmCsrfProtection` instance.
    pub fn from_key(aead_key: [u8; 32]) -> Self {
        AesGcmCsrfProtection { aead_key }
    }

    fn aead(&self) -> Aes256Gcm {
        let key = Key::<Aes256Gcm>::from_slice(&self.aead_key);
        Aes256Gcm::new(key)
    }
}

impl CsrfProtection for AesGcmCsrfProtection {
    fn generate_cookie(
        &self,
        token_value: &[u8; 64],
        ttl_seconds: i64,
    ) -> Result<CsrfCookie, CsrfError> {
        let expires = (Utc::now() + Duration::seconds(ttl_seconds)).timestamp();
        let mut expires_bytes = [0u8; 8];
        (&mut expires_bytes[..])
            .write_i64::<BigEndian>(expires)
            .map_err(|_| CsrfError::InternalError)?;

        let mut nonce = [0; 12];
        self.random_bytes(&mut nonce)?;

        let mut plaintext = [0; 104];
        self.random_bytes(&mut plaintext[0..32])?; // padding
        plaintext[32..40].copy_from_slice(&expires_bytes);
        plaintext[40..].copy_from_slice(token_value);

        let aead = self.aead();

        let nonce = GenericArray::from_slice(&nonce);
        let ciphertext = aead.encrypt(nonce, plaintext.as_ref()).map_err(|err| {
            CsrfError::EncryptionFailure(format!("Failed to encrypt cookie: {err}"))
        })?;

        let mut transport = [0; 132];
        transport[0..12].copy_from_slice(nonce);
        transport[12..].copy_from_slice(&ciphertext);

        Ok(CsrfCookie::new(transport.to_vec()))
    }

    fn generate_token(&self, token_value: &[u8; 64]) -> Result<CsrfToken, CsrfError> {
        let mut nonce = [0; 12];
        self.random_bytes(&mut nonce)?;

        let mut plaintext = [0; 96];
        self.random_bytes(&mut plaintext[0..32])?; // padding
        plaintext[32..].copy_from_slice(token_value);

        let aead = self.aead();

        let nonce = GenericArray::from_slice(&nonce);
        let ciphertext = aead.encrypt(nonce, plaintext.as_ref()).map_err(|err| {
            CsrfError::EncryptionFailure(format!("Failed to encrypt token: {err}"))
        })?;

        let mut transport = [0; 124];
        transport[0..12].copy_from_slice(nonce);
        transport[12..].copy_from_slice(&ciphertext);

        Ok(CsrfToken::new(transport.to_vec()))
    }

    fn parse_cookie(&self, cookie: &[u8]) -> Result<UnencryptedCsrfCookie, CsrfError> {
        if cookie.len() != 132 {
            return Err(CsrfError::ValidationFailure(format!(
                "Cookie wrong size. Not parsed. Cookie length {} != 132",
                cookie.len()
            )));
        }

        let mut nonce = [0; 12];
        nonce.copy_from_slice(&cookie[0..12]);

        let aead = self.aead();

        let nonce = GenericArray::from_slice(&nonce);
        let plaintext = aead.decrypt(nonce, cookie[12..].as_ref()).map_err(|err| {
            CsrfError::ValidationFailure(format!("Failed to decrypt cookie: {err}"))
        })?;

        let mut cur = Cursor::new(&plaintext[32..40]);
        let expires = cur
            .read_i64::<BigEndian>()
            .map_err(|_| CsrfError::InternalError)?;
        Ok(UnencryptedCsrfCookie::new(
            expires,
            plaintext[40..].to_vec(),
        ))
    }

    fn parse_token(&self, token: &[u8]) -> Result<UnencryptedCsrfToken, CsrfError> {
        if token.len() != 124 {
            return Err(CsrfError::ValidationFailure(format!(
                "Token too small. Not parsed. Token length {} != 124",
                token.len()
            )));
        }

        let mut nonce = [0; 12];
        nonce.copy_from_slice(&token[0..12]);

        let aead = self.aead();

        let nonce = GenericArray::from_slice(&nonce);
        let plaintext = aead.decrypt(nonce, token[12..].as_ref()).map_err(|err| {
            CsrfError::ValidationFailure(format!("Failed to decrypt token: {err}"))
        })?;

        Ok(UnencryptedCsrfToken::new(plaintext[32..].to_vec()))
    }
}

/// Uses ChaCha20Poly1305 to provide signed, encrypted CSRF tokens and cookies.
pub struct ChaCha20Poly1305CsrfProtection {
    aead_key: [u8; 32],
}

impl ChaCha20Poly1305CsrfProtection {
    /// Given a key, return a `ChaCha20Poly1305CsrfProtection` instance.
    pub fn from_key(aead_key: [u8; 32]) -> Self {
        ChaCha20Poly1305CsrfProtection { aead_key }
    }

    fn aead(&self) -> ChaCha20Poly1305 {
        ChaCha20Poly1305::new_from_slice(&self.aead_key).unwrap()
    }
}

impl CsrfProtection for ChaCha20Poly1305CsrfProtection {
    fn generate_cookie(
        &self,
        token_value: &[u8; 64],
        ttl_seconds: i64,
    ) -> Result<CsrfCookie, CsrfError> {
        let expires = (Utc::now() + Duration::seconds(ttl_seconds)).timestamp();
        let mut expires_bytes = [0u8; 8];
        (&mut expires_bytes[..])
            .write_i64::<BigEndian>(expires)
            .map_err(|_| CsrfError::InternalError)?;

        let mut nonce = [0; 12];
        self.random_bytes(&mut nonce)?;

        let mut plaintext = [0; 104];
        self.random_bytes(&mut plaintext[0..32])?; // padding
        plaintext[32..40].copy_from_slice(&expires_bytes);
        plaintext[40..].copy_from_slice(token_value);

        let aead = self.aead();

        let nonce = GenericArray::from_slice(&nonce);
        let ciphertext = aead.encrypt(nonce, plaintext.as_ref()).map_err(|err| {
            CsrfError::EncryptionFailure(format!("Failed to encrypt cookie: {err}"))
        })?;

        let mut transport = [0; 132];
        transport[0..12].copy_from_slice(nonce);
        transport[12..].copy_from_slice(&ciphertext);

        Ok(CsrfCookie::new(transport.to_vec()))
    }

    fn generate_token(&self, token_value: &[u8; 64]) -> Result<CsrfToken, CsrfError> {
        let mut nonce = [0; 12];
        self.random_bytes(&mut nonce)?;

        let mut plaintext = [0; 96];
        self.random_bytes(&mut plaintext[0..32])?; // padding
        plaintext[32..].copy_from_slice(token_value);

        let aead = self.aead();

        let nonce = GenericArray::from_slice(&nonce);
        let ciphertext = aead.encrypt(nonce, plaintext.as_ref()).map_err(|err| {
            CsrfError::EncryptionFailure(format!("Failed to encrypt token: {err}"))
        })?;

        let mut transport = [0; 124];
        transport[0..12].copy_from_slice(nonce);
        transport[12..].copy_from_slice(&ciphertext);

        Ok(CsrfToken::new(transport.to_vec()))
    }

    fn parse_cookie(&self, cookie: &[u8]) -> Result<UnencryptedCsrfCookie, CsrfError> {
        if cookie.len() != 132 {
            return Err(CsrfError::ValidationFailure(format!(
                "Cookie wrong size. Not parsed. Cookie length {} != 132",
                cookie.len()
            )));
        }

        let mut nonce = [0; 12];
        nonce.copy_from_slice(&cookie[0..12]);

        let aead = self.aead();

        let nonce = GenericArray::from_slice(&nonce);
        let plaintext = aead.decrypt(nonce, cookie[12..].as_ref()).map_err(|err| {
            CsrfError::ValidationFailure(format!("Failed to decrypt cookie: {err}"))
        })?;

        let mut cur = Cursor::new(&plaintext[32..40]);
        let expires = cur
            .read_i64::<BigEndian>()
            .map_err(|_| CsrfError::InternalError)?;
        Ok(UnencryptedCsrfCookie::new(
            expires,
            plaintext[40..].to_vec(),
        ))
    }

    fn parse_token(&self, token: &[u8]) -> Result<UnencryptedCsrfToken, CsrfError> {
        if token.len() != 124 {
            return Err(CsrfError::ValidationFailure(format!(
                "Token too small. Not parsed. Token length {} != 124",
                token.len()
            )));
        }

        let mut nonce = [0; 12];
        nonce.copy_from_slice(&token[0..12]);

        let aead = self.aead();

        let nonce = GenericArray::from_slice(&nonce);
        let plaintext = aead.decrypt(nonce, token[12..].as_ref()).map_err(|err| {
            CsrfError::ValidationFailure(format!("Failed to decrypt token: {err}"))
        })?;

        Ok(UnencryptedCsrfToken::new(plaintext[32..].to_vec()))
    }
}

/// This is used when one wants to rotate keys or switch from implementation to another. It accepts
/// `1 + N` instances of `CsrfProtection` and uses only the first to generate tokens and cookies.
/// The `N` remaining instances are used only for parsing.
pub struct MultiCsrfProtection {
    current: Box<dyn CsrfProtection>,
    previous: Vec<Box<dyn CsrfProtection>>,
}

impl MultiCsrfProtection {
    /// Create a new `MultiCsrfProtection` from one current `CsrfProtection` and some `N` previous
    /// instances of `CsrfProtection`.
    pub fn new(current: Box<dyn CsrfProtection>, previous: Vec<Box<dyn CsrfProtection>>) -> Self {
        Self { current, previous }
    }
}

impl CsrfProtection for MultiCsrfProtection {
    fn generate_cookie(
        &self,
        token_value: &[u8; 64],
        ttl_seconds: i64,
    ) -> Result<CsrfCookie, CsrfError> {
        self.current.generate_cookie(token_value, ttl_seconds)
    }

    fn generate_token(&self, token_value: &[u8; 64]) -> Result<CsrfToken, CsrfError> {
        self.current.generate_token(token_value)
    }

    fn parse_cookie(&self, cookie: &[u8]) -> Result<UnencryptedCsrfCookie, CsrfError> {
        match self.current.parse_cookie(cookie) {
            ok @ Ok(_) => ok,
            Err(_) => {
                for protection in self.previous.iter() {
                    match protection.parse_cookie(cookie) {
                        ok @ Ok(_) => return ok,
                        Err(_) => (),
                    }
                }
                Err(CsrfError::ValidationFailure(
                    "Failed to validate the cookie against all provided keys".to_owned(),
                ))
            }
        }
    }

    fn parse_token(&self, token: &[u8]) -> Result<UnencryptedCsrfToken, CsrfError> {
        match self.current.parse_token(token) {
            ok @ Ok(_) => ok,
            Err(_) => {
                for protection in self.previous.iter() {
                    match protection.parse_token(token) {
                        ok @ Ok(_) => return ok,
                        Err(_) => (),
                    }
                }
                Err(CsrfError::ValidationFailure(
                    "Failed to validate the token against all provided keys".to_owned(),
                ))
            }
        }
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

    const KEY_32: [u8; 32] = *b"01234567012345670123456701234567";
    const KEY2_32: [u8; 32] = *b"76543210765432107654321076543210";

    macro_rules! test_cases {
        ($strct: ident, $md: ident) => {
            mod $md {
                use super::KEY_32;
                use data_encoding::BASE64;
                use $crate::{$strct, CsrfProtection};

                #[test]
                fn verification_succeeds() {
                    let protect = $strct::from_key(KEY_32);
                    let (token, cookie) = protect
                        .generate_token_pair(None, 300)
                        .expect("couldn't generate token/cookie pair");
                    let token = &BASE64
                        .decode(token.b64_string().as_bytes())
                        .expect("token not base64");
                    let token = protect.parse_token(&token).expect("token not parsed");
                    let cookie = &BASE64
                        .decode(cookie.b64_string().as_bytes())
                        .expect("cookie not base64");
                    let cookie = protect.parse_cookie(&cookie).expect("cookie not parsed");
                    assert!(
                        protect.verify_token_pair(&token, &cookie).is_ok(),
                        "could not verify token/cookie pair"
                    );
                }

                #[test]
                fn modified_cookie_value_fails() {
                    let protect = $strct::from_key(KEY_32);
                    let (_, mut cookie) = protect
                        .generate_token_pair(None, 300)
                        .expect("couldn't generate token/cookie pair");
                    cookie.bytes[0] ^= 0x01;
                    let cookie = &BASE64
                        .decode(cookie.b64_string().as_bytes())
                        .expect("cookie not base64");
                    assert!(protect.parse_cookie(&cookie).is_err());
                }

                #[test]
                fn modified_token_value_fails() {
                    let protect = $strct::from_key(KEY_32);
                    let (mut token, _) = protect
                        .generate_token_pair(None, 300)
                        .expect("couldn't generate token/token pair");
                    token.bytes[0] ^= 0x01;
                    let token = &BASE64
                        .decode(token.b64_string().as_bytes())
                        .expect("token not base64");
                    assert!(protect.parse_token(&token).is_err());
                }

                #[test]
                fn mismatched_cookie_token_fail() {
                    let protect = $strct::from_key(KEY_32);
                    let (token, _) = protect
                        .generate_token_pair(None, 300)
                        .expect("couldn't generate token/token pair");
                    let (_, cookie) = protect
                        .generate_token_pair(None, 300)
                        .expect("couldn't generate token/token pair");

                    let token = &BASE64
                        .decode(token.b64_string().as_bytes())
                        .expect("token not base64");
                    let token = protect.parse_token(&token).expect("token not parsed");
                    let cookie = &BASE64
                        .decode(cookie.b64_string().as_bytes())
                        .expect("cookie not base64");
                    let cookie = protect.parse_cookie(&cookie).expect("cookie not parsed");
                    assert!(
                        !protect.verify_token_pair(&token, &cookie).is_ok(),
                        "verified token/cookie pair when failure expected"
                    );
                }

                #[test]
                fn expired_token_fail() {
                    let protect = $strct::from_key(KEY_32);
                    let (token, cookie) = protect
                        .generate_token_pair(None, -1)
                        .expect("couldn't generate token/cookie pair");
                    let token = &BASE64
                        .decode(token.b64_string().as_bytes())
                        .expect("token not base64");
                    let token = protect.parse_token(&token).expect("token not parsed");
                    let cookie = &BASE64
                        .decode(cookie.b64_string().as_bytes())
                        .expect("cookie not base64");
                    let cookie = protect.parse_cookie(&cookie).expect("cookie not parsed");
                    assert!(
                        !protect.verify_token_pair(&token, &cookie).is_ok(),
                        "verified token/cookie pair when failure expected"
                    );
                }
            }
        };
    }

    test_cases!(AesGcmCsrfProtection, aesgcm);
    test_cases!(ChaCha20Poly1305CsrfProtection, chacha20poly1305);
    test_cases!(HmacCsrfProtection, hmac);

    mod multi {
        macro_rules! test_cases {
            ($strct1: ident, $strct2: ident, $name: ident) => {
                mod $name {
                    use super::super::{super::*, KEY2_32, KEY_32};
                    use data_encoding::BASE64;

                    #[test]
                    fn no_previous() {
                        let protect = $strct1::from_key(KEY_32);
                        let mut pairs = vec![];
                        let pair = protect
                            .generate_token_pair(None, 300)
                            .expect("couldn't generate token/cookie pair");
                        pairs.push(pair);

                        let protect = MultiCsrfProtection::new(Box::new(protect), vec![]);
                        let pair = protect
                            .generate_token_pair(None, 300)
                            .expect("couldn't generate token/cookie pair");
                        pairs.push(pair);

                        for &(ref token, ref cookie) in pairs.iter() {
                            let token = &BASE64
                                .decode(token.b64_string().as_bytes())
                                .expect("token not base64");
                            let token = protect.parse_token(&token).expect("token not parsed");
                            let cookie = &BASE64
                                .decode(cookie.b64_string().as_bytes())
                                .expect("cookie not base64");
                            let cookie = protect.parse_cookie(&cookie).expect("cookie not parsed");
                            assert!(
                                protect.verify_token_pair(&token, &cookie).is_ok(),
                                "could not verify token/cookie pair"
                            );
                        }
                    }

                    #[test]
                    fn $name() {
                        let protect_1 = $strct1::from_key(KEY_32);
                        let mut pairs = vec![];
                        let pair = protect_1
                            .generate_token_pair(None, 300)
                            .expect("couldn't generate token/cookie pair");
                        pairs.push(pair);

                        let protect_2 = $strct2::from_key(KEY2_32);
                        let mut pairs = vec![];
                        let pair = protect_2
                            .generate_token_pair(None, 300)
                            .expect("couldn't generate token/cookie pair");
                        pairs.push(pair);

                        let protect = MultiCsrfProtection::new(
                            Box::new(protect_1),
                            vec![Box::new(protect_2)],
                        );
                        let pair = protect
                            .generate_token_pair(None, 300)
                            .expect("couldn't generate token/cookie pair");
                        pairs.push(pair);

                        for &(ref token, ref cookie) in pairs.iter() {
                            let token = &BASE64
                                .decode(token.b64_string().as_bytes())
                                .expect("token not base64");
                            let token = protect.parse_token(&token).expect("token not parsed");
                            let cookie = &BASE64
                                .decode(cookie.b64_string().as_bytes())
                                .expect("cookie not base64");
                            let cookie = protect.parse_cookie(&cookie).expect("cookie not parsed");
                            assert!(
                                protect.verify_token_pair(&token, &cookie).is_ok(),
                                "could not verify token/cookie pair"
                            );
                        }
                    }
                }
            };
        }

        test_cases!(
            AesGcmCsrfProtection,
            AesGcmCsrfProtection,
            aesgcm_then_aesgcm
        );

        test_cases!(
            ChaCha20Poly1305CsrfProtection,
            ChaCha20Poly1305CsrfProtection,
            chacha20poly1305_then_chacha20poly1305
        );

        test_cases!(HmacCsrfProtection, HmacCsrfProtection, hmac_then_hmac);

        test_cases!(
            ChaCha20Poly1305CsrfProtection,
            AesGcmCsrfProtection,
            chacha20poly1305_then_aesgcm
        );

        test_cases!(HmacCsrfProtection, AesGcmCsrfProtection, hmac_then_aesgcm);

        test_cases!(
            AesGcmCsrfProtection,
            ChaCha20Poly1305CsrfProtection,
            aesgcm_then_chacha20poly1305
        );
        test_cases!(
            HmacCsrfProtection,
            ChaCha20Poly1305CsrfProtection,
            hmac_then_chacha20poly1305
        );

        test_cases!(AesGcmCsrfProtection, HmacCsrfProtection, aesgcm_then_hmac);
        test_cases!(
            ChaCha20Poly1305CsrfProtection,
            HmacCsrfProtection,
            chacha20poly1305_then_hmac
        );
    }
}
