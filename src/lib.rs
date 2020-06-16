//! Crate providing cross-site request forgery (CSRF) protection primitives
//!
//! ## Overview
//! `csrf` provides the basic building blocks you will need to implement CSRF protection for the
//! web framework of your choice. `csrf` generates encrypyed, signed tokens and cookies, and
//! verifies that they have not been tampered with and that they match.
//!
//! This crate is used by [iron-csrf](https://crates.io/crates/iron-csrf) and be used as a
//! reference for using `csrf` in other applications.
//!
//! ## Hello, CSRF.
//!
//! A simple example of how to use this library is as follows.
//!
//! ```
//! extern crate csrf;
//! extern crate data_encoding;
//!
//! use csrf::{AesGcmCsrfProtection, CsrfProtection};
//! use data_encoding::BASE64;
//!
//! fn main() {
//!     let protect = AesGcmCsrfProtection::from_key(*b"01234567012345670123456701234567");
//!
//!     let (token, cookie) = protect.generate_token_pair(None, 300)
//!         .expect("couldn't generate token/cookie pair");
//!
//!     let token_str = token.b64_string();
//!     let cookie_str = cookie.b64_string();
//!
//!     // add them to outgoing response
//!
//!     // wait for incoming connection
//!
//!     // extract them from an incoming request
//!
//!     let token_bytes = BASE64.decode(token_str.as_bytes()).expect("token not base64");
//!     let cookie_bytes= BASE64.decode(cookie_str.as_bytes()).expect("cookie not base64");
//!
//!     let parsed_token = protect.parse_token(&token_bytes).expect("token not parsed");
//!     let parsed_cookie = protect.parse_cookie(&cookie_bytes).expect("cookie not parsed");
//!
//!     assert!(protect.verify_token_pair(&parsed_token, &parsed_cookie));
//! }
//! ```
//!
//! ## Warning
//! CSRF protection is not a substitute for authentication or authorization. It *only* exists to
//! prevent malicious entities from forcing users to take actions they did not intend. If this is
//! unclear, please read the [Wikipedia
//! article](https://en.wikipedia.org/wiki/Cross-site_request_forgery).

#![deny(missing_docs)]

#[macro_use]
extern crate log;

mod core;
pub use crate::core::*;
