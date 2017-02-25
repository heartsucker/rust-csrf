//! Crate providing cross-site request forgery (CSRF) protection for Rust web frameworks..
//!
//! ## Overview
//!
//! CSRF is done checking all requests with the HTTP method POST, PUT, PATCH, and DELETE for the
//! presence of a CSRF token and cookie. Cryptographic signing ensures that only the true owner
//! of a cookie can perform actios against an API.
//!
//! ## Protection
//! There are three ways that `csrf` checks for the presence of a CSRF token.
//!
//! - The query string `csrf-token` in the body for requests with `Content-Type:
//! application/x-www-form-urlencoded`
//! - The query string `csrf-token` in the URL
//! - The header `X-CSRF-Token`
//!
//! The selection is done short circuit, so the first present wins, and retrieval only fails if the
//! token is not present in any of the fields.
//!
//! Tokens have a time to live (TTL) that defaults to 3600 seconds. If a token is stale, validation
//! will fail.
//!
//! In the provided implementations, tokens are cryptographically signed, so tampering with a token
//! or its signature will cause the validation to fail. Validation failures will return a `403
//! Forbidden`.
//!
//! Signatures and other data needed for validation are stored in a cookie that is sent to the user
//! via the `Set-Cookie` header.

extern crate chrono;
extern crate cookie;
#[cfg(feature = "iron_")]
extern crate hyper;
#[cfg(feature = "iron_")]
extern crate iron;
#[cfg(all(test, feature = "iron_"))]
extern crate iron_test;
extern crate protobuf;
extern crate ring;
extern crate rustc_serialize;
extern crate time;
extern crate untrusted;
extern crate urlencoded;

pub mod core;
pub mod error;
#[cfg(feature = "iron_")]
pub mod iron;
pub mod serial;
