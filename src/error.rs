//! Module containing the CSRF error types.

use std::error::Error;
use std::fmt;

/// An `enum` of all CSRF related errors.
#[derive(Debug)]
pub enum CsrfError {
    /// The necessary pieces to validate a request were missing. This could mean the either the
    /// cookie or the token, query string, or form field are missing.
    CriteriaMissing,
    /// Input was not able to be converted from Base64.
    NotBase64,
    /// Random data was unable to be generated.
    RngError,
    /// Generic error case. Uncatchable by consumers of this crate.
    Undefined(String),
    /// The CSRF validation failed.
    ValidationFailed,
}

impl Error for CsrfError {
    fn description(&self) -> &str {
        "CSRF Error"
    }
}

impl fmt::Display for CsrfError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self)
    }
}
