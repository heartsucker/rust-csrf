#![no_main]

extern crate csrf;
#[macro_use]
extern crate libfuzzer_sys;

use csrf::{AesGcmCsrfProtection, CsrfProtection};

fuzz_target!(|data: &[u8]| {
    let protect = AesGcmCsrfProtection::from_key(*b"01234567012345670123456701234567");
    let _ = protect.parse_token(data);
});
