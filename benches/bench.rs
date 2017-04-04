#![feature(test)]

extern crate csrf;
#[cfg(test)]
extern crate test;

macro_rules! benchmark {
    ($strct: ident, $md: ident) => {
        mod $md {
            use csrf::{CsrfProtection, $strct};
            use test::Bencher;

            #[bench]
            fn generate_pair(b: &mut Bencher) {
                let protect = $strct::from_key(*b"01234567012345670123456701234567");
                b.iter(|| {
                    let _ = protect.generate_token_pair(None, 3600);
                });
            }
        }
    }
}

benchmark!(AesGcmCsrfProtection, aesgcm);
benchmark!(ChaCha20Poly1305CsrfProtection, chacha20poly1305);
