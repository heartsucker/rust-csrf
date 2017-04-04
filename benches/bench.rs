#![feature(test)]

extern crate csrf;
#[cfg(test)]
extern crate test;

macro_rules! benchmark {
    ($struct: ident, $mod: ident) => {
        mod $mod {
            use csrf::{CsrfProtection, $struct};
            use test::Bencher;

            #[bench]
            fn generate_pair(b: &mut Bencher) {
                let protect = $struct::from_key(*b"01234567012345670123456701234567");
                b.iter(|| {
                    let _ = protect.generate_token_pair(None, 3600);
                });
            }
        }
    }
}

benchmark!(AesGcmCsrfProtection, aesgcm);
benchmark!(ChaCha20Poly1305CsrfProtection, chacha20poly1305);
