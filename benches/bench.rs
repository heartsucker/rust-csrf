#![feature(test)]

extern crate csrf;
extern crate rustc_serialize;
#[cfg(test)]
extern crate test;

macro_rules! benchmark {
    ($strct: ident, $md: ident) => {
        mod $md {
            use csrf::{CsrfProtection, $strct};
            use rustc_serialize::base64::FromBase64;
            use test::Bencher;

            #[bench]
            fn generate_pair(b: &mut Bencher) {
                let protect = $strct::from_key(*b"01234567012345670123456701234567");
                b.iter(|| {
                    let _ = protect.generate_token_pair(None, 3600);
                });
            }

            #[bench]
            fn validate_pair_success(b: &mut Bencher) {
                let protect = $strct::from_key(*b"01234567012345670123456701234567");
                let mut pairs = Vec::new();

                for _ in 0..10 {
                    let (token, cookie) = protect.generate_token_pair(None, 3600).expect("failed to generate token");
                    let token = token.b64_string().from_base64().expect("token not base64");
                    let token = protect.parse_token(&token).expect("token not parsed");
                    let cookie = cookie.b64_string().from_base64().expect("cookie not base64");
                    let cookie = protect.parse_cookie(&cookie).expect("cookie not parsed");
                    pairs.push((token, cookie));
                }

                b.iter(|| {
                    for &(ref token, ref cookie) in pairs.iter() {
                        protect.verify_token_pair(&token, &cookie);
                    }
                });
            }

            #[bench]
            fn parse_cookie_success(b: &mut Bencher) {
                let protect = $strct::from_key(*b"01234567012345670123456701234567");
                let mut cookies = Vec::new();

                for _ in 0..10 {
                    let (_, cookie) = protect.generate_token_pair(None, 3600).expect("failed to generate cookie");
                    let cookie = cookie.b64_string().from_base64().expect("cookie not base64");
                    cookies.push(cookie)
                }

                b.iter(|| {
                    for cookie in cookies.iter() {
                        let _ = protect.parse_cookie(&cookie).expect("cookie not parsed");
                    }
                });
            }

            #[bench]
            fn parse_token_success(b: &mut Bencher) {
                let protect = $strct::from_key(*b"01234567012345670123456701234567");
                let mut tokens = Vec::new();

                for _ in 0..10 {
                    let (token, _) = protect.generate_token_pair(None, 3600).expect("failed to generate token");
                    let token = token.b64_string().from_base64().expect("token not base64");
                    tokens.push(token)
                }

                b.iter(|| {
                    for token in tokens.iter() {
                        let _ = protect.parse_token(&token).expect("token not parsed");
                    }
                });
            }

            #[bench]
            fn parse_cookie_bad_sig(b: &mut Bencher) {
                let protect = $strct::from_key(*b"01234567012345670123456701234567");
                let mut cookies = Vec::new();

                for _ in 0..10 {
                    let (_, cookie) = protect.generate_token_pair(None, 3600).expect("failed to generate cookie");
                    let mut cookie = cookie.b64_string().from_base64().expect("cookie not base64");
                    let cookie_len = cookie.len();
                    cookie[cookie_len - 1] ^= 0x01;
                    cookies.push(cookie)
                }

                b.iter(|| {
                    for cookie in cookies.iter() {
                        assert!(protect.parse_cookie(&cookie).is_err());
                    }
                });
            }

            #[bench]
            fn parse_token_bad_sig(b: &mut Bencher) {
                let protect = $strct::from_key(*b"01234567012345670123456701234567");
                let mut tokens = Vec::new();

                for _ in 0..10 {
                    let (token, _) = protect.generate_token_pair(None, 3600).expect("failed to generate token");
                    let mut token = token.b64_string().from_base64().expect("token not base64");
                    let token_len = token.len();
                    token[token_len - 1] ^= 0x01;
                    tokens.push(token)
                }

                b.iter(|| {
                    for token in tokens.iter() {
                        assert!(protect.parse_token(&token).is_err());
                    }
                });
            }

            #[bench]
            fn parse_cookie_bad_value(b: &mut Bencher) {
                let protect = $strct::from_key(*b"01234567012345670123456701234567");
                let mut cookies = Vec::new();

                for _ in 0..10 {
                    let (_, cookie) = protect.generate_token_pair(None, 3600).expect("failed to generate cookie");
                    let mut cookie = cookie.b64_string().from_base64().expect("cookie not base64");
                    cookie[0] ^= 0x01;
                    cookies.push(cookie)
                }

                b.iter(|| {
                    for cookie in cookies.iter() {
                        assert!(protect.parse_cookie(&cookie).is_err());
                    }
                });
            }

            #[bench]
            fn parse_token_bad_value(b: &mut Bencher) {
                let protect = $strct::from_key(*b"01234567012345670123456701234567");
                let mut tokens = Vec::new();

                for _ in 0..10 {
                    let (token, _) = protect.generate_token_pair(None, 3600).expect("failed to generate token");
                    let mut token = token.b64_string().from_base64().expect("token not base64");
                    token[0] ^= 0x01;
                    tokens.push(token)
                }

                b.iter(|| {
                    for token in tokens.iter() {
                        assert!(protect.parse_token(&token).is_err());
                    }
                });
            }
        }
    }
}

benchmark!(AesGcmCsrfProtection, aesgcm);
benchmark!(ChaCha20Poly1305CsrfProtection, chacha20poly1305);
benchmark!(HmacCsrfProtection, hmac);
