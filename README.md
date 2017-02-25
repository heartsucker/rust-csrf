# rust-csrf

Primitives for CSRF protection.

`rust-csrf` uses Ed25519 DSA or HMAC to sign and verify timestamped CSRF cookies
and their accompanying tokens.

Documentation is hosted at [docs.rs](https://docs.rs/rust-csrf/).

## Beta Software

This code is not at this time suitable for any production deployment. It has not been
verified and the API is somewhat unstable. Use with caution.

## Contributing

Please make all pull requests to the `develop` branch.

### Bugs

This project has a **full disclosure** policy on security related errors. Please
treat these errors like all other bugs and file a public issue. Errors communitcated
via other channels will be immediately made public.

## Legal

### License

This work is licensed under the MIT license. See [LICENSE](./LICENSE) for details.

### Cryptography Notice

This software includes and uses cryptographic software. Your current country may have
restrictions on the import, export, possession, or use cryptographic software. Check
your country's relevant laws before using this in any way. See
[Wassenaar](http://www.wassenaar.org/) for more info.
