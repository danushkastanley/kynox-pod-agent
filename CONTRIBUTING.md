# Contributing

Thank you for helping improve pod-agent.

1. Open an issue for significant behavioural, eBPF, or protocol changes.
2. Create a focused branch and keep the diff small.
3. Add or update tests when behaviour changes.
4. Run `cargo fmt --all -- --check`, `cargo clippy --workspace --all-targets -- -D warnings`, and `cargo test --workspace --locked` on Linux.
5. Update documentation for configuration or protocol changes.
6. Open a pull request describing the change, privilege impact, and verification.

Do not commit credentials, certificates, `.env` files, cluster data, build
artefacts, or personal information. New dependencies need a clear maintenance and
security justification.

By participating, you agree to follow [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).
