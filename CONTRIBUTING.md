# Contributing

Thanks for your interest! Bug reports, fixes and features are welcome.

## Build and test (Windows)

```powershell
cargo build --release
cargo test --release
```

Requirements: Rust (stable, edition 2024) and the Visual Studio Build Tools (C++ workload).

## Pull requests

- One topic per PR, with tests when the behaviour is testable.
- `cargo test --release` must pass; keep code formatted (`cargo fmt`) and warning-free.
- Never include real hostnames, IPs, credentials, keys or vault files in code, tests, logs or screenshots.
- Changes to `vendor/` must be mentioned in `Cargo.toml` (`[patch.crates-io]`) and in the PR.
- The UI and code comments are in French; English is fine in issues and PRs.

By contributing you agree that your contribution is licensed under the MIT license.
