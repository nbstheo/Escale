# Third-party notices

Escale is MIT-licensed (see `LICENSE`). It bundles or depends on:

| Component | License | Where |
|---|---|---|
| Inter (fonts) | SIL Open Font License 1.1 | `assets/fonts/Inter-*.ttf` |
| JetBrains Mono (fonts) | SIL Open Font License 1.1 | `assets/fonts/JetBrainsMono-*.ttf` |
| IronRDP (`ironrdp-connector`, `-egfx`, `-graphics`, patched copies) | MIT OR Apache-2.0 | `vendor/ironrdp-*` |
| picky, sspi (patched copies) | MIT OR Apache-2.0 | `vendor/picky`, `vendor/sspi` |
| vt100 (patched copy) | MIT | `vendor/vt100` |
| Cisco OpenH264 (via `openh264` crate, built from source) | BSD-2-Clause (see note) | Cargo dependency |
| Other Rust crates | mostly MIT / Apache-2.0 | `Cargo.lock` (`cargo install cargo-license && cargo license`) |

Each vendored directory keeps its upstream license file(s); the changes made to them are described in `Cargo.toml` (`[patch.crates-io]`).

Note on H.264: building OpenH264 from source does not grant Cisco's patent license, which only covers Cisco's own binaries. Distributors of Escale binaries are responsible for their own H.264 patent compliance.

The OFL license texts for Inter and JetBrains Mono must be added next to the fonts (`assets/fonts/OFL-Inter.txt`, `assets/fonts/OFL-JetBrainsMono.txt`) before publishing.
