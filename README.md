<p align="center"><img src="assets/logo.svg" alt="Escale" width="120"></p>

<h1 align="center">Escale</h1>

<p align="center">
  A lightweight, native desktop client for <b>SSH, RDP and VNC</b> — single <code>.exe</code>, encrypted vault, jump hosts and a built-in per-host VPN.
</p>

<p align="center">
  <a href="https://github.com/nbstheo/Escale/releases/latest"><img alt="Latest release" src="https://img.shields.io/github/v/release/nbstheo/Escale?sort=semver"></a>
  <a href="https://github.com/nbstheo/Escale/actions/workflows/ci.yml"><img alt="CI" src="https://github.com/nbstheo/Escale/actions/workflows/ci.yml/badge.svg"></a>
  <a href="https://github.com/nbstheo/Escale/releases"><img alt="Downloads" src="https://img.shields.io/github/downloads/nbstheo/Escale/total"></a>
  <img alt="Platform" src="https://img.shields.io/badge/platform-Windows%2010%20%7C%2011-0078D6">
  <img alt="Rust" src="https://img.shields.io/badge/Rust-2024-orange">
  <a href="LICENSE"><img alt="License: MIT" src="https://img.shields.io/badge/license-MIT-green"></a>
</p>

<p align="center">
  <b>English</b> · <a href="README.fr.md">Français</a>
</p>

---

Escale is a native desktop client (Rust + egui) inspired by Termius. Everything ships in one executable: no runtime, no admin rights, nothing installed on the rest of the system.

> **Status:** early (0.x). Windows is the supported platform. The interface is currently in French.

## Download

| File | Description |
|---|---|
| [`Escale-Setup-<version>.exe`](https://github.com/nbstheo/Escale/releases/latest) | Installer (per-user, no admin rights required) |
| [`Escale-<version>-portable.exe`](https://github.com/nbstheo/Escale/releases/latest) | Portable executable, just run it |
| `SHA256SUMS.txt` | Checksums to verify your download |

Get them from the **[latest release](https://github.com/nbstheo/Escale/releases/latest)**. Binaries are built and published by GitHub Actions from the tagged source.

## Features

- **Unlimited hosts** (SSH, RDP, VNC) with groups, instant search and filters
- **SSH**: password or key authentication (OpenSSH, PEM, PuTTY `.ppk`, passphrases), built-in xterm-256color terminal, **one-click key setup** (generates an ed25519 key and installs it in `authorized_keys`), host-key verification (TOFU) with change alerts
- **SFTP file manager**: two columns (this PC / remote), drag and drop between them; over RDP, via a shared drive
- **Jump hosts (ProxyJump)**: chains of any length with loop detection, through `direct-tcpip` channels (nothing is decrypted on the hops). RDP and VNC hosts can use jump hosts too
- **RDP** (IronRDP): RDPGFX with H.264 (OpenH264), RemoteFX Progressive, ClearCodec; TLS + NLA/CredSSP/Kerberos, dynamic resolution, multi-monitor, audio and microphone, clipboard, shared folder, Windows shortcuts, auto-reconnect
- **VNC**: RFB 3.8, ZRLE / CopyRect / Raw
- **Built-in VPN per host**: reusable **WireGuard** and **OpenVPN** profiles (including WatchGuard SSL VPN), imported from `.conf` / `.ovpn`. The tunnel runs inside the app (user-space TCP/IP stack): no network adapter, no admin rights, the rest of the PC is unaffected. VPN → jump hosts → target chains are supported
- **Encrypted vault**: all data (hosts, passwords, keys, fingerprints) is encrypted on your device; encrypted export/import, several vaults per PC, optional 6-digit PIN

## Security model

| Item | Choice |
|---|---|
| Key derivation | Argon2id, 64 MiB, 3 iterations, random 16-byte salt |
| Encryption | XChaCha20-Poly1305 (fresh random 24-byte nonce on every save) |
| Integrity | Header (parameters + salt) authenticated as associated data |
| PIN | Vault key wrapped with Argon2id(PIN) + XChaCha20-Poly1305, then Windows DPAPI; the file is consumed on each attempt and rewritten only if the PIN is correct |
| Memory | Secrets are zeroized on lock / drop |
| Storage | `%APPDATA%\Escale\Coffre1`, `Coffre2`… (`vault.escale`, `vault.pin`, `profil.json`) |

The master password is never stored. **If you lose it, the vault cannot be recovered.**
This project has not been independently audited — see [SECURITY.md](SECURITY.md).

## Portable mode

Set `ESCALE_VAULT=path\to\vault.escale` to use a single vault stored elsewhere (e.g. a USB drive).

## Build from source

Requirements: Rust (stable, edition 2024) and the Visual Studio Build Tools (C++ workload).

```powershell
cargo build --release          # -> target\release\escale.exe
cargo test --release           # end-to-end tests with in-memory SSH / RDP / VNC / OpenVPN servers
```

Windows installer (requires [Inno Setup 6](https://jrsoftware.org/isinfo.php)):

```powershell
powershell -ExecutionPolicy Bypass -File installer\build.ps1   # -> dist\Escale-Setup-<version>.exe
```

### Publishing a release

Bump `version` in `Cargo.toml`, commit, then push a matching tag — the [Release workflow](.github/workflows/release.yml) builds the installer and the portable exe and attaches them to a GitHub release:

```powershell
git tag v0.2.2
git push origin v0.2.2
```

Real OpenVPN servers for manual testing: [`tools/openvpn-test`](tools/openvpn-test) (Docker). Run `gen-pki.sh` to create your own test certificates; they are git-ignored.

## Project layout

```
src/        application (app.rs UI, ssh.rs, rdp.rs, rfb.rs, vpn.rs, openvpn/, vault.rs, terminal.rs, …)
assets/     logo and fonts
vendor/     patched copies of dependencies, see [patch.crates-io] in Cargo.toml
installer/  Inno Setup script
tools/      OpenVPN test environment
```

Keyboard shortcuts and the full French documentation are in [README.fr.md](README.fr.md).

## Contributing

Issues and pull requests are welcome: see [CONTRIBUTING.md](CONTRIBUTING.md).

## License

[MIT](LICENSE). Bundled and vendored components keep their own licenses: see [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
