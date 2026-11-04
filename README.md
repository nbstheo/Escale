<p align="center"><img src="assets/logo.svg" alt="Escale" width="120"></p>

<h1 align="center">Escale</h1>

<p align="center">
  <b>SSH · RDP · VNC</b> — native, lightweight, encrypted.<br>
  Client SSH, RDP et VNC natif, léger et chiffré.
</p>

<p align="center">
  <a href="https://github.com/nbstheo/Escale/releases/latest"><img alt="Release" src="https://img.shields.io/github/v/release/nbstheo/Escale?sort=semver&label=release"></a>
  <a href="https://github.com/nbstheo/Escale/releases"><img alt="Downloads" src="https://img.shields.io/github/downloads/nbstheo/Escale/total"></a>
  <img alt="Windows 10 | 11" src="https://img.shields.io/badge/Windows-10%20%7C%2011-0078D6">
  <img alt="Rust" src="https://img.shields.io/badge/Rust-2024-orange">
  <a href="LICENSE"><img alt="MIT" src="https://img.shields.io/badge/license-MIT-green"></a>
</p>

<p align="center">
  <a href="https://github.com/nbstheo/Escale/releases/latest"><b>⬇ Download / Télécharger <code>Escale.exe</code></b></a>
</p>

<p align="center">
  <a href="#english">English</a> · <a href="#français">Français</a>
</p>

---

## English

A native desktop client (Rust + egui) inspired by Termius. **One `.exe`, nothing to install**: no runtime, no admin rights.

> Early version (0.x). Windows 10 / 11. The interface is currently in French.

### Features

- **Unlimited hosts** (SSH, RDP, VNC) with groups, instant search and filters
- **SSH**: password or key (OpenSSH, PEM, PuTTY `.ppk`, passphrases), xterm-256color terminal, **one-click key setup** (ed25519 key generated and added to `authorized_keys`), host-key verification with change alerts
- **Files**: two-column manager (this PC / remote) with drag and drop — SFTP over SSH, shared drive over RDP
- **Jump hosts (ProxyJump)**: chains of any length, nothing decrypted on the hops; RDP and VNC can use them too
- **RDP** (IronRDP): H.264, RemoteFX, ClearCodec, NLA / Kerberos, dynamic resolution, **multi-monitor**, sound and microphone, clipboard, shared folder, Windows shortcuts, auto-reconnect
- **VNC**: RFB 3.8, ZRLE / CopyRect / Raw
- **Built-in VPN per host**: **WireGuard** and **OpenVPN** (including WatchGuard SSL VPN) from `.conf` / `.ovpn`. The tunnel runs inside the app — no network adapter, no admin rights, the rest of the PC is unaffected
- **Encrypted vault**: hosts, passwords, keys and fingerprints encrypted on your device; encrypted export / import, several vaults per PC, optional 6-digit PIN

### Security

| | |
|---|---|
| Key derivation | Argon2id (64 MiB, 3 iterations, random salt) |
| Encryption | XChaCha20-Poly1305, fresh nonce on every save |
| PIN | Vault key wrapped with Argon2id(PIN), then Windows DPAPI |
| Memory | Secrets wiped on lock |
| Storage | `%APPDATA%\Escale\Coffre1`, `Coffre2`… |

The master password is never stored: **if you lose it, the vault cannot be recovered.**
Not independently audited — see [SECURITY.md](SECURITY.md).

**Portable mode:** set `ESCALE_VAULT=path\to\vault.escale` to keep the vault elsewhere (e.g. a USB drive).

### Terminal shortcuts

| Action | Shortcut |
|---|---|
| Copy | Ctrl+Shift+C, Ctrl+C (with selection), right click |
| Paste | Ctrl+V |
| Scroll history | Mouse wheel, Shift+PgUp / PgDn |
| Files panel | Ctrl+Shift+E |
| Type the saved password (sudo / su) | Ctrl+Shift+M |
| Collapse sidebar | Ctrl+Shift+B |

---

## Français

Client de bureau natif (Rust + egui) inspiré de Termius. **Un seul `.exe`, rien à installer** : aucune dépendance, aucun droit administrateur.

> Version précoce (0.x). Windows 10 / 11.

### Fonctionnalités

- **Hôtes illimités** (SSH, RDP, VNC) avec groupes, recherche instantanée et filtres
- **SSH** : mot de passe ou clé (OpenSSH, PEM, PuTTY `.ppk`, phrase secrète), terminal xterm-256color, **clé en un clic** (clé ed25519 générée et ajoutée à `authorized_keys`), vérification des clés serveur avec alerte si elles changent
- **Fichiers** : gestionnaire deux colonnes (ce PC / distant) avec glisser-déposer — SFTP en SSH, dossier partagé en RDP
- **Rebonds (ProxyJump)** : chaînes de longueur quelconque, rien n'est déchiffré sur les rebonds ; utilisables aussi en RDP et VNC
- **RDP** (IronRDP) : H.264, RemoteFX, ClearCodec, NLA / Kerberos, résolution dynamique, **multi-écrans**, son et micro, presse-papiers, dossier partagé, raccourcis Windows, reconnexion automatique
- **VNC** : RFB 3.8, ZRLE / CopyRect / Raw
- **VPN intégré par hôte** : **WireGuard** et **OpenVPN** (dont WatchGuard SSL VPN) depuis un `.conf` / `.ovpn`. Le tunnel tourne dans l'application — aucune carte réseau, aucun droit admin, le reste du PC n'est pas concerné
- **Coffre chiffré** : hôtes, mots de passe, clés et empreintes chiffrés sur l'appareil ; export / import chiffré, plusieurs coffres par PC, code PIN à 6 chiffres en option

### Sécurité

| | |
|---|---|
| Dérivation de clé | Argon2id (64 Mio, 3 itérations, sel aléatoire) |
| Chiffrement | XChaCha20-Poly1305, nonce neuf à chaque sauvegarde |
| Code PIN | Clé du coffre enveloppée par Argon2id(PIN), puis DPAPI Windows |
| Mémoire | Secrets effacés au verrouillage |
| Stockage | `%APPDATA%\Escale\Coffre1`, `Coffre2`… |

Le mot de passe maître n'est jamais stocké : **s'il est perdu, le coffre est irrécupérable.**
Pas encore audité de façon indépendante — voir [SECURITY.md](SECURITY.md).

**Mode portable :** définir `ESCALE_VAULT=chemin\vers\vault.escale` pour placer le coffre ailleurs (ex. clé USB).

### Raccourcis du terminal

| Action | Raccourci |
|---|---|
| Copier | Ctrl+Maj+C, Ctrl+C (si sélection), clic droit |
| Coller | Ctrl+V |
| Défiler l'historique | Molette, Maj+PgUp / PgDn |
| Panneau Fichiers | Ctrl+Maj+E |
| Saisir le mot de passe enregistré (sudo / su) | Ctrl+Maj+M |
| Replier la barre latérale | Ctrl+Maj+B |

---

<p align="center">
  <a href="LICENSE">MIT</a> · <a href="THIRD_PARTY_NOTICES.md">Third-party notices / Licences tierces</a> · <a href="CONTRIBUTING.md">Contributing</a>
</p>
