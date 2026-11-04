# Escale

[English](README.md) · **Français**

[![Dernière version](https://img.shields.io/github/v/release/nbstheo/Escale?sort=semver)](https://github.com/nbstheo/Escale/releases/latest) [![CI](https://github.com/nbstheo/Escale/actions/workflows/ci.yml/badge.svg)](https://github.com/nbstheo/Escale/actions/workflows/ci.yml) [![Licence MIT](https://img.shields.io/badge/licence-MIT-green)](LICENSE)

Client SSH, RDP et VNC de bureau, léger et natif (Rust + egui), inspiré de Termius.

## Téléchargement

Sur la **[dernière version](https://github.com/nbstheo/Escale/releases/latest)** : `Escale-Setup-<version>.exe` (installateur, sans droits admin), `Escale-<version>-portable.exe` (exécutable portable) et `SHA256SUMS.txt` (empreintes).

## Fonctionnalités

- **Hôtes illimités** en SSH, RDP ou VNC, regroupables par groupe, recherche instantanée ; la page des hôtes se filtre par protocole et par groupe
- **Bureau à distance RDP** (IronRDP) : pipeline graphique moderne RDPGFX par défaut (H.264 AVC420 via OpenH264, RemoteFX Progressive, ClearCodec, Planar ; repli automatique sur l'ancien mode si le serveur ne le propose pas), curseur système sans latence, TLS + NLA (CredSSP / NTLM), domaine Windows, résolution adaptée à la fenêtre (redimensionnement dynamique), curseur distant, clavier physique transmis tel quel (disposition locale annoncée au serveur), collage du presse-papiers tapé au clavier (Ctrl+Maj+V). Options propres à chaque hôte (éditeur d'hôte › Options du bureau à distance) : graphisme, résolution dynamique ou fixe (ajustée ou 1:1), **plusieurs écrans** (comme `mstsc /multimon` : tous ou seulement ceux choisis sur un plan des écrans ; fenêtre sans bordure découpée aux écrans choisis, au-dessus de la barre des tâches locale ; disposition annoncée au serveur pour la barre des tâches distante et l'agrandissement par écran), mise à l'échelle, son, micro, presse-papiers, dossier partagé, disposition clavier, raccourcis Windows (Win et Win+touche, Alt+Tab, Alt+F4, Alt+Espace, Ctrl+Échap, Impr écran envoyés au bureau distant ; Ctrl+Alt+Fin = Ctrl+Alt+Suppr), préréglages d'expérience, NLA / TLS / Kerberos, programme de démarrage, session administrateur et reconnexion automatique
- **VNC** (RFB 3.8, authentification VNC, encodages ZRLE / CopyRect / Raw, curseur distant)
- **Fichiers** : la barre de droite d'une session bascule entre *Console* (terminal ou bureau) et *Fichiers*, qui affiche deux colonnes à la place : ce PC à gauche, l'appareil distant à droite (SFTP sur la connexion SSH existante ; en RDP, le dossier partagé visible sur le bureau distant dans « Ce PC › Escale sur … », `\\tsclient\Escale`). On navigue dans les deux, on glisse les fichiers de l'une à l'autre ou dans un dossier pour les déplacer ; les dossiers sans droit d'accès sont masqués et un accès forcé affiche un refus explicite
- **Authentification** par mot de passe ou clé privée (OpenSSH, PEM, PuTTY .ppk ; phrase secrète supportée), avec repli mot de passe
- **Clé en un clic** : dans une session SSH ouverte par mot de passe, le bouton *Clé* de la barre de droite génère une clé ed25519, l'enregistre dans le coffre, ajoute la clé publique à `~/.ssh/authorized_keys` du serveur par la session en cours, puis passe l'hôte en connexion par clé (mot de passe conservé en secours)
- **Rebonds (ProxyJump)** : chaque hôte peut passer par un autre hôte, lui-même pouvant passer par un autre… La chaîne est résolue automatiquement (détection des boucles) via des canaux `direct-tcpip` : aucune donnée n'est déchiffrée sur les rebonds. Les hôtes RDP et VNC peuvent aussi passer par un ou plusieurs rebonds SSH
- **VPN par hôte, propre à Escale** : profils VPN réutilisables (WireGuard, OpenVPN — dont WatchGuard Mobile VPN SSL) enregistrés dans le coffre, importés depuis un `.conf` / `.ovpn` puis modifiables, et choisis dans chaque hôte. Le tunnel tourne dans l'application (pile TCP/IP en mémoire) : aucune carte réseau, aucun droit administrateur, le reste du PC n'est pas concerné. Enchaînement possible VPN → rebond(s) SSH → cible ; un tunnel est partagé par les onglets d'un même profil et fermé avec le dernier. OpenVPN : UDP / TCP, tls-auth, tls-crypt, AES-GCM, ChaCha20-Poly1305, AES-CBC + HMAC, identifiant / mot de passe, comp-lzo, routes et DNS poussés, renégociation. Serveurs OpenVPN réels de test : `tools/openvpn-test` (Docker)
- **Terminal intégré** (xterm-256color, couleurs truecolor, écran alternatif pour vim/htop, historique, sélection/copie, collage)
- **Coffre chiffré** : toutes les données (hôtes, mots de passe, clés, empreintes) sont chiffrées sur l'appareil
- **Export / import du coffre** (Paramètres) : export en copie chiffrée (mot de passe maître exigé) ; import qui ajoute les hôtes d'une sauvegarde sans modifier ceux déjà présents ; restauration complète d'une sauvegarde depuis l'écran de création du coffre (nouveau PC)
- **Plusieurs coffres** sur le même PC (un par personne) : sur l'écran de déverrouillage, « Changer de coffre » permet d'en choisir un autre ou d'en créer un ; chacun a son mot de passe maître, son PIN et son propriétaire, visibles dans Paramètres › Coffres de cet appareil
- **Code PIN à 6 chiffres** pour déverrouiller rapidement (choisi à la création du coffre ou dans les paramètres) ; une seule erreur et le mot de passe maître est exigé
- **Vérification des clés serveur** (TOFU) avec alerte si la clé change — y compris le certificat RDP, vérifié avant l'envoi des identifiants
- **Barre latérale rétractable** (flèche ou Ctrl+Maj+B)
- Un seul `.exe`, aucune dépendance à l'exécution

## Sécurité

| Élément | Choix |
|---|---|
| Dérivation de clé | Argon2id, 64 Mio, 3 itérations, sel aléatoire de 16 octets |
| Chiffrement | XChaCha20-Poly1305 (nonce aléatoire de 24 octets à chaque sauvegarde) |
| Intégrité | En-tête (paramètres + sel) authentifié en données associées |
| Fichiers | Un dossier par coffre : `%APPDATA%\Escale\Coffre1`, `Coffre2`… contenant `vault.escale` (écriture atomique), `vault.pin` et `profil.json` (propriétaire, seule information en clair). L'ancien `Escale\vault.escale` est déplacé automatiquement dans le premier `CoffreN` libre |
| Code PIN | Clé du coffre enveloppée par Argon2id(PIN) + XChaCha20-Poly1305, puis DPAPI (lié à la session Windows) ; fichier consommé à chaque tentative, réécrit seulement si le PIN est bon |
| Mémoire | secrets effacés (`zeroize`) au verrouillage / à la destruction |

Le mot de passe maître n'est jamais stocké. **S'il est perdu, le coffre est irrécupérable.**

## Compilation

```powershell
cargo build --release
# -> target\release\escale.exe
```

Prérequis Windows : Rust (rustup) + Visual Studio Build Tools (charge de travail C++).

Installateur (`dist\Escale-Setup-<version>.exe`, nécessite Inno Setup 6) :

```powershell
powershell -ExecutionPolicy Bypass -File installer\build.ps1
```

Mode portable : définir `ESCALE_VAULT=chemin\vers\vault.escale` pour utiliser un coffre unique placé ailleurs (ex. clé USB) ; la création d'autres coffres est alors désactivée.

## Tests

```powershell
cargo test --release
```

Tests de bout en bout avec des serveurs SSH en mémoire : mot de passe, refus d'authentification,
chaîne de 2 rebonds + clé ed25519, empreintes connues / changées, coffre (aller-retour, mauvais mot de passe, altération),
SFTP (envoi / liste / téléchargement sur la connexion du terminal), tunnel d'un hôte graphique à travers un rebond.
RDP contre un serveur IronRDP en mémoire (NLA, image, souris / clavier, certificat refusé, mauvais mot de passe),
VNC contre un serveur RFB minimal, opérations du lecteur partagé (création, écriture, renommage, suppression, confinement).

## Raccourcis du terminal

| Action | Raccourci |
|---|---|
| Copier la sélection | Ctrl+Shift+C, Ctrl+C (si sélection), clic droit |
| Coller | Ctrl+V |
| Défiler l'historique | Molette, Shift+PgUp / Shift+PgDn |
| Fermer un onglet | × ou clic molette |
| Reconnecter | clic droit sur l'onglet |
| Fichiers (SFTP / dossier partagé) | Ctrl+Maj+E |
| Saisir le mot de passe enregistré (invite sudo / su) | Ctrl+Maj+M ou bouton « Saisir le mot de passe » |
| Replier la barre latérale | Ctrl+Maj+B |

## Structure

```
src/
  main.rs      point d'entrée, fenêtre
  app.rs       interface (verrou, barres latérales, onglets, filtres, formulaires)
  ssh.rs       sessions russh + chaîne de rebonds (sert aussi de tunnel à RDP / VNC), ouverture SFTP
  rdp.rs       sessions RDP (IronRDP : TLS, NLA, image, entrées, redimensionnement)
  rdpdr.rs     redirection de lecteur RDP (dossier partagé confiné)
  gfx.rs       pipeline graphique RDP (surfaces, caches, codecs) composé dans l'image affichée
  clearcodec.rs  décodeur ClearCodec (texte, icônes, fenêtres) avec NSCodec et RLEX
  rfb.rs       sessions VNC (vnc-rs)
  desktop.rs   vue de bureau distant commune : image, souris, clavier, curseur
  files.rs     gestionnaire de fichiers deux colonnes : ce PC / SFTP ou dossier partagé
  terminal.rs  émulation vt100 + rendu + clavier
  vault.rs     coffre chiffré
  model.rs     hôtes, paramètres, résolution des rebonds
  logo.rs      logo vectoriel rasterisé (icône fenêtre + .exe)
assets/logo.svg    logo (« E » en trois voies)
vendor/        copies corrigées de dépendances, cf. [patch] de Cargo.toml : picky et sspi (versions de dalek
               assouplies), vt100 (panique au redimensionnement), ironrdp-connector (pipeline
               graphique, session console, son distant / micro, profondeur de couleur, échelle),
               ironrdp-egfx (une commande graphique illisible n'interrompt plus le flux),
               ironrdp-graphics (RemoteFX Progressive aligné sur FreeRDP : couleurs, pleine qualité,
               passes d'amélioration SRL / RAW, tuiles différentielles, DWT saturée, état par surface)
```
