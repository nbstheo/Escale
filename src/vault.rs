//! Coffre chiffré local : Argon2id (dérivation du mot de passe maître) + XChaCha20-Poly1305.
//!
//! Format : MAGIC(8) | m_cost(4) | t_cost(4) | p_cost(4) | salt(16) | nonce(24) | ciphertext
//! L'en-tête (jusqu'au sel inclus) est authentifié comme données associées.

use crate::model::VaultData;
use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{KeyInit, XChaCha20Poly1305, XNonce};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use zeroize::{Zeroize, Zeroizing};

const MAGIC: &[u8; 8] = b"ESCALEV1";
const HEADER_LEN: usize = 8 + 12 + 16;
pub(crate) const M_COST: u32 = 64 * 1024; // 64 Mio
pub(crate) const T_COST: u32 = 3;
pub(crate) const P_COST: u32 = 1;

pub struct Vault {
    path: PathBuf,
    key: Zeroizing<[u8; 32]>,
    header: [u8; HEADER_LEN],
}

/// Dossier racine des données d'Escale (`%APPDATA%\Escale`).
pub fn root() -> PathBuf {
    if let Some(p) = portable() {
        return p.parent().map(PathBuf::from).unwrap_or_else(|| PathBuf::from("."));
    }
    let base = std::env::var_os("APPDATA")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".config")))
        .unwrap_or_else(|| PathBuf::from("."));
    base.join("Escale")
}

/// ESCALE_VAULT : coffre unique à un emplacement personnalisé (ex. mode portable sur clé USB).
pub fn portable() -> Option<PathBuf> {
    std::env::var_os("ESCALE_VAULT").map(PathBuf::from)
}

// ---------------------------------------------------------------- coffres multiples
//
// Chaque coffre vit dans son propre dossier : %APPDATA%\Escale\Coffre1, Coffre2…
// avec `vault.escale` (données chiffrées), `vault.pin` (déverrouillage rapide, lié à ce coffre
// et à la session Windows) et `profil.json` (propriétaire, affiché avant le déverrouillage).

const VAULT_FILE: &str = "vault.escale";
const PROFILE_FILE: &str = "profil.json";
const LAST_FILE: &str = "dernier-coffre";
const SLOT_PREFIX: &str = "Coffre";

/// Informations en clair d'un coffre. Simple étiquette : le propriétaire enregistré dans le coffre
/// chiffré fait foi et réécrit ce fichier à chaque ouverture.
#[derive(Serialize, Deserialize, Clone, Default)]
pub struct Profile {
    #[serde(default)]
    pub owner: String,
    /// Compte Windows qui a créé le coffre (le PIN ne fonctionne que dans cette session).
    #[serde(default)]
    pub windows_user: String,
    /// Date de création (secondes Unix).
    #[serde(default)]
    pub created: u64,
}

#[derive(Clone)]
pub struct VaultInfo {
    /// Chemin du fichier `vault.escale`.
    pub path: PathBuf,
    /// Nom du dossier (« Coffre1 »…).
    pub folder: String,
    pub profile: Profile,
}

impl VaultInfo {
    pub fn owner(&self) -> &str {
        if self.profile.owner.trim().is_empty() { &self.folder } else { &self.profile.owner }
    }
}

pub fn windows_user() -> String {
    std::env::var("USERNAME").or_else(|_| std::env::var("USER")).unwrap_or_default()
}

pub fn now() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

fn profile_path(vault_path: &Path) -> PathBuf {
    vault_path.with_file_name(PROFILE_FILE)
}

pub fn read_profile(vault_path: &Path) -> Profile {
    std::fs::read(profile_path(vault_path)).ok().and_then(|b| serde_json::from_slice(&b).ok()).unwrap_or_default()
}

pub fn write_profile(vault_path: &Path, profile: &Profile) -> Result<(), String> {
    let json = serde_json::to_vec_pretty(profile).map_err(|e| e.to_string())?;
    std::fs::write(profile_path(vault_path), json).map_err(|e| format!("Écriture du profil : {e}"))
}

fn slot_number(name: &str) -> Option<u32> {
    name.strip_prefix(SLOT_PREFIX)?.parse().ok()
}

/// Ancien emplacement unique (`Escale\vault.escale`) : déplacé dans `Coffre1`, avec son PIN et
/// son dossier de partage. La clé et le PIN ne dépendent pas du chemin : rien à re-chiffrer.
fn migrate_legacy(root: &Path) {
    let legacy = root.join(VAULT_FILE);
    if !legacy.exists() {
        return;
    }
    let dir = (1..).map(|n| root.join(format!("{SLOT_PREFIX}{n}"))).find(|d| !d.join(VAULT_FILE).exists()).unwrap();
    if std::fs::create_dir_all(&dir).is_err() || std::fs::rename(&legacy, dir.join(VAULT_FILE)).is_err() {
        return;
    }
    let _ = std::fs::rename(root.join("vault.pin"), dir.join("vault.pin"));
    if root.join("Partage").is_dir() && !dir.join("Partage").exists() {
        let _ = std::fs::rename(root.join("Partage"), dir.join("Partage"));
    }
    let path = dir.join(VAULT_FILE);
    let _ = write_profile(&path, &Profile { owner: String::new(), windows_user: windows_user(), created: now() });
    set_last_used(&path);
}

/// Coffres présents sur cet appareil, dans l'ordre des dossiers.
pub fn list() -> Vec<VaultInfo> {
    if let Some(p) = portable() {
        if !p.exists() {
            return Vec::new();
        }
        let folder = p.file_stem().map(|s| s.to_string_lossy().into_owned()).unwrap_or_default();
        return vec![VaultInfo { profile: read_profile(&p), path: p, folder }];
    }
    let root = root();
    migrate_legacy(&root);
    // tout sous-dossier contenant un coffre compte (ex. un dossier « PERSO » créé à la main)
    let mut out: Vec<VaultInfo> = std::fs::read_dir(&root)
        .into_iter()
        .flatten()
        .flatten()
        .filter_map(|e| {
            let folder = e.file_name().to_string_lossy().into_owned();
            let path = e.path().join(VAULT_FILE);
            path.is_file().then(|| VaultInfo { profile: read_profile(&path), path, folder })
        })
        .collect();
    // Coffre1, Coffre2… dans l'ordre numérique, puis les autres dossiers par nom
    out.sort_by_key(|v| (slot_number(&v.folder).unwrap_or(u32::MAX), v.folder.to_lowercase()));
    out
}

/// Emplacement libre pour un nouveau coffre (`CoffreN\vault.escale`, premier numéro libre).
pub fn new_slot() -> PathBuf {
    if let Some(p) = portable() {
        return p;
    }
    let root = root();
    (1..).map(|n| root.join(format!("{SLOT_PREFIX}{n}"))).find(|d| !d.exists()).unwrap().join(VAULT_FILE)
}

/// Peut-on créer un coffre supplémentaire ? (pas en mode portable)
pub fn can_add() -> bool {
    portable().is_none()
}

/// Coffre proposé au démarrage : le dernier ouvert, sinon le premier.
pub fn last_used(list: &[VaultInfo]) -> Option<VaultInfo> {
    let last = std::fs::read_to_string(root().join(LAST_FILE)).unwrap_or_default();
    list.iter().find(|v| v.folder == last.trim()).or(list.first()).cloned()
}

pub fn set_last_used(vault_path: &Path) {
    if portable().is_some() {
        return;
    }
    if let Some(folder) = vault_path.parent().and_then(|d| d.file_name()) {
        let _ = std::fs::write(root().join(LAST_FILE), folder.to_string_lossy().as_bytes());
    }
}

pub(crate) fn random<const N: usize>() -> [u8; N] {
    let mut b = [0u8; N];
    rand::fill(&mut b[..]);
    b
}

pub(crate) fn derive(password: &str, m: u32, t: u32, p: u32, salt: &[u8]) -> Result<Zeroizing<[u8; 32]>, String> {
    let params = Params::new(m, t, p, Some(32)).map_err(|e| e.to_string())?;
    let mut key = Zeroizing::new([0u8; 32]);
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
        .hash_password_into(password.as_bytes(), salt, key.as_mut())
        .map_err(|e| e.to_string())?;
    Ok(key)
}

fn make_header(m: u32, t: u32, p: u32, salt: &[u8; 16]) -> [u8; HEADER_LEN] {
    let mut h = [0u8; HEADER_LEN];
    h[..8].copy_from_slice(MAGIC);
    h[8..12].copy_from_slice(&m.to_le_bytes());
    h[12..16].copy_from_slice(&t.to_le_bytes());
    h[16..20].copy_from_slice(&p.to_le_bytes());
    h[20..36].copy_from_slice(salt);
    h
}

impl Vault {
    pub fn create_at(path: PathBuf, password: &str) -> Result<Vault, String> {
        let salt = random::<16>();
        let key = derive(password, M_COST, T_COST, P_COST, &salt)?;
        let vault = Vault { path, key, header: make_header(M_COST, T_COST, P_COST, &salt) };
        vault.save(&VaultData::default())?;
        Ok(vault)
    }

    fn read(path: &PathBuf) -> Result<(Vec<u8>, [u8; HEADER_LEN]), String> {
        let bytes = std::fs::read(path).map_err(|e| format!("Lecture du coffre : {e}"))?;
        if bytes.len() < HEADER_LEN + 24 + 16 || &bytes[..8] != MAGIC {
            return Err("Fichier de coffre invalide".into());
        }
        let header: [u8; HEADER_LEN] = bytes[..HEADER_LEN].try_into().unwrap();
        Ok((bytes, header))
    }

    pub fn open_at(path: PathBuf, password: &str) -> Result<(Vault, VaultData), String> {
        let (bytes, header) = Self::read(&path)?;
        let u = |i: usize| u32::from_le_bytes(header[i..i + 4].try_into().unwrap());
        let key = derive(password, u(8), u(12), u(16), &header[20..36])?;
        Self::decrypt(path, &bytes, header, key).map_err(|_| "Mot de passe incorrect".to_string())
    }

    /// Ouvre le coffre avec une clé déjà dérivée (déverrouillage par code PIN).
    pub fn open_with_key(path: PathBuf, key: Zeroizing<[u8; 32]>) -> Result<(Vault, VaultData), String> {
        let (bytes, header) = Self::read(&path)?;
        Self::decrypt(path, &bytes, header, key)
    }

    pub fn path(&self) -> &PathBuf {
        &self.path
    }

    pub fn key(&self) -> &[u8; 32] {
        &self.key
    }

    pub fn header(&self) -> &[u8] {
        &self.header
    }

    /// En-tête du coffre sur disque (sert à lier le fichier PIN à ce coffre précis).
    pub fn header_on_disk(path: &PathBuf) -> Result<Vec<u8>, String> {
        Ok(Self::read(path)?.1.to_vec())
    }

    fn decrypt(
        path: PathBuf,
        bytes: &[u8],
        header: [u8; HEADER_LEN],
        key: Zeroizing<[u8; 32]>,
    ) -> Result<(Vault, VaultData), String> {
        let nonce: [u8; 24] = bytes[HEADER_LEN..HEADER_LEN + 24].try_into().unwrap();
        let cipher = XChaCha20Poly1305::new((&*key).into());
        let plain = Zeroizing::new(
            cipher
                .decrypt(&XNonce::from(nonce), Payload { msg: &bytes[HEADER_LEN + 24..], aad: &header })
                .map_err(|_| "Clé incorrecte".to_string())?,
        );
        let data: VaultData = serde_json::from_slice(&plain).map_err(|e| format!("Coffre corrompu : {e}"))?;
        Ok((Vault { path, key, header }, data))
    }

    pub fn save(&self, data: &VaultData) -> Result<(), String> {
        let mut plain = serde_json::to_vec(data).map_err(|e| e.to_string())?;
        let nonce = random::<24>();
        let cipher = XChaCha20Poly1305::new((&*self.key).into());
        let ct = cipher
            .encrypt(&XNonce::from(nonce), Payload { msg: &plain, aad: &self.header })
            .map_err(|_| "Échec du chiffrement".to_string());
        plain.zeroize();
        let ct = ct?;

        let mut out = Vec::with_capacity(HEADER_LEN + 24 + ct.len());
        out.extend_from_slice(&self.header);
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&ct);

        if let Some(dir) = self.path.parent() {
            std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
        }
        // écriture atomique
        let tmp = self.path.with_extension("tmp");
        std::fs::write(&tmp, &out).map_err(|e| format!("Écriture du coffre : {e}"))?;
        std::fs::rename(&tmp, &self.path).map_err(|e| format!("Écriture du coffre : {e}"))?;
        Ok(())
    }

    /// Change le mot de passe maître (nouveau sel) et ré-chiffre les données.
    pub fn change_password(&mut self, new_password: &str, data: &VaultData) -> Result<(), String> {
        let salt = random::<16>();
        self.key = derive(new_password, M_COST, T_COST, P_COST, &salt)?;
        self.header = make_header(M_COST, T_COST, P_COST, &salt);
        self.save(data)
    }
}
