//! Déverrouillage rapide par code PIN à 6 chiffres.
//!
//! La clé du coffre est chiffrée avec une clé dérivée du PIN (Argon2id + XChaCha20-Poly1305),
//! puis protégée par DPAPI : le fichier n'est exploitable que par la session Windows de
//! l'utilisateur sur cette machine. Une seule tentative : le fichier est supprimé avant la
//! vérification et n'est réécrit qu'en cas de succès. Après une erreur, le mot de passe
//! maître est obligatoire ; le PIN (conservé dans le coffre chiffré) est alors réactivé.

use crate::model::VaultData;
use crate::vault::{self, Vault};
use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{KeyInit, XChaCha20Poly1305, XNonce};
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

const MAGIC: &[u8; 8] = b"ESCPIN01";
const PLAIN_LEN: usize = 8 + 16 + 24 + 32 + 16;

pub fn pin_path(vault_path: &Path) -> PathBuf {
    vault_path.with_extension("pin")
}

pub fn is_valid(pin: &str) -> bool {
    pin.len() == 6 && pin.bytes().all(|b| b.is_ascii_digit())
}

pub fn is_enabled(vault_path: &Path) -> bool {
    pin_path(vault_path).exists()
}

pub fn disable(vault_path: &Path) {
    let _ = std::fs::remove_file(pin_path(vault_path));
}

fn aad(salt: &[u8], vault_header: &[u8]) -> Vec<u8> {
    [MAGIC.as_slice(), salt, vault_header].concat()
}

/// Active (ou remplace) le PIN pour ce coffre.
pub fn enable(vault: &Vault, pin: &str) -> Result<(), String> {
    if !is_valid(pin) {
        return Err("Le code PIN doit comporter exactement 6 chiffres".into());
    }
    let salt = vault::random::<16>();
    let nonce = vault::random::<24>();
    let pin_key = vault::derive(pin, vault::M_COST, vault::T_COST, vault::P_COST, &salt)?;
    let ct = XChaCha20Poly1305::new((&*pin_key).into())
        .encrypt(&XNonce::from(nonce), Payload { msg: vault.key(), aad: &aad(&salt, vault.header()) })
        .map_err(|_| "Échec du chiffrement".to_string())?;

    let mut plain = Zeroizing::new(Vec::with_capacity(PLAIN_LEN));
    plain.extend_from_slice(MAGIC);
    plain.extend_from_slice(&salt);
    plain.extend_from_slice(&nonce);
    plain.extend_from_slice(&ct);
    let blob = dpapi::protect(&plain)?;

    let path = pin_path(vault.path());
    let tmp = path.with_extension("pin.tmp");
    std::fs::write(&tmp, &blob).map_err(|e| format!("Écriture du PIN : {e}"))?;
    std::fs::rename(&tmp, &path).map_err(|e| format!("Écriture du PIN : {e}"))
}

pub enum PinError {
    /// PIN faux : le PIN est désactivé jusqu'à la saisie du mot de passe maître.
    Wrong,
    /// PIN inutilisable (coffre modifié, autre session Windows…).
    Unavailable(String),
}

/// Tente d'ouvrir le coffre avec le PIN. Une seule tentative possible.
pub fn unlock(vault_path: PathBuf, pin: &str) -> Result<(Vault, VaultData), PinError> {
    let path = pin_path(&vault_path);
    let blob = std::fs::read(&path).map_err(|_| PinError::Unavailable("Code PIN non configuré".into()))?;
    // Consommer la tentative avant toute vérification (résiste à un arrêt brutal de l'appli).
    std::fs::remove_file(&path)
        .map_err(|e| PinError::Unavailable(format!("Fichier PIN inaccessible : {e}")))?;

    let plain = Zeroizing::new(
        dpapi::unprotect(&blob).map_err(|_| PinError::Unavailable("PIN lié à une autre session Windows".into()))?,
    );
    if plain.len() != PLAIN_LEN || &plain[..8] != MAGIC {
        return Err(PinError::Unavailable("Fichier PIN invalide".into()));
    }
    let (salt, nonce, ct) = (&plain[8..24], &plain[24..48], &plain[48..]);
    let header = Vault::header_on_disk(&vault_path).map_err(PinError::Unavailable)?;
    if !is_valid(pin) {
        return Err(PinError::Wrong);
    }
    let pin_key = vault::derive(pin, vault::M_COST, vault::T_COST, vault::P_COST, salt)
        .map_err(PinError::Unavailable)?;
    let nonce: [u8; 24] = nonce.try_into().unwrap();
    let key = XChaCha20Poly1305::new((&*pin_key).into())
        .decrypt(&XNonce::from(nonce), Payload { msg: ct, aad: &aad(salt, &header) })
        .map_err(|_| PinError::Wrong)?;
    let key: Zeroizing<[u8; 32]> =
        Zeroizing::new(key.as_slice().try_into().map_err(|_| PinError::Unavailable("Clé invalide".into()))?);

    let opened = Vault::open_with_key(vault_path, key).map_err(PinError::Unavailable)?;
    // Succès : la tentative est rendue.
    let _ = std::fs::write(&path, &blob);
    Ok(opened)
}

#[cfg(windows)]
mod dpapi {
    use windows_sys::Win32::Foundation::LocalFree;
    use windows_sys::Win32::Security::Cryptography::{
        CRYPT_INTEGER_BLOB, CRYPTPROTECT_UI_FORBIDDEN, CryptProtectData, CryptUnprotectData,
    };

    fn call(data: &[u8], protect: bool) -> Result<Vec<u8>, String> {
        let input = CRYPT_INTEGER_BLOB { cbData: data.len() as u32, pbData: data.as_ptr() as *mut u8 };
        let mut out = CRYPT_INTEGER_BLOB { cbData: 0, pbData: std::ptr::null_mut() };
        // SAFETY : tampons valides pendant l'appel ; la sortie est allouée par Windows puis libérée.
        unsafe {
            let ok = if protect {
                CryptProtectData(
                    &input,
                    std::ptr::null(),
                    std::ptr::null(),
                    std::ptr::null(),
                    std::ptr::null(),
                    CRYPTPROTECT_UI_FORBIDDEN,
                    &mut out,
                )
            } else {
                CryptUnprotectData(
                    &input,
                    std::ptr::null_mut(),
                    std::ptr::null(),
                    std::ptr::null(),
                    std::ptr::null(),
                    CRYPTPROTECT_UI_FORBIDDEN,
                    &mut out,
                )
            };
            if ok == 0 {
                return Err("DPAPI a échoué".into());
            }
            let bytes = std::slice::from_raw_parts(out.pbData, out.cbData as usize).to_vec();
            std::ptr::write_bytes(out.pbData, 0, out.cbData as usize);
            LocalFree(out.pbData as _);
            Ok(bytes)
        }
    }

    pub fn protect(data: &[u8]) -> Result<Vec<u8>, String> {
        call(data, true)
    }

    pub fn unprotect(data: &[u8]) -> Result<Vec<u8>, String> {
        call(data, false)
    }
}

#[cfg(not(windows))]
mod dpapi {
    pub fn protect(data: &[u8]) -> Result<Vec<u8>, String> {
        Ok(data.to_vec())
    }

    pub fn unprotect(data: &[u8]) -> Result<Vec<u8>, String> {
        Ok(data.to_vec())
    }
}
