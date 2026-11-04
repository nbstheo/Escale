//! Client OpenVPN propre à Escale (canal de contrôle TLS, canal de données, options poussées),
//! branché sur la pile TCP/IP en mémoire de `vpn` : comme WireGuard, il ne touche pas au reste du PC.

pub mod config;
// Couches du protocole : une partie de leur API ne sert qu'au serveur de test et aux tests.
#[allow(dead_code)]
pub mod control;
#[allow(dead_code)]
pub mod data;
pub mod link;
#[allow(dead_code)]
pub mod packet;
#[allow(dead_code)]
pub mod reliable;
#[cfg(test)]
pub(crate) mod test_server;

use crate::model::VpnProfile;

/// Vérifie un profil OpenVPN avant de l'enregistrer : tout ce que la connexion exigera
/// (autorité acceptée par webpki, paire certificat / clé utilisable, enveloppe, chiffrements).
pub fn check(p: &VpnProfile) -> Result<(), String> {
    control::ClientSetup::new(&p.openvpn, &p.username, &p.password).map(|_| ())
}
