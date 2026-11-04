#!/bin/sh
# Produit un profil client autonome (blocs inline) pour le profil donné.
# REMOTE (défaut 127.0.0.1) permet de viser un autre hôte (ex : conteneur serveur).
set -eu
P="$1"; R="${REMOTE:-127.0.0.1}"; K=/etc/openvpn/pki
case "$P" in
  A) cat <<X
# Escale test A : UDP, tls-crypt, AES-256-GCM, certificat seul
client
dev tun
proto udp
remote $R 11194
nobind
remote-cert-tls server
data-ciphers AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305
verb 3
X
  echo "<tls-crypt>"; cat $K/tc.key; echo "</tls-crypt>" ;;
  B|C) [ "$P" = B ] && port=11443 || port=11444
  cat <<X
# Escale test $P : TCP, type WatchGuard SSL VPN (tls-auth SHA256, comp-lzo, user/pass)
# Identifiants : test / secret
client
dev tun
proto tcp-client
remote $R $port
nobind
remote-cert-tls server
auth SHA256
cipher AES-256-CBC
data-ciphers AES-256-GCM:AES-256-CBC
comp-lzo
auth-user-pass
key-direction 1
verb 3
X
  echo "<tls-auth>"; cat $K/ta.key; echo "</tls-auth>" ;;
  *) echo "profil inconnu: $P" >&2; exit 1 ;;
esac
echo "<ca>"; cat $K/ca.crt; echo "</ca>"
echo "<cert>"; openssl x509 -in $K/client.crt; echo "</cert>"
echo "<key>"; cat $K/client.key; echo "</key>"
