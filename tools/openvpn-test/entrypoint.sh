#!/bin/sh
# Usage : entrypoint.sh A|B|C        -> lance le serveur du profil + service echo TCP :7
#         entrypoint.sh export A|B|C -> écrit le .ovpn client sur stdout
#         entrypoint.sh client <fichier.ovpn> [args openvpn...] -> client de validation
set -eu
case "${1:-A}" in
  export) shift; exec /usr/local/bin/export-client.sh "$@" ;;
  client) shift; mkdir -p /dev/net; [ -c /dev/net/tun ] || mknod /dev/net/tun c 10 200
          exec openvpn --config "$@" ;;
  A|B|C)  P="$1" ;;
  *) exec "$@" ;;
esac
mkdir -p /dev/net; [ -c /dev/net/tun ] || mknod /dev/net/tun c 10 200
# Service echo : écoute sur toutes les adresses, donc joignable via l'IP tunnel du serveur
# (10.8.0.1 / 10.9.0.1 / 10.10.0.1 port 7). Seul le port VPN est publié par Docker.
socat TCP-LISTEN:7,reuseaddr,fork EXEC:cat &
exec openvpn --config /etc/openvpn/conf/server-$P.conf
