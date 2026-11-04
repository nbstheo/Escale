#!/bin/sh
# Client de validation : lit un .ovpn sur stdin, remplace "remote 127.0.0.1" par l'hôte
# serveur du réseau Docker, monte le tunnel puis vérifie l'echo TCP via l'IP tunnel.
# Usage : validate-client.sh <hote_serveur> <ip_echo> [user] [pass]
set -u
H="$1"; IP="$2"
mkdir -p /dev/net; [ -c /dev/net/tun ] || mknod /dev/net/tun c 10 200
sed "s/^remote 127\.0\.0\.1 /remote $H /" > /tmp/c.ovpn
EXTRA=""
if [ $# -ge 4 ]; then printf '%s\n%s\n' "$3" "$4" > /tmp/up; EXTRA="--auth-user-pass /tmp/up"; fi
openvpn --config /tmp/c.ovpn $EXTRA --log /tmp/log --daemon
i=0
until grep -q "Initialization Sequence Completed" /tmp/log; do
  i=$((i+1)); if [ $i -gt 40 ] || grep -q "AUTH_FAILED\|Exiting" /tmp/log; then cat /tmp/log; echo "ECHEC: tunnel non établi"; exit 1; fi
  sleep 0.5
done
grep -E "PUSH: Received|Data Channel:|Outgoing Data Channel|Incoming Data Channel|Control Channel:|OpenVPN 2" /tmp/log
M="escale-echo-$(date +%s)"
R=$(printf '%s\n' "$M" | socat -t2 - TCP:$IP:7,connect-timeout=5)
if [ "$R" = "$M" ]; then echo "OK: echo via $IP:7 -> '$R'"; exit 0; fi
cat /tmp/log; echo "ECHEC: echo '$R' != '$M'"; exit 1
