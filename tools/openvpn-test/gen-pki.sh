#!/bin/sh
# Génère une PKI minimale : CA, cert serveur (serverAuth), cert client (clientAuth),
# clé tls-auth et clé tls-crypt (même format "OpenVPN Static key V1", 2048 bits).
set -eu
D="$1"; mkdir -p "$D"; cd "$D"
cat > ext.cnf <<'X'
[srv]
basicConstraints=CA:FALSE
keyUsage=digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid
[cli]
basicConstraints=CA:FALSE
keyUsage=digitalSignature
extendedKeyUsage=clientAuth
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid
[ca]
basicConstraints=critical,CA:TRUE
keyUsage=critical,keyCertSign,cRLSign
subjectKeyIdentifier=hash
X
openssl req -x509 -newkey rsa:2048 -nodes -days 3650 -sha256 -subj "/CN=Escale Test CA" -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign" -keyout ca.key -out ca.crt
for n in server client; do
  openssl req -newkey rsa:2048 -nodes -subj "/CN=$n" -keyout $n.key -out $n.csr
  [ $n = server ] && e=srv || e=cli
  openssl x509 -req -in $n.csr -CA ca.crt -CAkey ca.key -CAcreateserial -days 3650 \
    -sha256 -extfile ext.cnf -extensions $e -out $n.crt
done
openvpn --genkey secret ta.key
openvpn --genkey secret tc.key
rm -f *.csr
