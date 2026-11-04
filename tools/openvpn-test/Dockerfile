# Serveur OpenVPN de test pour Escale (interop du client OpenVPN userspace).
# PKI générée au build (openssl) : stable tant que la couche n'est pas invalidée.
FROM alpine:3.20

RUN apk add --no-cache openvpn openssl socat bash iproute2

WORKDIR /etc/openvpn
COPY conf/ /etc/openvpn/conf/
COPY gen-pki.sh entrypoint.sh export-client.sh /usr/local/bin/
RUN sed -i 's/\r$//' /usr/local/bin/*.sh /etc/openvpn/conf/* \
 && chmod +x /usr/local/bin/*.sh /etc/openvpn/conf/verify.sh \
 && /usr/local/bin/gen-pki.sh /etc/openvpn/pki

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
CMD ["A"]

# Ajouté après la PKI pour ne pas la régénérer quand ce script change.
COPY validate-client.sh /usr/local/bin/
RUN sed -i 's/\r$//' /usr/local/bin/validate-client.sh && chmod +x /usr/local/bin/validate-client.sh
