# Security policy

Escale stores SSH/RDP/VNC/VPN credentials, so vulnerability reports are taken seriously.

**Please do not open a public issue for a security problem.** Use GitHub's private
vulnerability reporting (Security tab → "Report a vulnerability") and include the version,
steps to reproduce and impact.

The vault design (Argon2id + XChaCha20-Poly1305, DPAPI-wrapped PIN, host-key TOFU) is described in the README.
The project has not had an independent security audit.
