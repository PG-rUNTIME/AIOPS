---
id: RB-TLS-001
title: TLS certificate close to expiry
failure_types: [tls_certificate_expiry]
---
## Confirm
- `(probe_ssl_earliest_cert_expiry - time()) / 86400` from the blackbox exporter.
## Safe actions
1. Renew via the PKI/ACME process; deploy to all load balancer members.
2. Verify the chain with `openssl s_client -connect host:443 -servername host`.
