# Security notes

This repository is a testable prototype, not an independently audited custody system. Task 1 calls tss-lib `vss.Create` with the supplied scalar, then combines its Feldman VSS result with tss-lib-generated Paillier/safe-prime pre-parameters to construct `LocalPartySaveData`. The full key and all three shares are present in the offline process. This local save-data assembly has not received an independent cryptographic audit and does not represent a distributed online keygen ceremony.

Each `share.json` contains the local signing share and sensitive Paillier material. File mode 0600 is only a baseline; isolate each share, its backups, host, cloud account and operator trust domain. A resharing operation may replace shares but keeps the root public key, so it cannot invalidate copied old shares. If the root key may be compromised, create a new wallet and migrate assets.

The gateway signs arbitrary 32-byte digests. API authentication is not transaction approval. Put transaction decoding, chain/destination/amount/nonce/fee policy, approvals, limits, audit and durable idempotency in a trusted control plane. Jobs are in memory and are lost at restart. Public root-key and chain-code metadata lets anyone enumerate the non-hardened address path; it does not reveal the private key.

Signer gRPC and the gateway API default to plaintext because certificates are optional. Plaintext connections provide neither confidentiality nor peer authentication; keep every endpoint on an isolated private network with strict firewall rules. Use the optional mutual-TLS and certificate-pin configuration when traffic crosses a network boundary. The API key authenticates gateway callers only; it does not protect signer-to-signer traffic.

Audit and pin the exact tss-lib commit, test node failure and recovery, and review the complete deployment threat model before using real funds.
