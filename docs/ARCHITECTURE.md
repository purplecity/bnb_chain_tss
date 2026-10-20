# Architecture

`task1-keygen` first generates each signer's Paillier and safe-prime pre-parameters using the tss-lib generator. Once ready, it calls tss-lib `vss.Create` with the imported scalar as the Shamir polynomial constant and threshold 1, then assembles the signing fields in `keygen.LocalPartySaveData`. It writes one save JSON per signer plus public root-key, chain-code and roster metadata.

`task2-sign` consists of three signer nodes and a gateway. Signers maintain long-lived bidirectional gRPC streams with peers; the gateway maintains a control stream to each signer. Connections use plaintext by default and support optional TLS 1.3, mutual certificate verification and SHA-256 certificate pins. Plaintext mode has no transport encryption or peer authentication and must stay on an isolated private network. TSS protobuf messages travel as binary payloads. Signing has PREPARE and START phases so all parties are subscribed before tss-lib begins.

The gateway exposes an asynchronous HTTP API by default, with optional HTTPS. Jobs enter per-wallet FIFO workers; a global semaphore limits active signing jobs to five. Each node serializes work for a wallet and allows distinct wallets to run concurrently. Nodes validate session metadata and verify signatures; the gateway checks all three results agree and verifies against the derived child key.

`task3-address` derives non-hardened secp256k1 children with `m/site_id/index` from public root-key and chain-code metadata. It creates EVM addresses and TRON Base58Check addresses using network prefix `0x41`. Signing applies the child tweak through tss-lib's `NewLocalPartyWithKDD`.

Share JSON contains private Xi and Paillier parameters; `wallet.json` contains public derivation metadata. The project does not implement transaction-policy enforcement, approvals, durable jobs, idempotency, wallet lifecycle coordination, automated resharing or disaster recovery. The caller must validate transaction intent and authorization before passing a digest for signing.
