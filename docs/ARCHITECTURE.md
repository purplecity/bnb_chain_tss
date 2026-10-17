# Architecture and security boundaries

## Components

- `internal/tssadapter` contains the only application integration with BNB `tss-lib` v2.0.2. A 3-party committee with 2 required signers maps to BNB `threshold=1`. It supports in-process test helpers, a distributed per-party DKG/signing runner, and in-process committee resharing.
- `internal/transport` carries session-bound protocol frames over HTTPS/mTLS. It maps authenticated peer certificates to party IDs, pins outbound server certificates, checks session/attempt/key/epoch/recipient metadata, rejects replay and equivocation, and fails closed unless all committee members echo an identical broadcast.
- `internal/signer` is a one-party HTTP handler. It journals an attempt before starting protocol messages, persists its own encrypted share after DKG, requires a local chain/policy validator before signing, and returns signature data without reconstructing a private key.
- `internal/coordinator` is a mTLS client library that fans DKG/signing requests to independent signer handlers, verifies the three DKG public-key/address reports match, constructs the activation manifest, and aggregates matching threshold-signature results.
- `internal/chain/{evm,tron}` decode canonical unsigned transactions, enforce configured constraints, compute chain digests, and encode/check the resulting signatures. `internal/chain/prepare` binds these decoded values to the approved intent. TRON requires a trusted reference-block verifier.
- `internal/policy` validates approval quorum proofs that bind the request, key, epoch, network, expiry, and SHA-256 of the exact unsigned transaction.
- `internal/sharestore` encrypts complete tss-lib save data, supports separate online/recovery data-key wraps, includes an AWS KMS adapter, and provides a development-only immutable local file store.
- `internal/workflow` persists attempt and epoch state in a local bbolt journal. On process restart, an in-flight protocol attempt becomes `INTERRUPTED`; a fresh party object and attempt ID are required.

## Protocol and key lifecycle

Every signer participates independently. DKG must persist all three local shares before the coordinator compares the same public key and derived addresses. Epoch activation is irreversible: the local epoch floor is written before the job becomes `ACTIVE`, and only the exact committed manifest can be retried. Signing is limited to two selected members and each signer validates the entire transaction and approval proof before it starts tss-lib.

The local two-old-to-three-new resharing helper preserves the public key and verifies that the new committee can sign. This is committee migration, not key rotation. Copied old shares remain valid for the same public key. Suspected threshold compromise requires fresh DKG and an asset/authorization migration to the new address.

## Threat boundaries and limits

- One 2-of-3 share is below threshold under tss-lib's cryptographic assumptions. Two shares from the same generation can sign.
- mTLS protects peer transport and identifies configured certificates; it does not protect a compromised signer host, operator account, deployment pipeline, CA, or two signer domains.
- The reliable-broadcast layer intentionally aborts on disagreement and requires all members to echo. It prioritizes consistency over availability; a network partition or unavailable member stops the session.
- AEAD at rest does not protect a running signer. Go big integers, serialization, garbage collection, and copies mean the application cannot promise complete secret erasure.
- The daemon currently calls online and recovery wrappers in the same process during DKG. Separate wrapper references are enforced, but process/account isolation for recovery still requires a backup service and IAM controls.
- Activation checks the canonical manifest, committee membership list, and local public key. The ready list is supplied by the coordinator; production needs signed READY attestations and signed backup receipts from every signer.
- Local bbolt and local files are not shared production coordination/storage. A cloud deployment needs atomic request fencing, immutable versioned backups, recovery authorization, and reconciliation of partially completed transitions.
- Chain validation primitives exist, but production RPC clients, atomic EVM nonce reservation, TRON full-node reference-block verification, coordinator, and transaction broadcast service are deployment integrations still required.

This code is a reviewable security foundation, not a claim of production readiness. Perform independent implementation and cryptographic review before holding funds.
