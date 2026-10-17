# Usage

## Prerequisites and checks

- Go 1.25 or newer (required by the pinned dependency set).
- Network access for the first dependency download.

Run the full suite:

```sh
go test ./...
go vet ./...
```

Run the local-only demo:

```sh
go run ./cmd/tss-demo
```

The demo generates a fresh test key in one process, exercises signing, and prints public test output. It does not persist shares or contact a chain. The cryptographic integration tests take longer than unit tests because tss-lib creates Paillier parameters:

```sh
go test ./internal/tssadapter -run 'TestDKGAndAllTwoOfThreeSigningPairs|TestDistributedParties|TestReshareChangesCommittee' -count=1 -v
```

## Signer service integration

`internal/signer.Daemon` implements `http.Handler` for one signer process. Construct one instance per independent signer account/security domain. Each instance requires:

- Stable committee party IDs and tss-lib identity integers (`Participant.UniqueKey`). Keep those identities bound to the signer certificates and security-domain inventory.
- A `transport.HTTPSMesh` using an mTLS client certificate, trusted CA roots, an HTTPS URL and pinned server-certificate SHA-256 fingerprint for every peer.
- A `transport.HTTPReceiver` with the local server certificate, the client CA, and the SHA-256 fingerprints of the three committee client certificates. Use `receiver.TLSConfig()` on the HTTPS server. Pin the control-plane client certificate separately in `Config.ControlCertificateIDs`.
- A `sharestore.ShareStore`, `workflow.Journal`, and separate online and recovery `sharestore.KeyWrapper` implementations. The repository supplies an immutable local file store and an AWS KMS wrapper. The file store is for development and recovery drills.
- An `IntentValidator` implementation. It must decode the supplied raw transaction, verify the chain/network and all policy rules locally, validate the approval quorum, and return the exact 32-byte chain digest. The chain packages in `internal/chain/prepare`, `internal/chain/evm`, and `internal/chain/tron` provide the validation primitives. A missing validator disables signing.

The daemon's HTTPS API is protected by mutual TLS and a pinned control-certificate fingerprint:

| Method and path | Purpose |
| --- | --- |
| `GET /v1/control/health` | Check the signer process. |
| `POST /v1/control/dkg/start` | Start this signer's DKG participant. Returns `202` and a job ID. |
| `GET /v1/control/jobs/{job_id}` | Poll DKG/signing state and result. |
| `POST /v1/control/keys/{key_id}/activate` | Commit an epoch after the coordinator has polled every signer and verified a matching public key and share backup. |
| `POST /v1/control/sign/start` | Independently validate a transaction and start the local party of a selected 2-member signing session. |
| `POST /v1/control/jobs/{job_id}/broadcast` | Record the chain transaction ID after the coordinator broadcasts the signed transaction. |
| `POST /v1/control/jobs/{job_id}/complete` | Record the matching transaction ID, block number, and receipt after the coordinator verifies chain confirmation. |
| `POST /v1/tss/message` | Peer protocol endpoint. It is authenticated with mTLS and peer certificate pins. |

`internal/coordinator.Client` provides the coordinator-side mTLS client. It starts DKG on all three signers, polls each share record to `READY`, compares public keys/addresses, commits the canonical activation manifest on all signers, and coordinates the two selected signing sessions. The caller supplies HTTPS endpoints, the control client certificate, trusted roots, and the pinned server fingerprints:

```go
control, err := coordinator.New(coordinator.Config{
    Signers: []coordinator.Endpoint{
        {ID: "signer-a", URL: "https://signer-a.example", ServerFingerprint: "<64 hex chars>"},
        {ID: "signer-b", URL: "https://signer-b.example", ServerFingerprint: "<64 hex chars>"},
        {ID: "signer-c", URL: "https://signer-c.example", ServerFingerprint: "<64 hex chars>"},
    },
    ControlCertificate: cert,
    ServerRoots: roots,
})
if err != nil { return err }
key, err := control.CreateKey(ctx, coordinator.DKGRequest{
    JobID: "dkg-wallet-epoch-1", RequestID: "create-wallet-001",
    AttemptID: attemptID, SessionID: sessionID, KeyID: "treasury-hot-wallet", Epoch: 1,
})
```

The service is intentionally exposed as an embeddable handler and client library; operators choose and harden their HTTP server, configuration source, process supervisor, and chain-specific policy validator.

Example DKG start body (use globally unique random attempt/session IDs and a durable job ID):

```json
{
  "job_id": "dkg-wallet-epoch-1",
  "request_id": "create-wallet-001",
  "attempt_id": "random-128-bit-attempt-id",
  "session_id": "random-128-bit-session-id",
  "key_id": "treasury-hot-wallet",
  "epoch": 1
}
```

Call the DKG endpoint on all three signers with the same request, attempt, and session IDs. Poll each job until `READY`; compare their uncompressed secp256k1 public keys and derived EVM/TRON addresses. Each signer stores only its own complete `LocalPartySaveData`. After all three records and recovery wraps have been verified, construct the canonical activation manifest as JSON with fields in this order: `key_id`, `epoch`, `public_key_uncompressed`, `ready_parties`. `ready_parties` must be the sorted configured IDs. SHA-256 the exact JSON bytes and send the public key, ready party list, and hex hash to each signer's activation endpoint. Every signer checks its local public key, the committee list, and the manifest hash before irreversibly raising its epoch floor.

For signing, send the same exact intent, approval proof, selected two party IDs, and session metadata to each selected signer. The two signers independently run the configured `IntentValidator`; they never accept a caller-supplied digest. Poll both results and verify the returned signature against the active public key and original transaction digest before chain submission. Record the transaction ID on both signers after broadcast. Once a trusted chain observer verifies inclusion/confirmation, send the matching transaction ID, block number, and receipt to both signers. The signer stores this confirmation report; it does not independently query the chain.

The service library intentionally does not invent chain policy or nonce reservations. The calling deployment must provide a validator backed by trusted chain state: EVM nonce reservation must be atomic and current; TRON reference-block checking must use a trusted full node. Signing API consumers should treat `RequestID` as single-use and create a new attempt/session after any timeout or restart.

## Key storage and recovery

The encrypted record contains the full tss-lib save data, identity-bound AES-256-GCM ciphertext, and two envelopes of a random data-encryption key. The online and recovery `KeyWrapper`s must use different key references and bind `key_id`, `epoch`, `party_id`, and schema version as KMS encryption context. Never log plaintext shares or data keys.

`sharestore.AWSKMSWrapper` uses the AWS SDK default credential chain and calls KMS Encrypt/Decrypt with identity-bound context. Configure two distinct KMS keys with distinct IAM roles/accounts and separate recovery administration. The current daemon invokes both wrappers in the signer process while creating the record; a production deployment should move the recovery wrap to a separately operated backup service before granting any online signer access to the recovery role.

The local `sharestore.FileStore` creates immutable, mode-0600 records. Production storage needs a cloud backend with versioning/retention, independent account access, audited recovery, and a tested restore path. The journal is local bbolt; a distributed coordinator still needs a durable, fenced request/epoch registry and reconciliation of partial activation.

## Resharing and compromise response

`tssadapter.ReshareKeySet` demonstrates tss-lib resharing from two old shares to three new participants. It preserves the public key/address and includes a post-reshare 2-of-3 signing check. Use it for planned committee/domain migration when the old key remains trusted. Do not treat it as revocation: copied old shares may still form the old signing quorum. If compromise of two old shares or the complete key is suspected, run fresh DKG, verify the new address, and transfer funds and chain authorizations to it.

The distributed per-party runner currently exposes DKG and signing sessions. A distributed multi-domain resharing coordinator, signed all-party activation attestations, and automated new-address asset migration are not included yet.

## Production deployment

Before real assets are enabled, complete and review these items:

1. Build a coordinator that gathers three independently authenticated READY attestations and recovery-backup receipts before sending a signed activation manifest. The current signer checks the manifest's contents and its own DKG public key, while the readiness list itself is a coordinator assertion.
2. Deploy the signers in separate accounts/regions with distinct operators, hosts, identities, KMS policies, logs, network paths, and recovery control. Ensure no process can call both online and recovery KMS roles.
3. Implement a production immutable object store and a fenced, shared request/epoch registry. Exercise crash windows between each write and activation call.
4. Supply reviewed EVM nonce reservation and TRON full-node/reference-block validators for each network. Add chain-specific limits for contracts, tokens, fee behavior, and reorg handling.
5. Add monitoring and alerting for policy denials, failed/replayed sessions, KMS and backup outages, interrupted jobs, and unexpected signer combinations. Perform restore and key-migration drills.
6. Pin and audit dependency versions, run race/fuzz tests and independent cryptographic/security review, and test against chain testnets before production.

No AWS account IDs, certificates, KMS keys, IAM policies, RPC endpoints, or deployment credentials were available in this workspace, so this repo includes the AWS KMS adapter but cannot provision or validate those production controls.
