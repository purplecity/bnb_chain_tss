# Testing

Run the full suite and static checks with:

```sh
go test ./...
go vet ./...
```

The suite currently covers:

- AES-GCM share envelope identity binding, tampering, complete save-data round trip, separate online/recovery wraps, AWS KMS encryption-context binding, and immutable file writes.
- Exact policy/approval proof binding, invalid/duplicate approvers, chain and epoch mismatches, and expiry checks.
- Canonical EVM legacy/EIP-1559 transaction decoding, nonce/network/fee/destination/calldata policy, signature attachment, and recovered EOA address.
- Canonical TRON protobuf decoding, transfer and contract-call gates, owner/recipient/fee/time/reference-block checks, signature byte encoding, and recovered TRON address.
- Session-bound transport replay/equivocation rejection and an actual TLS 1.3 mutual-TLS HTTPS mesh with peer server certificate pins.
- Durable job transitions, stale-version conflicts, request uniqueness, interrupted-session handling after restart, idempotent epoch commits, and rollback rejection.
- Real tss-lib DKG and all three 2-of-3 signing pairs, distributed DKG/signing across separate party runners, and a two-old-to-three-new resharing migration that preserves the public key and signs with every new pair.
- Signer control API certificate pinning and strict request JSON parsing.

The tss-lib protocol tests are CPU intensive and may take tens of seconds or longer on a laptop because safe Paillier parameters are generated. Use `go test -short ./...` to skip the longer cryptographic integration cases while iterating on unrelated code.

The tests do not establish production readiness. Still needed are multi-process signer tests over real HTTPS in one combined end-to-end flow, crash/fencing tests at cloud persistence boundaries, backup-role isolation drills, transaction RPC/nonce race tests, testnet submission/reorg scenarios, fuzzing of untrusted decoders, and independent cryptographic/security review.
