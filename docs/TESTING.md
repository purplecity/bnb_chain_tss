# Testing

Run `go test -short ./...` for fast unit tests and `go test ./...` for the full suite.

The task 1 integration test runs three real tss-lib v4 keygen parties, verifies every two-share combination reconstructs the imported scalar, round-trips save data through JSON, checks file permissions and overwrite protection, then performs and verifies threshold signing for a derived child key. Task 2 tests certificate-free three-node gRPC signing with two simultaneous BIP-39-derived wallets, independent ECDSA verification, gRPC bidirectional frame encoding, binary payload preservation, size limits and optional TLS configuration. Task 3 tests deterministic address derivation, distinct indices, invalid metadata and scalar parsing.
