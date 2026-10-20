# bnb_chain_tss

Three programs for 2-of-3 ECDSA MPC wallet operations using the pinned purplecity fork of BNB Chain `tss-lib` v4:

- `task1-keygen`: offline import of an existing secp256k1 private key into three `keygen.LocalPartySaveData` files.
- `task2-sign`: three signer nodes plus an API gateway, using long-lived gRPC streams and threshold signing. gRPC and the API run without certificates by default; TLS is optional.
- `task3-address`: derive EVM and TRON addresses from public wallet metadata using the non-hardened path `m/site_id/index`.

**This is a research implementation and is not production-ready.** Task 1 uses tss-lib Feldman VSS with the supplied scalar and assembles its ECDSA signing save data after generating each signer's Paillier/safe-prime pre-parameters offline. The full private key and all three shares exist in the offline process. Share JSON contains sensitive TSS private parameters. Read [security notes](docs/SECURITY.zh-CN.md) before handling real funds.

The tss-lib dependency is pinned to fork commit `f204718ae5950ac8bf9e1a8c1a5a3f0261121bf6`. Run `go test -short ./...` for fast tests and `go test ./...` for the real DKG and signing integration. See [usage](docs/USAGE.md), [中文使用文档](docs/USAGE.zh-CN.md), [architecture](docs/ARCHITECTURE.md), and [testing](docs/TESTING.md).
