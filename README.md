# 2-of-3 MPC signer foundation

This repository implements a Go signer service foundation around BNB `tss-lib` v2.0.2. It has real distributed 3-party DKG and 2-of-3 signing sessions, mutually authenticated HTTPS peer transport, signer-side EVM and TRON transaction validation packages, quorum approval verification, encrypted full-share persistence, AWS KMS key wrapping, durable attempt journaling, epoch activation controls, and 2-of-3 committee resharing.

The signer API is an embeddable Go HTTP handler in `internal/signer`, with a coordinator client library in `internal/coordinator`; this repository does not yet include a production daemon binary, cloud account provisioning, or a production RPC-backed policy/nonce service. The local `cmd/tss-demo` is only an in-process development demo. Do not use this repository as-is to custody real funds until the deployment gaps in [Production checklist](docs/USAGE.md#production-deployment) are closed and an independent security review is complete.

Start with [usage](docs/USAGE.md), [architecture and threat boundaries](docs/ARCHITECTURE.md), and [tests](docs/TESTING.md).

中文文档：[项目说明](README.zh-CN.md)、[使用指南](docs/USAGE.zh-CN.md)、[架构与安全边界](docs/ARCHITECTURE.zh-CN.md)、[测试说明](docs/TESTING.zh-CN.md)、[注意事项与未完成项](docs/注意事项与未完成项.zh-CN.md)、[多站点充值地址设计](docs/多站点多用户充值地址设计.zh-CN.md)。
