# bnb_chain_tss

本仓库包含三个基于 BNB Chain `tss-lib` v4 fork 的 ECDSA MPC 程序：

- `task1-keygen`：离线导入已有 secp256k1 私钥，生成三份 `keygen.LocalPartySaveData`。
- `task2-sign`：三个签名节点和一个签名网关，通过长连接 gRPC 执行门限签名。默认不要求连接证书，也可选配 TLS。
- `task3-address`：只凭公开钱包元数据，按非硬化路径 `m/site_id/index` 派生 EVM 与 TRON 地址。

**当前实现用于研究和测试，不能直接视为生产就绪系统。** 任务 1 使用 tss-lib Feldman VSS 直接对输入标量分片，并在离线生成各 signer 的 Paillier/safe-prime 预参数后组装 ECDSA 签名所需的保存数据。完整私钥和三份 share 会在离线进程内同时存在。分片 JSON 含敏感 TSS 私有参数。处理真实资金前请先阅读[安全说明](docs/SECURITY.zh-CN.md)。

`go.mod` 固定使用 tss-lib fork 提交 `f204718ae5950ac8bf9e1a8c1a5a3f0261121bf6`。测试命令及操作步骤见[中文使用文档](docs/USAGE.zh-CN.md)、[架构说明](docs/ARCHITECTURE.zh-CN.md)和[测试说明](docs/TESTING.zh-CN.md)。
