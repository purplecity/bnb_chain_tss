# 2-of-3 MPC 签名服务基础实现

本仓库基于 BNB `tss-lib` v2.0.2 实现 Go 签名服务基础框架，包含真实的三方分布式 DKG 和 2-of-3 签名会话、相互认证的 HTTPS 节点传输、签名节点侧 EVM/TRON 交易校验、审批门限验证、加密的完整分片持久化、AWS KMS 密钥封装、持久化尝试日志、epoch 激活控制，以及 2-of-3 委员会重分片。

签名服务是 `internal/signer` 中可嵌入的 Go HTTP handler；协调器客户端位于 `internal/coordinator`。当前没有生产级守护进程、云账户配置或生产 RPC 策略/nonce 服务。`cmd/tss-demo` 仅用于单进程开发演示。关闭 [生产部署检查项](docs/USAGE.zh-CN.md#生产部署检查项) 并完成独立安全审计前，不要用本仓库直接托管真实资金。

建议按顺序阅读：[使用指南](docs/USAGE.zh-CN.md)、[架构与安全边界](docs/ARCHITECTURE.zh-CN.md)、[测试说明](docs/TESTING.zh-CN.md)、[注意事项与未完成项](docs/注意事项与未完成项.zh-CN.md)，以及 [多站点多用户充值地址设计](docs/多站点多用户充值地址设计.zh-CN.md)。英文文档：[README](README.md)、[Usage](docs/USAGE.md)、[Architecture](docs/ARCHITECTURE.md)、[Testing](docs/TESTING.md)。
