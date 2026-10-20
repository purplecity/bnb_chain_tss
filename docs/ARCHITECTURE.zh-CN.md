# 架构说明

`task1-keygen` 只在离线环境运行。它先并行调用 tss-lib 的预参数生成器，为三个 signer 生成 Paillier 和 safe-prime 参数；这一步会耗时。参数就绪后，调用 tss-lib `vss.Create`，直接以输入私钥标量为 Shamir 多项式常数项生成阈值为 1 的 Feldman VSS 分片与承诺，再组装签名需要的 `keygen.LocalPartySaveData` 字段。分别写给三节点，并输出根公钥、随机链码和 party roster 元数据。

`task2-sign` 包含 signer 节点和 gateway。节点之间建立长连接 gRPC 双向流，gateway 到每个 signer 建立长连接控制流。默认使用明文连接，也支持可选的 TLS 1.3、双向证书验证和 SHA-256 证书 pin；明文模式没有传输加密和对端认证，只能用于隔离的私有网络。tss-lib protobuf 消息作为二进制 payload 传输。控制签名分两阶段：三节点先准备会话，再启动 signing，避免部分节点提前开始。

网关默认提供 HTTP 异步 API，也可选 HTTPS。入口创建随机 request/session ID 和 nonce，按钱包进入 FIFO worker；全局 semaphore 控制最多五个签名任务。节点按钱包互斥，同一钱包不会并行签名，不同钱包可并发。节点校验会话元数据和 peer roster，节点及网关分别验证签名；网关要求三节点返回结果一致。

`task3-address` 仅使用根压缩公钥与链码，按 `m/site_id/index` 做两步 secp256k1 非硬化派生，再生成 EVM 地址和使用 `0x41` 网络字节、Base58Check 编码的 TRON 地址。child tweak 通过 tss-lib 的 `NewLocalPartyWithKDD` 用于门限签名。

```text
node-1/<wallet_id>/share.json  # 只部署给 node-1
node-1/<wallet_id>/wallet.json # 公共元数据
node-2/<wallet_id>/share.json
node-3/<wallet_id>/share.json
gateway-wallet-meta/<wallet_id>/wallet.json
```

份额 JSON 含本地 Xi、Paillier 私钥等敏感数据；wallet.json 是公开派生信息。项目没有链交易解析/白名单/限额、审批工作流、持久化队列、请求幂等层、钱包生命周期协调器、自动重分片或灾难恢复编排。生产部署还需独立建设这些控制面、监控、审计、备份恢复和密钥生命周期管理。
