# 使用指南

## 环境要求与检查

- Go 1.25 或更新版本（当前锁定的依赖要求）。
- 首次下载依赖时需要网络。

运行完整测试和静态检查：

```sh
go test ./...
go vet ./...
```

运行本地演示：

```sh
go run ./cmd/tss-demo
```

演示会在一个进程中生成全新的测试密钥并签名，只输出测试用公钥结果；它不保存分片，也不连接区块链。tss-lib 集成测试会生成 Paillier 参数，因此耗时比单元测试长：

```sh
go test ./internal/tssadapter -run 'TestDKGAndAllTwoOfThreeSigningPairs|TestDistributedParties|TestReshareChangesCommittee' -count=1 -v
```

## 接入签名服务

`internal/signer.Daemon` 为单个签名节点实现 `http.Handler`。每个独立签名账户/安全域应运行一个实例。每个实例需要配置：

- 稳定的委员会 party ID 和 tss-lib 身份整数 `Participant.UniqueKey`。应将这些身份绑定到节点证书和安全域清单。
- `transport.HTTPSMesh`：使用 mTLS 客户端证书、受信 CA 根、每个 peer 的 HTTPS 地址和固定的服务器证书 SHA-256 指纹。
- `transport.HTTPReceiver`：配置本地服务器证书、客户端 CA 和三个委员会客户端证书的 SHA-256 指纹。HTTPS 服务端应使用 `receiver.TLSConfig()`。控制面的客户端证书指纹应单独配置到 `Config.ControlCertificateIDs`。
- `sharestore.ShareStore`、`workflow.Journal`，以及相互独立的在线和恢复 `sharestore.KeyWrapper`。仓库提供不可变本地文件存储和 AWS KMS wrapper；文件存储仅适用于开发和恢复演练。
- `IntentValidator` 实现。它必须解析原始交易、验证链和网络及策略规则、校验审批门限，并返回精确的 32 字节链上摘要。`internal/chain/prepare`、`evm`、`tron` 提供校验基础组件。没有 validator 时签名会被禁用。

Daemon 的 HTTPS API 使用双向 TLS 和固定控制证书指纹认证：

| 方法和路径 | 用途 |
| --- | --- |
| `GET /v1/control/health` | 检查签名节点进程。 |
| `POST /v1/control/dkg/start` | 启动该节点的 DKG participant，返回 `202` 和 job ID。 |
| `GET /v1/control/jobs/{job_id}` | 查询 DKG/签名状态和结果。 |
| `POST /v1/control/keys/{key_id}/activate` | 协调器检查所有节点并核对公钥和备份后，提交 epoch。 |
| `POST /v1/control/sign/start` | 本地独立校验交易，并启动选定两方签名会话。 |
| `POST /v1/control/jobs/{job_id}/broadcast` | 协调器广播签名交易后，登记链上交易 ID。 |
| `POST /v1/control/jobs/{job_id}/complete` | 协调器验证链上确认后，登记交易 ID、区块号和回执。 |
| `POST /v1/tss/message` | tss-lib peer 协议端点，使用 mTLS 和 peer 证书 pin 认证。 |

`internal/coordinator.Client` 是协调端 mTLS 客户端。它会在三个签名节点启动 DKG，轮询到每个分片记录为 `READY`，比较公钥/地址，并在所有节点上提交规范化的激活 manifest；它也会协调选定的两个签名会话。调用方提供 HTTPS 地址、控制客户端证书、受信根和固定的服务器证书指纹：

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

本服务以可嵌入 handler 和客户端库形式提供；HTTP 服务、配置来源、进程守护和链策略 validator 需要由部署方选择并加固。

DKG 启动请求示例（attempt/session ID 应使用全局唯一随机值，job ID 应持久化）：

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

对三个签名节点发送完全相同的 request、attempt 和 session ID。轮询每个 job 直至 `READY`，比较未压缩 secp256k1 公钥以及派生的 EVM/TRON 地址。每个节点只保存自己的完整 `LocalPartySaveData`。确认三个分片记录和恢复密钥封装均已验证后，按以下字段顺序生成规范激活 manifest JSON：`key_id`、`epoch`、`public_key_uncompressed`、`ready_parties`。`ready_parties` 必须是排序后的配置 ID。对 JSON 原始字节计算 SHA-256，并把公钥、节点列表和十六进制摘要发送到每个节点的激活端点。每个节点会核对本地公钥、委员会列表和 manifest 摘要，然后不可逆地提高自己的 epoch 下限。

签名时，对选出的两个节点发送完全相同的 intent、审批证明、party ID 和会话元数据。两个节点分别运行配置好的 `IntentValidator`；节点不会接受调用方直接提供的 digest。轮询两个结果，并在提交上链前用活动公钥和原始交易摘要验证签名。广播后，在两个节点登记交易 ID。受信链观察器确认交易已纳入区块后，向两个节点发送相同的交易 ID、区块号和回执。节点保存该确认报告，但不会自行查询区块链。

本库不会自行定义链策略或 nonce 预留机制。调用方部署必须提供基于可信链状态的 validator：EVM nonce 预留应原子化并检查当前状态；TRON 的 reference block 检查应依赖可信全节点。签名 API 的调用方应将 `RequestID` 视为一次性标识；发生超时或重启后创建新的 attempt/session。

## 密钥存储与恢复

加密记录包含完整的 tss-lib save data、绑定身份的 AES-256-GCM 密文，以及随机数据加密密钥的两个 envelope。在线与恢复 `KeyWrapper` 应使用不同的 key reference，并在 KMS encryption context 中绑定 `key_id`、`epoch`、`party_id` 和 schema version。不得记录明文分片或数据密钥。

`sharestore.AWSKMSWrapper` 使用 AWS SDK 默认凭证链，并通过身份绑定的 context 调用 KMS Encrypt/Decrypt。应配置两把不同 KMS key，并采用不同 IAM role/account 和独立恢复管理。当前 daemon 在创建记录时会在同一进程调用两个 wrapper；生产环境应先把恢复 envelope 的封装移到独立运维的备份服务，再避免在线 signer 获得恢复 role。

本地 `sharestore.FileStore` 创建不可变、权限为 `0600` 的记录。生产存储应使用云端后端，具备版本控制/保留策略、独立账户访问、可审计恢复和经过测试的恢复流程。journal 当前使用本地 bbolt；分布式协调器仍需持久化、有 fencing 的请求/epoch 注册表，以及部分激活后的协调修复机制。

## 重分片与泄露响应

`tssadapter.ReshareKeySet` 演示 tss-lib 从两个旧分片重分片到三个新参与方。它保持公钥/地址不变，并包含重分片后的 2-of-3 签名检查。旧密钥仍可信时可用于计划内的委员会/安全域迁移。它不能撤销旧密钥：被复制的旧分片仍可能组成旧签名门限。如果怀疑两个旧分片或完整私钥已泄露，应执行全新 DKG、核验新地址，并将资金和链上授权迁移到新地址。

分布式 party runner 目前提供 DKG 和签名会话。分布式多安全域 resharing coordinator、所有节点签名的激活证明，以及自动向新地址迁移资产的功能尚未包含。

## 生产部署检查项

启用真实资产前，必须完成并评审以下事项：

1. 构建协调器，收集三个节点独立认证的 READY 证明和恢复备份回执后，再发送已签名的激活 manifest。当前 signer 会核对 manifest 内容和本地 DKG 公钥，但 ready 列表仍是协调器的声明。
2. 将 signer 部署到不同账户/区域，分配不同运维人员、主机、身份、KMS 策略、日志、网络路径和恢复控制。确保任何进程都不能同时调用在线和恢复 KMS role。
3. 实现生产级不可变对象存储和带 fencing 的共享请求/epoch 注册表。在每次写入和激活调用之间模拟崩溃窗口。
4. 为每个网络提供经过评审的 EVM nonce 预留和 TRON 全节点/reference-block validator；增加合约、代币、手续费行为和 reorg 处理策略。
5. 为策略拒绝、失败/重放会话、KMS/备份故障、中断任务和异常 signer 组合增加监控告警，并演练恢复和密钥迁移。
6. 固定并审计依赖版本，运行 race/fuzz 测试和独立密码学/安全评审，并在生产前对接测试网验证。

当前工作区没有 AWS 账户、证书、KMS key、IAM policy、RPC 地址或部署凭证，因此仓库虽然包含 AWS KMS adapter，仍无法配置或验证这些生产控制。
