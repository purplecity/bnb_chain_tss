# 架构与安全边界

## 组件

- `internal/tssadapter` 是应用与 BNB `tss-lib` v2.0.2 集成的唯一入口。三方委员会、两方签名门限对应 BNB 的 `threshold=1`。它包含进程内测试辅助代码、分布式单方 DKG/签名 runner 和进程内委员会重分片。
- `internal/transport` 通过 HTTPS/mTLS 传递绑定会话的协议帧。它将已认证 peer 证书映射到 party ID，固定出站服务器证书，检查 session/attempt/key/epoch/recipient 元数据，拒绝重放和等价冲突，并要求全体委员会成员对同一广播回显，否则失败关闭。
- `internal/signer` 是单方 HTTP handler。它会在启动协议消息前记录 attempt，DKG 后持久化本方加密分片，签名前要求本地链/策略 validator，并返回签名数据，不会重建私钥。
- `internal/coordinator` 是 mTLS 客户端库，将 DKG/签名请求发送给独立 signer handler，检查三方 DKG 公钥/地址一致，构造激活 manifest，并汇总匹配的门限签名结果。
- `internal/chain/{evm,tron}` 解析规范化的未签名交易，检查配置约束，计算链上摘要，并编码/校验生成的签名。TRON 需要可信 reference-block verifier。
- `internal/policy` 校验审批门限证明；证明绑定 request、key、epoch、网络、过期时间和精确未签名交易的 SHA-256。
- `internal/sharestore` 加密完整 tss-lib save data，支持独立的在线/恢复数据密钥封装，包含 AWS KMS adapter，并提供仅供开发使用的不可变本地文件存储。
- `internal/workflow` 将 attempt 和 epoch 状态写入本地 bbolt journal。进程重启后，进行中的协议 attempt 会成为 `INTERRUPTED`；需要创建新的 party 对象和 attempt ID。

## 协议和密钥生命周期

每个 signer 独立参与协议。DKG 需要先在三方保存各自分片，再由协调器比较相同公钥和派生地址。epoch 激活不可逆：本地 epoch 下限先持久化，然后 job 才变为 `ACTIVE`，且仅允许对完全相同的 manifest 重试。签名仅限选定的两个成员；每个 signer 在启动 tss-lib 之前都会独立验证完整交易和审批证明。

进程内“两旧方到三新方”的 resharing helper 保留公钥，并验证新委员会能够签名。这是委员会迁移，不是密钥轮换；复制出去的旧分片仍对原公钥有效。若怀疑达到门限的密钥材料泄露，必须重新 DKG，并将资产/授权迁移到新地址。

## 威胁边界与限制

- 在 tss-lib 密码学假设成立时，一个 2-of-3 分片低于签名门限。同一代的两个分片即可签名。
- mTLS 保护 peer 传输并识别配置的证书；无法防护已失陷的 signer 主机、运维账户、部署流水线、CA 或两个 signer 安全域。
- 可靠广播层在成员意见不一致时主动中止，并要求全体成员回显，因此优先保证一致性而非可用性；网络分区或任一成员不可用会停止会话。
- 静态 AEAD 加密无法保护正在运行的 signer。Go 大整数、序列化、垃圾回收和内存拷贝意味着应用无法保证秘密被彻底擦除。
- 当前 daemon 在 DKG 时于同一进程调用在线和恢复 wrapper。虽然会检查 wrapper 引用不同，但恢复服务仍需独立进程/账户、备份服务和 IAM 控制。
- 激活流程检查规范 manifest、委员会成员列表和本地公钥。ready 列表由协调器提供；生产部署要收集每个 signer 签发的 READY 证明和备份回执。
- 本地 bbolt 和本地文件不能作为分布式生产协调/存储。云部署需要原子请求 fencing、不可变版本化备份、恢复授权，以及对未完成状态迁移的协调修复。
- 已提供链交易校验基础组件，但生产 RPC 客户端、原子 EVM nonce 预留、TRON 全节点 reference-block 校验、协调器和交易广播服务仍需集成。

本项目是便于评审的安全基础实现，不代表已达到生产可用状态。托管资金之前应完成独立实现审查和密码学审查。
