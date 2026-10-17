# 测试说明

运行完整测试和静态检查：

```sh
go test ./...
go vet ./...
```

当前测试覆盖：

- AES-GCM 分片 envelope 的身份绑定和篡改检测、完整 save data 往返、在线/恢复双封装、AWS KMS encryption context 绑定，以及不可变文件写入。
- 精确策略/审批证明绑定、无效或重复审批人、链和 epoch 不匹配、过期检查。
- 规范 EVM legacy/EIP-1559 交易解析、nonce/网络/手续费/收款地址/calldata 策略、签名附加和 EOA 地址恢复。
- 规范 TRON protobuf 解析、转账和合约调用门禁、owner/收款方/手续费/时间/reference-block 检查、签名字节编码和 TRON 地址恢复。
- 会话绑定传输的重放/等价冲突拒绝，以及真实 TLS 1.3 双向认证 HTTPS mesh 和 peer 服务器证书 pin。
- 持久化 job 状态转换、过期版本冲突、request 唯一性、重启后中断会话处理、epoch 提交幂等和回滚拒绝。
- 真实 tss-lib DKG 和全部三种 2-of-3 签名组合、独立 party runner 上的分布式 DKG/签名，以及保持公钥并用每种新委员会组合签名的“两旧方到三新方”resharing 迁移。
- signer 控制 API 证书 pin 和严格 JSON 请求解析。

tss-lib 协议测试会生成安全 Paillier 参数，CPU 开销较大；在笔记本上可能耗时数十秒或更长。修改非密码学集成代码时，可先用 `go test -short ./...` 跳过耗时较长的密码学集成用例。

测试通过并不等于生产就绪。仍需增加：真实 HTTPS 上多进程 signer 的完整端到端测试、云持久化边界的崩溃/fencing 测试、备份角色隔离演练、交易 RPC/nonce 竞争测试、测试网提交及 reorg 场景、非可信解码器 fuzz 测试，以及独立密码学/安全审查。
