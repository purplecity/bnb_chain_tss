# 测试说明

```sh
go test -short ./...   # 快速单元测试
go test ./...          # 包含真实 tss-lib DKG 和门限签名
```

任务 1 集成测试运行三个 tss-lib v4 keygen party，检查任意两份分片均恢复输入标量、save data JSON 往返、输出权限与覆盖保护，并用派生 child key 执行真实门限签名、验证 ECDSA 签名。

任务 2 通过无证书的三节点 gRPC 网络，让两个由 BIP-39 助记词派生的钱包同时签名并独立验证 ECDSA 结果；同时测试 gRPC 双向流编解码、二进制 payload、帧大小边界和可选 TLS 配置。任务 3 测试地址派生确定性、索引隔离、输入校验及私钥标量解析。全量测试可能较慢。
