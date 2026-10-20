# 使用指南

## 依赖和构建

Go 版本需满足 `go.mod` 中 tss-lib v4 fork 的要求。依赖固定在提交 `f204718ae5950ac8bf9e1a8c1a5a3f0261121bf6`。运行：

```sh
go test -short ./...
go test ./...
go build ./task1-keygen ./task2-sign/cmd/node ./task2-sign/cmd/gateway ./task3-address
```

全量测试会运行真实 DKG 和签名协议，可能需要数分钟。

## 1. 离线生成三份分片

在断网的可信机器准备权限为 `0600` 的文本文件，内容为 64 位十六进制私钥，不带 `0x`。工具先为三个 signer 生成 tss-lib Paillier 和 safe-prime 预参数，这一步会耗时；完成后调用 `vss.Create` 对输入私钥生成可验证分片并组装保存文件。不要把明文私钥放到在线节点或网关。

```sh
umask 077
./task1-keygen --private-key ./private_key.txt --wallet-id treasury-evm-01 --out-dir ./generated
```

输出为 `generated/node-{1,2,3}/treasury-evm-01/share.json` 及 `generated/public/treasury-evm-01/wallet.json`。将每个 share 单独送到对应节点，禁止把三份放在同一台在线机器。`wallet.json` 是公开元数据，可复制到网关和地址派生机。工具拒绝覆盖已有目录。

## 2. 地址派生

```sh
./task3-address --wallet-meta ./generated/public/treasury-evm-01/wallet.json --site-id 17 --index 29
```

路径为 `m/site_id/index`，两个值都必须小于 `2^31`，都是非硬化索引。将 `(wallet_id, site_id, index)` 与充值业务记录可靠绑定，避免重用索引。正式充值前建议以独立实现核验地址向量。

## 3. 签名服务

连接证书是可选的。未配置证书和指纹时，signer 之间的 gRPC、gateway 到 signer 的 gRPC，以及 gateway API 默认使用明文连接，因此只应放在隔离的私有网络中；这些连接没有传输加密和对端认证。若需要 TLS，为每个节点和 gateway 配置证书、私钥、CA，并填写相应 SHA-256 指纹。节点配置字段见 `task2-sign/config.go` 的 `NodeConfig`。节点目录只放本节点的 share 与公共 wallet 元数据。

启动三个节点：

```sh
./node --config /etc/bnb-tss/node.json
```

节点持续连接另外两个节点。网关配置三个节点 endpoint、`wallet_meta_dir`、强随机 `api_key`、`max_concurrent` 和 `queue_size`；启用 TLS 时再配置证书与指纹。默认全局并发上限为 5，队列容量为 1000；相同钱包任务 FIFO，不同钱包可并发。启动：

```sh
./gateway --config /etc/bnb-tss/gateway.json
```

请求示例：

```sh
curl -H 'X-API-Key: <secret>' -H 'Content-Type: application/json' \
  -d '{"wallet_id":"treasury-evm-01","site_id":17,"index":29,"digest":"<64 hex chars>"}' \
  http://gateway.internal:8080/v1/sign
```

返回 202 和 request ID，通过 `GET /v1/jobs/{request_id}` 轮询。digest 必须是 32 字节。返回签名是紧凑的 `r || s`，另含恢复 ID、`r`、`s`。调用方负责交易解析与检查、nonce、金额、收款人、链 ID、费用、审批、广播及确认；当前 signer 会签任意传入摘要，没有交易策略引擎。

## 运维边界

网关队列和状态保存在内存，重启会丢作业。上游需处理未知终态并按业务幂等重试。增加或删除钱包时先排空对应签名，再部署/移除三节点份额和网关元数据。若根私钥或完整密钥材料可能泄露，应更换根公钥并迁移资产。详情见[安全说明](SECURITY.zh-CN.md)。
