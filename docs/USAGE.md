# Usage guide

The tss-lib dependency is pinned to fork commit `f204718ae5950ac8bf9e1a8c1a5a3f0261121bf6`. Run `go test -short ./...` for fast tests and `go test ./...` for the real DKG and threshold-signing integration.

On a trusted offline host, create a mode-0600 text file containing exactly 64 hex characters without `0x`. The tool first generates each signer's tss-lib Paillier and safe-prime pre-parameters, which takes time, then calls `vss.Create` for the existing scalar and assembles the signer save data. Run:

```sh
umask 077
./task1-keygen --private-key ./private_key.txt --wallet-id treasury-evm-01 --out-dir ./generated
```

The tool writes one `share.json` per signer and public `wallet.json` metadata. Transfer each share individually to its assigned signer; do not stage all shares together online. The tool refuses to overwrite an existing output directory.

Derive a deposit address with `./task3-address --wallet-meta ./generated/public/treasury-evm-01/wallet.json --site-id 17 --index 29`. The path is `m/site_id/index`; both indices are non-hardened and less than `2^31`. Persist the wallet/site/index mapping and never reuse an index.

Certificates are optional. With no TLS fields or certificate pins, the signer gRPC mesh and gateway API use plaintext. This is suitable only for an isolated private network; it provides no transport encryption or peer authentication. For TLS, configure a certificate, private key and CA for each node and gateway, then set the corresponding SHA-256 pins. Each node receives only its own share plus public metadata. Start nodes with `./node --config /etc/bnb-tss/node.json`.

Configure the gateway with the three signer endpoints, public metadata directory, strong API key, `max_concurrent` and `queue_size`. Add TLS identity and signer pins only if TLS is enabled. Defaults are five active requests and 1000 queued. Same-wallet requests are FIFO; distinct wallets can proceed concurrently. Start with `./gateway --config /etc/bnb-tss/gateway.json`.

Submit a 32-byte digest to `/v1/sign` over HTTP or HTTPS, then poll `/v1/jobs/{request_id}` with the API key. The API uses HTTP when no API certificate is configured. The signer accepts arbitrary digests. The caller must validate transaction chain, destination, amount, nonce, fees and approvals, then broadcast and confirm. Jobs are in-memory and lost on gateway restart. See [Chinese security notes](SECURITY.zh-CN.md) before production use.
