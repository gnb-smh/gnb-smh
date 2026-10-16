# GnB node releases

Prebuilt binaries of the GnB full node (`gnb`) and command-line wallet
(`gnb-cli`). Source: the `main` branch; each release is tagged.

| Version | Tag | Platform | Archive | Archive SHA-256 |
|---|---|---|---|---|
| 0.1.2 (7b02dcc) — **current** | `release-7b02dcc` | Linux x86-64 | [0.1.2-7b02dcc/gnb-0.1.2-7b02dcc-linux-x86_64.tar.gz](0.1.2-7b02dcc/gnb-0.1.2-7b02dcc-linux-x86_64.tar.gz) | `2fa02699c13129076d9c3499022e1472c68ca70e787f03a765aa22749e65c9b5` |
| 0.1.2 (1a0ba40) — superseded | `v0.1.2` (node source = 1a0ba40) | Linux x86-64 | [0.1.2/gnb-0.1.2-1a0ba40-linux-x86_64.tar.gz](0.1.2/gnb-0.1.2-1a0ba40-linux-x86_64.tar.gz) | `74d27db5b11103f3712f4b5f8f02e38a7b476f68e1f532fd4683f8a104a0e151` |

Binaries inside 0.1.2-7b02dcc (`0.1.2-7b02dcc/SHA256SUMS`), adds the mainnet
minimum chain work (7,000,000):

- `gnb` `b3310243acdf253196ea587f88e02d85fc9b49c6f071675cd6816617714aa03b`
- `gnb-cli` `f61e48c4eb254b068875d47dffaf397f9c25ad9f238c361746858f472a11872a`

Binaries inside 0.1.2 (`0.1.2/SHA256SUMS`):

- `gnb` `aa658dafa5b08f1deaa1712b056eb1fa26ecd5f6510c5b1615f50db5cd4b3141`
- `gnb-cli` `a6ca0afe0284c7eb32652080c7f03751bb1aeb301a7a615d864ac30c231bcf8f`

**Upgrade before mainnet height 17,500.** From that height the 2026-10
audit's hardening rules apply; a node on an earlier build splits from the
network at the activation block. Earlier builds (0.1.0, activation at
110,000) are withdrawn.

Also on https://gnb-smh.com/downloads/.

Verify:

```
sha256sum gnb-0.1.2-7b02dcc-linux-x86_64.tar.gz
tar xzf gnb-0.1.2-7b02dcc-linux-x86_64.tar.gz
cd gnb-0.1.2-7b02dcc-linux-x86_64 && sha256sum -c SHA256SUMS
```
