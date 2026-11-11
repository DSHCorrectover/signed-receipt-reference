# FINDING: Ed25519 小阶公钥零密钥伪造——跨实现接受分歧实测矩阵

**日期**: 2026-11-10/11 ｜ **状态**: 全证据复现闭环（`bash run-all.sh` 幂等重放）｜ **分类**: 生态级验证分歧
**测试环境**: Linux 5.10.134 x86_64 / Node v24.21.0 (OpenSSL 3.5.8) / openssl CLI 3.5.7 / Go 1.22.5 / Python 3.12.14 + pyca-cryptography 44.0.3 / noble 1.0.0→2.4.0 / tweetnacl

## 一句话发现

**一把没有任何人持有标量的公钥（RFC 8032 8 阶挠点编码）可以对任意消息产出「验证通过」的 Ed25519 签名**——攻击者自选 S、令 R = S·B，挠项消失。是否被接受**完全取决于验证器用哪个库**：noble 16 个历史版本全部接受，Go/opensslCLI 部分接受且攻击者可枚举，OpenSSL(库) 拒绝。在收据/证明生态（DSSE、PEP 740、SER、CCS receipt）里，这把「公钥注入/配置错误」从「可检测故障」升级为「静默万能伪造」。

## 攻击构造（零密钥，全部攻击者侧完成）

```
S ← 任意规范标量（攻击者自选）
R ← S·B                        ← 无需任何私钥，纯公开点运算
sig ← R ‖ S                    ← 32+32 字节
受害公钥 A ← 8 阶挠点编码
cofactorless: S·B == R + k·A → k·A=I 当 ord(A)|k → 退化成立
cofactored  : 8·S·B == 8·R + 8·k·A → 恒成立
```

## 裁决矩阵（同一伪造签名，逐库实测，`run-all.sh` [1][2][3] 节）

| 验证实现 | identity `01\|00` | order2 `ec..7f` | 其余挠点/全零 |
|---|---|---|---|
| **@noble/curves 2.4.0**（默认 zip215） | ❌ 接受 | ❌ 接受 | ❌ **全部 7 挠点+全零编码接受** |
| **@noble/curves 1.0.0→2.3.0**（16 版逐版实测） | ❌ 接受 | ❌ 接受 | ❌ 接受 |
| **tweetnacl** | ❌ 接受 | ✅ 拒 | — |
| **pyca-cryptography 44.0.3** | ❌ 接受 | ✅ 拒 | — |
| **Go 1.22.5 crypto/ed25519** | ❌ **接受（任意 S）** | ✅ 拒 | ❌ order4 可枚举接受 |
| Node/OpenSSL 3.5.8 | ✅ 拒 | ✅ 拒 | ✅ 全拒 |
| openssl CLI 3.5.7 `-rawin` | ✅ 拒 | ✅ 拒 | ❌ `c717..fa` **可枚举接受** |

对照组：合法公钥 + 伪造签名 → 全部 rejected（假阳性排除，`run-all.sh` [1] 节头部）。

## 三个根因（全部查清）

1. **noble 2.4.0**: wrapper 默认 `zip215:true`（`ed25519.js:119`），verify 声称 RFC 8032 语义却走 ZIP-215 宽松解码；自带 `isSmallOrder()` 但仅 `zip215:false` 分支使用（`edwards.js:651`）。**1.0.0→2.3.0 无任何小阶检查**。官方自测只覆盖 `R=identity` 伪造形状，未覆盖 `R=S·B` 形状。
2. **openssl CLI 3.5.7 / Go crypto/ed25519**: 无小阶检查 + cofactorless 方程 → 挠点公钥在 `k ≡ 0 mod ord(A)` 时通过。对攻击者**可枚举**（每次尝试换 S，期望 4~6 次必中，实测 4/9 候选通过，`cli-rootcause.mjs`）。identity 挠点则对任意 S 直接通过（Go 实测）。
3. **Node/OpenSSL 3.5.8**: 解码路径完整拒绝全部挠点 → 本矩阵中唯一全拒实现。

## 复现方式（幂等）

```bash
cd research/small-order
npm i @noble/curves@2.4.0 tweetnacl && python3 -m pip install cryptography
bash run-all.sh     # 生成 REPRO-REPORT.md，重跑逐字节一致（时间戳行除外）
```

- 伪造向量: S=`(2^250+1234567890) mod l`，M=`arbitrary receipt forged without any secret`，R/S 逐位值由 `forge2.mjs` 重生成
- 挠点编码: 全 8 编码见 `keys.js SMALL_ORDER_ENCODINGS`（经 [l]P 挠分量枚举 + `isSmallOrder()` 双重确认）
- Go 工具链: `go1.22.5.linux-amd64.tar.gz`（sha256 记录于 REPRO-REPORT 环境指纹节）

## 与既有工作的关系（诚实边界）

- Small-subgroup/cofactor 检查缺失是**已知类别**（RFC 8032 §8.8、ZIP-215 放宽语义、EdDSA 文献均为先例）。
- 本文增量：① 2026 实测跨库矩阵（noble 16 版无一拒绝 + Go/pyca/tweetnacl/OpenSSL 分歧全谱）；② `R=S·B` 伪造形状绕过 noble 官方自测；③ 收据生态信任根影响分析；④ opensslCLI 单点根因（k≡0 mod 4 可枚举性）。
- **未覆盖**（如实声明）：Rust ed25519-dalek（沙箱无 Rust 工具链）、 noble 1.6.0（安装损坏跳过）、各实现的下游真实收据产品抽样、另一协作环境 N12 原始 66 向量的逐字节对拍（文件不在此环境，根因已按同链路独立复现）。
- 过程更正：早期手搓曲线数学的 l 常数有误（尾数），以 noble `Point.CURVE().n` 为准重验——所有库直判裁决不受影响（库自算 k）。

## 披露建议（待批）

1. **noble-curves GitHub issue**: 默认 `zip215:true` 使 `verify` 接受全挠点零密钥伪造，16 版无一拒绝；建议默认小阶拒绝 + 补 `R=S·B` 形状自测
2. **golang/go issue**: `crypto/ed25519.Verify` 接受 identity 公钥任意消息伪造（同 lib/sodium 系需查）
3. **pyca/cryptography + tweetnacl issue**: identity 向量
4. **CCS/SER 草案安全考量节**: verifier MUST fail-closed 拒绝挠点公钥，不依赖底层库
5. 我方 v2 已先行硬化（`keys.js` 小阶闸 + 全挠点向量测试，99/99 绿，commit 5a8e0df）

## 我方暴露面自查

- `signed-receipt-reference` v2 验签链 = Node crypto (OpenSSL 3.5.8) + 显式小阶闸（双保险）→ 已 fail-closed ✅
- CCS verifier 同栈 → 同上
