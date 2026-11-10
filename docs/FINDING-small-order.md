# FINDING: Ed25519 小阶公钥零密钥伪造——跨实现接受分歧实测矩阵

**日期**: 2026-11-10 ｜ **状态**: 已复现，待披露 ｜ **分类**: 生态级验证分歧（spec-adjacent）
**测试环境**: 沙箱 Linux x86_64 / Node v24.21.0 (OpenSSL 3.5.8) / openssl CLI 3.5.7 / noble 2.4.0 & 1.4.2 / pyca-cryptography 44.0.3 / tweetnacl latest

## 一句话发现

**一把没有任何人持有标量的公钥（RFC 8032 8 阶挠点编码）可以对任意消息产出「验证通过」的 Ed25519 签名**——攻击者自选 S、令 R = S·B，挠项消失。在收据/证明生态（DSSE、PEP 740、SER、CCS receipt）里，这把「公钥注入/配置错误」从「可检测的故障」升级为「静默的万能伪造」。是否被接受，**完全取决于验证器用哪个库**。

## 攻击构造（零密钥，全部攻击者侧完成）

```
S ← 任意规范标量（攻击者自选）
R ← S·B                        ← 无需任何私钥，纯公开点运算
sig ← R ‖ S                    ← 32+32 字节
受害公钥 A ← 8 阶挠点编码（如 01||00*31）
验证方程（cofactorless）: S·B == R + k·A → k·A = I → 退化为 S·B == R → 成立
验证方程（cofactored）  : 8·S·B == 8·R + 8·k·A → 8k·A = I → 同样成立
→ 任意消息 M 验证通过
```

## 裁决矩阵（同一伪造签名，逐库实测）

| 验证实现 | identity `01\|00` | order2 `ec..7f` | order4 `c717..fa` | 其余 4 挠点 | 全零 `00..00` |
|---|---|---|---|---|---|
| **@noble/curves 2.4.0**（默认 zip215） | ❌ 接受 | ❌ 接受 | ❌ 接受 | ❌ 接受 ×4 | ❌ 接受 |
| **@noble/curves 1.4.2**（部署最广） | ❌ 接受 | ❌ 接受 | — | — | — |
| **tweetnacl** | ❌ 接受 | ✅ 拒 | — | — | — |
| **pyca/cryptography 44.0.3** | ❌ 接受 | ✅ 拒 | — | — | — |
| **Node 24 / OpenSSL 3.5.8** | ✅ 拒 | ✅ 拒 | ✅ 拒 | ✅ 拒 ×4 | ✅ 拒 |
| **openssl CLI 3.5.7 (-rawin)** | ✅ 拒 | ✅ 拒 | ❌ **接受** | ✅ 拒 ×4 | ✅ 拒 |

**对照组**（排除假阳性）：合法公钥 + 同一伪造签名 → 全部实现拒绝。
**小阶点客观性**：noble 自带 `Point.isSmallOrder()` 对全部 8 个点返回 `true`——库有检测工具，默认 `verify()` 不使用。

## 三层定性

1. **规范层**：RFC 8032 §8.8 明言乘 cofactor「并非严格必要」，并预警实现分歧的后果；§5.1.3 解码规则不强制拒绝小阶点。**规范留了门，实现分歧已在实测中出现**——包括 OpenSSL 家族内部（CLI 3.5.7 接受一个 order-4 点，3.5.8 全拒）。
2. **实现层**：noble 2.4.0 默认 `zip215: true`（ed25519.js:119），与其 `verify` docstring「RFC 8032 §§5.1.7」自相矛盾；`{zip215:false}` 即拒——**默认值即安全边界**。noble 1.4.2 无任何检查。noble 自测仅覆盖 R=identity 伪造形状，**未覆盖本文 R=S·B 形状**。
3. **生态层**：noble/nacl/pyca 是 JS/Py 签名生态的事实标准；收据签发-验证链若任何一环允许公钥来自可注入源（登记表、metadata、降级配置），小阶点即万能伪造。

## 复现

```bash
cd research/small-order
node forge2.mjs          # 基线 + identity/order2 双库裁决
node torsion-matrix.mjs  # 全挠子群 7 点 × noble/node/opensslCLI 穷举
node matrix2.mjs         # 四实现 + 对照组
python3 pymatrix.py      # python-cryptography
```

伪造向量（S=`4f5e…8192a`(hex 小端 32B)，R=`S·B`，M=`arbitrary receipt forged without any secret`）见 `/tmp/torsion/sig.bin` + `/tmp/torsion/smalls.json`（7 编码全表）。

## 与既有工作的关系

- Small-subgroup / cofactor 检查缺失是已知类别（RFC 8032 §8.5.2 建议、EdDSA 文献、ZIP-215 放宽语义均为先例）。
- **本文增量**：① 2026 年实测矩阵——noble 1.x/2.x 默认全接受、pyca/tweetnacl 部分接受、OpenSSL 家族内部自相矛盾；② R=S·B 伪造形状绕过 noble 现有自测；③ 收据生态（DSSE/PEP 740/SER/CCS）语境的信任根影响分析。
- 不联系任何攻击者；仅公开数据与自有实现。

## 披露建议（待批）

1. **noble-curves GitHub issue**（公开，含 PoC + 建议 `verify` 默认 `zip215:false` 或至少默认小阶拒绝；明确提及 1.4.2 无检查）
2. **pyca/cryptography + tweetnacl issue**（identity 类向量）
3. **CCS / SER 草案安全考量节增补**：verifier MUST 拒绝小阶/挠点公钥（fail-closed），不依赖底层库行为
4. 我方 `signed-receipt-reference` v2 硬化：`keys.js` 显式小阶拒绝（不依赖 OpenSSL）+ 向量测试

## 我方暴露面自查

- `signed-receipt-reference` v2 验签链 = Node crypto (OpenSSL 3.5.8) → 当前全拒 ✅，但属「依赖底层行为」而非显式规则 → 待硬化补丁
- CCS verifier 同栈 → 同上
