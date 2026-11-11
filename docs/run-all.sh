#!/usr/bin/env bash
# 一键复现：Ed25519 小阶公钥零密钥伪造跨实现裁决矩阵
# 用法: bash run-all.sh   （输出到 stdout + REPRO-REPORT.md，幂等可重跑）
# 依赖: node + npm i @noble/curves@2.4.0 tweetnacl（主矩阵）；noble-versions/ 各历史版本；
#       python3 + pyca-cryptography；Go 工具链（/tmp/go，缺席则跳过 [5] 节）
set -u
cd "$(dirname "$0")"
OUT=REPRO-REPORT.md
: > "$OUT"

say() { echo "$@"; echo "$@" >> "$OUT"; }

say "# REPRO REPORT — generated $(date -u '+%Y-%m-%dT%H:%M:%SZ')"
say
say "## 环境指纹"
say '- kernel: '"$(uname -srm)"
say '- node: '"$(node --version) (bundled OpenSSL $(node -e 'console.log(process.versions.openssl)'))"
say '- openssl CLI: '"$(openssl version 2>/dev/null || echo absent)"
say '- go: '"$(${GO:-/tmp/go/bin/go} version 2>/dev/null || echo absent)"
say '- python: '"$(python3 --version 2>/dev/null || echo absent) / pyca-cryptography $(python3 -c 'import cryptography;print(cryptography.__version__)' 2>/dev/null || echo absent)"
say
say "伪造签名 = {R=S·B, S}, S=(2^250+1234567890) mod l, M='arbitrary receipt forged without any secret'"
say "（攻击者侧计算，零私钥参与；逐位值由 forge2.mjs 现场重生成）"
say

say "## [1] 主矩阵: noble 2.4.0 / tweetnacl / Node-OpenSSL / openssl CLI × identity+order2"
node matrix2.mjs 2>&1 | tee -a "$OUT"
say ""
say "## [2] 全挠点穷举: 7 非单位挠点 × noble/Node/opensslCLI"
node torsion-matrix.mjs 2>&1 | tee -a "$OUT"
say ""
say "## [3] python-cryptography (identity + order2)"
python3 pymatrix.py 2>&1 | tee -a "$OUT"
say ""
say "## [4] noble 全版本 1.0.0→2.3.0"
node noble-versions-matrix.mjs 2>&1 | tee -a "$OUT"
say ""
say "## [5] Go crypto/ed25519 (需 Go 工具链)"
if [ -x "${GO:-/tmp/go/bin/go}" ]; then
  (cd go && ${GO:-/tmp/go/bin/go} run . 2>&1) | tee -a "$OUT"
else
  say "Go 工具链缺席，跳过（go1.22.5.linux-amd64.tar.gz sha256 见 FINDING.md 附录）"
fi
say ""
say "## [6] openssl CLI 单点根因: 无小阶检查 + cofactorless, 攻击者枚举 S (k≡0 mod 4 即过)"
node cli-rootcause.mjs 2>&1 | tee -a "$OUT"
say ""
say "幂等性: 本报告可重跑，各节输出应逐字节一致（时间戳行除外）。"
