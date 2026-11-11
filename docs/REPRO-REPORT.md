# REPRO REPORT — generated 2026-11-11T00:46:02Z

## 环境指纹
- kernel: Linux 5.10.134-18.0.13.lifsea8.x86_64 x86_64
- node: v24.21.0 (bundled OpenSSL 3.5.8)
- openssl CLI: OpenSSL 3.5.7 9 Jun 2026 (Library: OpenSSL 3.5.7 9 Jun 2026)
- go: go version go1.22.5 linux/amd64
- python: Python 3.12.14 / pyca-cryptography 44.0.3

伪造签名 = {R=S·B, S}, S=(2^250+1234567890) mod l, M='arbitrary receipt forged without any secret'
（攻击者侧计算，零私钥参与；逐位值由 forge2.mjs 现场重生成）

## [1] 主矩阵: noble 2.4.0 / tweetnacl / Node-OpenSSL / openssl CLI × identity+order2
对照组(合法key+伪造sig):
  noble2: ✅ rejected
  node  : ✅ rejected
小阶点标记 isSmallOrder: identity= true | order2= true

公钥=identity(order1) (isSmallOrder=true)
  @noble/curves 2.4.0: ❌ ACCEPTED
  @noble/curves 1.4.2: ❌ ACCEPTED
  tweetnacl: ❌ ACCEPTED
  node/OpenSSL 3.5.8: ✅ rejected
公钥=order2(0,-1) (isSmallOrder=true)
  @noble/curves 2.4.0: ❌ ACCEPTED
  @noble/curves 1.4.2: ❌ ACCEPTED
  tweetnacl: ✅ rejected
  node/OpenSSL 3.5.8: ✅ rejected

## [2] 全挠点穷举: 7 非单位挠点 × noble/Node/opensslCLI
尝试解码 1 个合法点
非单位挠点数（去重）: 7 

26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85
  noble2.4:❌接受 node/OpenSSL:✅拒 opensslCLI:✅拒
0000000000000000000000000000000000000000000000000000000000000080
  noble2.4:❌接受 node/OpenSSL:✅拒 opensslCLI:✅拒
c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa
  noble2.4:❌接受 node/OpenSSL:✅拒 opensslCLI:❌接受
ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f
  noble2.4:❌接受 node/OpenSSL:✅拒 opensslCLI:✅拒
c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a
  noble2.4:❌接受 node/OpenSSL:✅拒 opensslCLI:✅拒
0000000000000000000000000000000000000000000000000000000000000000
  noble2.4:❌接受 node/OpenSSL:✅拒 opensslCLI:✅拒
26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05
  noble2.4:❌接受 node/OpenSSL:✅拒 opensslCLI:✅拒

## [3] python-cryptography (identity + order2)
python-cryptography identity(order1): ❌ ACCEPTED
python-cryptography order2(0,-1): ✅ rejected

## [4] noble 全版本 1.0.0→2.3.0
version      identity order2 allzero order4
1.0.0        ❌ACC  ❌ACC  ❌ACC  ❌ACC
1.1.0        ❌ACC  ❌ACC  ❌ACC  ❌ACC
1.2.0        ❌ACC  ❌ACC  ❌ACC  ❌ACC
1.3.0        ❌ACC  ❌ACC  ❌ACC  ❌ACC
1.4.0        ❌ACC  ❌ACC  ❌ACC  ❌ACC
1.4.1        ❌ACC  ❌ACC  ❌ACC  ❌ACC
1.4.2        ❌ACC  ❌ACC  ❌ACC  ❌ACC
1.5.0        ❌ACC  ❌ACC  ❌ACC  ❌ACC
1.6.0        IMPORT FAIL Cannot find module '/home/z/my-project/r
1.7.0        ❌ACC  ❌ACC  ❌ACC  ❌ACC
1.8.0        ❌ACC  ❌ACC  ❌ACC  ❌ACC
1.9.0        ❌ACC  ❌ACC  ❌ACC  ❌ACC
1.9.7        ❌ACC  ❌ACC  ❌ACC  ❌ACC
2.0.0        ❌ACC  ❌ACC  ❌ACC  ❌ACC
2.0.1        ❌ACC  ❌ACC  ❌ACC  ❌ACC
2.2.0        ❌ACC  ❌ACC  ❌ACC  ❌ACC
2.3.0        ❌ACC  ❌ACC  ❌ACC  ❌ACC

## [5] Go crypto/ed25519 (需 Go 工具链)
identity     ❌ ACCEPTED
order2       ✅ rejected
allzero      ✅ rejected
order4_fa    ❌ ACCEPTED
order4_7a    ✅ rejected
p26e8        ✅ rejected
p0080        ✅ rejected

## [6] openssl CLI 单点根因: 无小阶检查 + cofactorless, 攻击者枚举 S (k≡0 mod 4 即过)
k(…03fa) mod 4 = 0n (=0 → CLI接受)
k(…037a) mod 4 = 1n (≠0 → 拒)
CLI 对 k≡0 mod 4 候选: 4/9 接受（攻击者期望约 4~6 次尝试必中）

幂等性: 本报告可重跑，各节输出应逐字节一致（时间戳行除外）。
