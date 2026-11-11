// Go crypto/ed25519 小阶公钥裁决 — 零密钥伪造向量
package main

import (
	"os"
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
)

var identity, _ = hex.DecodeString("0100000000000000000000000000000000000000000000000000000000000000")
var order2, _ = hex.DecodeString("ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f")
var allzero, _ = hex.DecodeString("0000000000000000000000000000000000000000000000000000000000000000")
var order4, _ = hex.DecodeString("c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa")
var order4b, _ = hex.DecodeString("c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a")
var p26e8, _ = hex.DecodeString("26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85")
var p0080, _ = hex.DecodeString("0000000000000000000000000000000000000000000000000000000000000080")

// R = S·B，S = 2^250+1234567890（攻击者侧预计算，noble 产出，与本矩阵其他行同一签名）
var sig, _ = hex.DecodeString("e2f4b36a1b0c718dc4e2e8a8616d3ac8a95a1b24d6f23c58e07914a2b3c5d6e7" +
	"e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7")
var msg = []byte("arbitrary receipt forged without any secret")

func main() {
	// 签名 R 部分由攻击者侧(noble)计算，此处只做 verify 裁决。
	// 但 sig hex 是占位 —— 必须用真实向量。改为从文件读：
	data, err := os.ReadFile("/tmp/torsion/sig.bin")
	if err != nil { panic(err) }
	sig = data
	cases := []struct{ name string; A []byte }{
		{"identity", identity}, {"order2", order2}, {"allzero", allzero},
		{"order4_fa", order4}, {"order4_7a", order4b}, {"p26e8", p26e8}, {"p0080", p0080},
	}
	for _, c := range cases {
		name, A := c.name, c.A
		ok := ed25519.Verify(A, msg, sig)
		if ok {
			fmt.Printf("%-12s ❌ ACCEPTED\n", name)
		} else {
			fmt.Printf("%-12s ✅ rejected\n", name)
		}
	}
}
