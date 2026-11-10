// 全挠子群（8 点）穷举裁决矩阵
import { ed25519 } from '@noble/curves/ed25519.js';
import { verify as nodeVerify, createPublicKey, createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import fs from 'node:fs';

const l = ed25519.Point.CURVE().n;
const S = (2n**250n + 1234567890123456789n) % l;
const R = ed25519.Point.BASE.multiply(S).toBytes();
const M = Buffer.from('arbitrary receipt forged without any secret');
const Sb = Buffer.alloc(32); { let s=S; for(let i=0;i<32;i++){ Sb[i]=Number(s&0xffn); s>>=8n; } }
const sig = Buffer.concat([R, Sb]);

// 找非单位挠点：随机合法编码 P（可能不在 <B> 内）→ [l]P ∈ 挠子群
let T = null;
let tried = 0;
for (let i=0; i<100000 && !T; i++) {
  const raw = Buffer.from(createHash('sha256').update(Buffer.from([i & 0xff, i>>8])).digest());
  try {
    const P = ed25519.Point.fromBytes(raw);      // 严格解码，非法则抛
    tried++;
    // 挠分量 t(P) = [l]P，但 noble 会把标量 l 归约为 0；改用 [l-1]P + P
    const t = P.multiplyUnsafe(l - 1n).add(P);
    if (!t.is0()) { T = t; break; }
  } catch {}
}
console.log('尝试解码', tried, '个合法点');
const ZERO = T.multiply(8n); // identity（order-8 挠点自乘 8 次）
// 7 个非单位挠点: k·T, k=1..7（identity 编码已单测）
const encs = [];
for (let k=1; k<=7; k++) { encs.push(Buffer.from(T.multiplyUnsafe(BigInt(k)).toBytes()).toString('hex')); }
const uniq = [...new Set(encs)];
console.log('非单位挠点数（去重）:', uniq.length, '\n');
fs.mkdirSync('/tmp/torsion',{recursive:true});
fs.writeFileSync('/tmp/torsion/msg.bin', M);
fs.writeFileSync('/tmp/torsion/sig.bin', sig);

for (const h of uniq) {
  const A = Buffer.from(h,'hex');
  fs.writeFileSync('/tmp/torsion/pub.spki', Buffer.concat([Buffer.from('302a300506032b6570032100','hex'),A]));
  const n2 = ed25519.verify(sig,M,A);
  const nn = nodeVerify(null,M,createPublicKey({key:fs.readFileSync('/tmp/torsion/pub.spki'),format:'der',type:'spki'}),sig);
  let oc=false;
  try { oc = execFileSync('openssl',['pkeyutl','-verify','-pubin','-inkey','/tmp/torsion/pub.spki','-keyform','DER','-rawin','-in','/tmp/torsion/msg.bin','-sigfile','/tmp/torsion/sig.bin'],{stdio:'pipe'}).toString().includes('Verified'); } catch {}
  console.log(`${h}`);
  console.log(`  noble2.4:${n2?'❌接受':'✅拒'} node/OpenSSL:${nn?'❌接受':'✅拒'} opensslCLI:${oc?'❌接受':'✅拒'}`);
}
fs.writeFileSync('/tmp/torsion/smalls.json', JSON.stringify(uniq,null,1));
