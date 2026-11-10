// 扩展矩阵 v2：noble 2.4.0 / noble 1.4.2 / tweetnacl / python cryptography
// + 合法密钥对照组（排除假阳性）
import { ed25519 as ed2 } from '@noble/curves/ed25519.js';
import * as ed1mod from './v1/node_modules/@noble/curves/ed25519.js';
import nacl from 'tweetnacl';
import { verify as nodeVerify, createPublicKey } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import fs from 'node:fs';

const l = 2n**252n + 27742317777372353535854737965820589843n;
const ed1 = ed1mod.ed25519 ?? ed1mod.default?.ed25519 ?? ed1mod;
const VICTIMS = {
  'identity(order1)': Buffer.from('01'+'00'.repeat(31),'hex'),
  'order2(0,-1)':     Buffer.from('ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f','hex'),
};
const S = (2n**250n + 1234567890123456789n) % l;
const R = ed2.Point.BASE.multiply(S).toBytes();
const M = Buffer.from('arbitrary receipt forged without any secret');
const Sb = Buffer.alloc(32); { let s=S; for(let i=0;i<32;i++){ Sb[i]=Number(s&0xffn); s>>=8n; } }
const sig = Buffer.concat([R, Sb]);

// 小阶点客观性: noble 自带的 isSmallOrder 标记
const isSmall = (b)=>ed2.Point.fromBytes(b).isSmallOrder();

// 合法密钥对照组: 真 key + 该伪造 sig 必须全部 rejected（排除"签名本身合法"假阳性）
const kp = ed2.keygen();
console.log('对照组(合法key+伪造sig):');
console.log('  noble2:', ed2.verify(sig,M,kp.publicKey)===false?'✅ rejected':'❌ ACCEPTED(假阳性!)');
console.log('  node  :', nodeVerify(null,M,createPublicKey({key:Buffer.concat([Buffer.from('302a300506032b6570032100','hex'),kp.publicKey]),format:'der',type:'spki'}),sig)===false?'✅ rejected':'❌ ACCEPTED(假阳性!)');
console.log('小阶点标记 isSmallOrder: identity=', isSmall(VICTIMS['identity(order1)']), '| order2=', isSmall(VICTIMS['order2(0,-1)']));
console.log();

function verdict(v){ return v===true?'❌ ACCEPTED':(v===false?'✅ rejected':'— '+v); }
for (const [name, A] of Object.entries(VICTIMS)) {
  console.log(`公钥=${name} (isSmallOrder=${isSmall(A)})`);
  console.log('  @noble/curves 2.4.0:', verdict((()=>{try{return ed2.verify(sig,M,A)}catch{return false}})()));
  // noble 1.4.2 API: ed25519.verify(sig, msg, pub); pub 接受 Uint8Array
  console.log('  @noble/curves 1.4.2:', verdict((()=>{try{return ed1.verify(sig,M,A)}catch(e){return false}})()));
  // tweetnacl: nacl.sign.detached.verify(msg, sig, pub)
  console.log('  tweetnacl:', verdict((()=>{try{return nacl.sign.detached.verify(new Uint8Array(M),new Uint8Array(sig),new Uint8Array(A))}catch(e){return false}})()));
  console.log('  node/OpenSSL 3.5.8:', verdict(nodeVerify(null,M,createPublicKey({key:Buffer.concat([Buffer.from('302a300506032b6570032100','hex'),A]),format:'der',type:'spki'}),sig)));
}
