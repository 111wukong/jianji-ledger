import fs from 'node:fs';
import path from 'node:path';
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);
const AnchorCore = require('../web/public/anchor-core.cjs');
const ledgerUrl = String(process.env.LEDGER_URL || '').trim().replace(/\/+$/, '');
const output = path.resolve('anchoring/latest.json');
fs.mkdirSync(path.dirname(output), { recursive: true });
if (!ledgerUrl) {
  console.log('未配置 LEDGER_URL，跳过锚定。请在仓库 Variables 中设置公开账本地址。');
  process.exit(0);
}

const response = await fetch(ledgerUrl + '/api/anchor-proof', {
  cache:'no-store', headers:{ Accept:'application/json' }, signal:AbortSignal.timeout(20000)
});
if (!response.ok) throw new Error('读取公开锚定证明失败：HTTP ' + response.status);
const proof = await response.json();
const checked = await AnchorCore.verifyAnchorProof(proof);
if (!checked.ok) throw new Error('拒绝发布无效锚链：' + JSON.stringify(checked));
if (!proof.anchors.length) {
  console.log('账本尚未产生锚点，无需提交。');
  process.exit(0);
}

const anchor = proof.anchors[proof.anchors.length - 1];
if (fs.existsSync(output)) {
  try {
    const old = JSON.parse(fs.readFileSync(output, 'utf8'));
    if (old.anchor && old.anchor.hash === anchor.hash) {
      console.log('锚点未变化：' + anchor.hash + '，跳过提交。');
      process.exit(0);
    }
  } catch (_) { /* 损坏的旧文件会被新证明替换 */ }
}

const attestation = {
  schema:AnchorCore.SCHEMA,
  ledgerUrl:new URL(ledgerUrl).origin,
  repository:process.env.GITHUB_REPOSITORY || '',
  observedAt:new Date().toISOString(),
  proofGeneratedAt:proof.generatedAt || '',
  merkleRoot:proof.merkleRoot,
  anchorHead:proof.anchorHead,
  anchorCount:proof.anchorCount,
  anchor,
  policy:'hash commitments only; no ciphertext, mnemonic, key bundle or plaintext included'
};
const validationError = AnchorCore.validateAttestation(attestation, ledgerUrl);
if (validationError) throw new Error(validationError);
fs.writeFileSync(output, JSON.stringify(attestation, null, 2) + '\n');
console.log('已写入 GitHub 外部锚点 #' + anchor.seq + '：' + anchor.hash);
