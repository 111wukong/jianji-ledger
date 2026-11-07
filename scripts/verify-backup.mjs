/* 校验并可选还原加密备份：LEDGER_BACKUP_PASSPHRASE='...' node scripts/verify-backup.mjs <file> [--out path]
   会校验 GCM 认证标签、明文哈希、每行 JSON 与整条锚链；任何一项失败都以非零码退出。 */
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';

const file = process.argv[2];
const outIdx = process.argv.indexOf('--out');
const outPath = outIdx > 0 ? process.argv[outIdx + 1] : '';
const PASS = process.env.LEDGER_BACKUP_PASSPHRASE || '';
const sha = s => crypto.createHash('sha256').update(s).digest('hex');
if (!file || !PASS) {
  console.error("用法：LEDGER_BACKUP_PASSPHRASE='...' node scripts/verify-backup.mjs <备份文件> [--out 还原路径]");
  process.exit(1);
}
const pack = JSON.parse(fs.readFileSync(file, 'utf8'));
if (pack.format !== 'jianji-backup/v1' || pack.cipher !== 'aes-256-gcm')
  throw new Error('不是受支持的简记加密备份格式');
const key = crypto.scryptSync(PASS, Buffer.from(pack.salt, 'base64'), 32,
  { N: pack.kdfParams.N, r: pack.kdfParams.r, p: pack.kdfParams.p, maxmem: 96 * 1024 * 1024 });
const decipher = crypto.createDecipheriv('aes-256-gcm', key, Buffer.from(pack.iv, 'base64'));
decipher.setAuthTag(Buffer.from(pack.tag, 'base64'));
const plain = Buffer.concat([decipher.update(Buffer.from(pack.payload, 'base64')), decipher.final()]);
if (sha(plain) !== pack.sha256) throw new Error('明文哈希不匹配');
const lines = plain.toString('utf8').split('\n').filter(l => l.trim());
if (lines.length !== pack.lines) throw new Error('行数与备份头不一致');
const events = lines.map((l, i) => {
  try { return JSON.parse(l); } catch (e) { throw new Error('第 ' + (i + 1) + ' 行不是有效 JSON'); }
});
let seq = 0, prev = '0'.repeat(64);
for (const ev of events) {
  if (ev.t !== 'anchor') continue;
  seq++;
  if (ev.seq !== seq || ev.prevHash !== prev ||
      ev.hash !== sha([ev.seq, ev.prevHash, ev.root, ev.ts].join('|')))
    throw new Error('锚链在第 ' + seq + ' 条断开');
  prev = ev.hash;
}
if (seq !== pack.anchors || prev !== pack.anchorHead) throw new Error('锚链头与备份头不一致');
if (outPath) {
  fs.mkdirSync(path.dirname(path.resolve(outPath)), { recursive: true });
  fs.writeFileSync(outPath, plain, { mode: 0o600 });
}
console.log(JSON.stringify({ ok: true, file, createdAt: pack.createdAt, lines: lines.length,
  anchors: seq, anchorHead: prev, sha256: pack.sha256, restoredTo: outPath || null }, null, 2));
