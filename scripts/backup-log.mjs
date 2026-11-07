/* 加密的事件日志异地备份。零第三方依赖，只用 Node 内置 crypto。
   用法：LEDGER_BACKUP_PASSPHRASE='...' npm run backup
   可选：LEDGER_DATA_DIR（源）、LEDGER_BACKUP_DIRS（多个目标，逗号分隔；也兼容单个 LEDGER_BACKUP_DIR）、
        LEDGER_BACKUP_KEEP（每个目标保留份数，默认 30）

   备份前会校验整条锚链；校验失败时拒绝生成备份，避免把损坏的副本当成容灾。 */
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { fileURLToPath } from 'node:url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const SRC_DIR = path.resolve(process.env.LEDGER_DATA_DIR || path.join(ROOT, 'web', 'data'));
const SRC = path.join(SRC_DIR, 'events.jsonl');
const OUT_DIRS = Array.from(new Set(
  (process.env.LEDGER_BACKUP_DIRS || process.env.LEDGER_BACKUP_DIR || path.join(ROOT, 'backups'))
    .split(',').map(s => s.trim()).filter(Boolean).map(s => path.resolve(s))
));
const KEEP = Math.max(1, Number(process.env.LEDGER_BACKUP_KEEP) || 30);
const PASS = process.env.LEDGER_BACKUP_PASSPHRASE || '';
const FORMAT = 'jianji-backup/v1';
const SCRYPT = { N: 32768, r: 8, p: 1, maxmem: 96 * 1024 * 1024 };
const sha = s => crypto.createHash('sha256').update(s).digest('hex');

if (!PASS) {
  console.error('缺少 LEDGER_BACKUP_PASSPHRASE：拒绝生成未加密的账本备份。');
  console.error("示例：LEDGER_BACKUP_PASSPHRASE='一个高强度口令' npm run backup");
  process.exit(1);
}
if (!fs.existsSync(SRC)) {
  console.error('找不到事件日志：' + SRC);
  process.exit(1);
}
const plain = fs.readFileSync(SRC);
const lines = plain.toString('utf8').split('\n').filter(l => l.trim());
const events = lines.map((l, i) => {
  try { return JSON.parse(l); } catch (e) { throw new Error('第 ' + (i + 1) + ' 行不是有效 JSON'); }
});
let seq = 0, prev = '0'.repeat(64);
for (const ev of events) {
  if (ev.t !== 'anchor') continue;
  seq++;
  const calc = sha([ev.seq, ev.prevHash, ev.root, ev.ts].join('|'));
  if (ev.seq !== seq || ev.prevHash !== prev || ev.hash !== calc)
    throw new Error('锚链在第 ' + seq + ' 条断开，拒绝备份损坏的日志');
  prev = ev.hash;
}

const salt = crypto.randomBytes(16);
const iv = crypto.randomBytes(12);
const key = crypto.scryptSync(PASS, salt, 32, SCRYPT);
const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
const ct = Buffer.concat([cipher.update(plain), cipher.final()]);
const tag = cipher.getAuthTag();
const pack = {
  format: FORMAT, createdAt: new Date().toISOString(),
  source: path.basename(SRC), bytes: plain.length, lines: lines.length,
  anchors: seq, anchorHead: prev, sha256: sha(plain),
  kdf: 'scrypt', kdfParams: { N: SCRYPT.N, r: SCRYPT.r, p: SCRYPT.p },
  cipher: 'aes-256-gcm', salt: salt.toString('base64'), iv: iv.toString('base64'),
  tag: tag.toString('base64'), payload: ct.toString('base64')
};
const stamp = new Date().toISOString().replace(/[:.]/g, '-');
const body = JSON.stringify(pack, null, 2) + '\n';
const written = [], targets = [];
for (const dir of OUT_DIRS) {
  fs.mkdirSync(dir, { recursive: true });
  const out = path.join(dir, 'jianji-' + stamp + '.jsonl.enc');
  fs.writeFileSync(out, body, { mode: 0o600 });
  written.push(out);
  const files = fs.readdirSync(dir)
    .filter(f => f.startsWith('jianji-') && f.endsWith('.jsonl.enc')).sort();
  let removed = 0;
  while (files.length > KEEP) { fs.rmSync(path.join(dir, files.shift())); removed++; }
  targets.push({ dir, count: files.length, removed });
}
console.log(JSON.stringify({ ok: true, file: written[0], files: written, targets,
  bytes: plain.length, lines: lines.length, anchors: seq, encrypted: true,
  kept: targets[0].count, removed: targets[0].removed }, null, 2));
