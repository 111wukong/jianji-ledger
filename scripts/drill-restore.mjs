/* 灾难恢复演练：模拟「服务器关闭 / 数据目录全丢」，验证仅凭一份加密备份能否把账本完整找回来。
   流程：起临时服务 → 写入身份与记录 → 生成加密备份 → 关服务并删掉整个数据目录
        → 从备份还原 events.jsonl → 用还原后的日志重启服务 → 校验链高、链头、锚链与身份可恢复性。
   全程只用临时目录，不接触真实账本。

   用法：npm run drill:restore */
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import net from 'node:net';
import crypto from 'node:crypto';
import { spawn, execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const SERVER = path.join(ROOT, 'web', 'server.mjs');
const BACKUP = path.join(ROOT, 'scripts', 'backup-log.mjs');
const VERIFY = path.join(ROOT, 'scripts', 'verify-backup.mjs');
const GENESIS = '0'.repeat(64);
const sha = s => crypto.createHash('sha256').update(s).digest('hex');
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'jianji-drill-'));
const dataDir = path.join(tmp, 'data');
const backupDir = path.join(tmp, 'backups');
const PASS = 'drill-only-passphrase-' + crypto.randomBytes(8).toString('hex');
let server = null, port = 0, BASE = '';
const sleep = ms => new Promise(r => setTimeout(r, ms));

function freePort() {
  return new Promise(resolve => {
    const s = net.createServer();
    s.listen(0, '127.0.0.1', () => { const p = s.address().port; s.close(() => resolve(p)); });
  });
}
async function req(p, method = 'GET', body, token) {
  const r = await fetch(BASE + p, {
    method,
    headers: { 'Content-Type': 'application/json', ...(token ? { Authorization: 'Bearer ' + token } : {}) },
    body: body == null ? undefined : JSON.stringify(body)
  });
  return { status: r.status, json: await r.json() };
}
function newKey() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  return { jwk: publicKey.export({ format: 'jwk' }), privateKey };
}
const sign = (k, d) => crypto.sign('sha256', Buffer.from(d),
  { key: k.privateKey, dsaEncoding: 'ieee-p1363' }).toString('base64');
async function start() {
  server = spawn(process.execPath, [SERVER], { cwd: ROOT,
    env: { ...process.env, PORT: String(port), HOST: '127.0.0.1', LEDGER_DATA_DIR: dataDir },
    stdio: ['ignore', 'pipe', 'pipe'] });
  for (let i = 0; i < 60; i++) {
    try { if ((await fetch(BASE + '/api/health')).ok) return; } catch (e) { /* 启动中 */ }
    await sleep(80);
  }
  throw new Error('演练服务启动失败');
}
async function stop() {
  if (!server || server.exitCode !== null) return;
  await new Promise(resolve => { server.once('exit', resolve); server.kill(); });
}
function check(cond, msg) { if (!cond) throw new Error(msg); }

try {
  port = await freePort();
  BASE = 'http://127.0.0.1:' + port;
  fs.mkdirSync(dataDir, { recursive: true });
  await start();

  const k = newKey();
  const fp = sha(k.jwk.x + '|' + k.jwk.y).slice(0, 20);
  const mnemonicVerifier = sha('jianji-verifier|drill-mnemonic');
  const ch = await req('/api/challenge', 'POST', { fp });
  const sess = await req('/api/session', 'POST', { fp, pubSign: k.jwk, pubDh: k.jwk,
    nonce: ch.json.nonce, sig: sign(k, ch.json.nonce), bundle: 'encrypted-key-bundle', verifier: mnemonicVerifier });
  check(sess.status === 200, '身份注册失败');
  const token = sess.json.token;
  let head = GENESIS;
  for (let seq = 1; seq <= 3; seq++) {
    const ts = Date.now() + seq, cipher = Buffer.from('drill-cipher-' + seq).toString('base64');
    const bookTag = 'tag-drill';
    const hash = sha([seq, head, fp, cipher, bookTag, ts].join('|'));
    const r = await req('/api/entries', 'POST',
      { seq, prevHash: head, hash, cipher, sig: sign(k, hash), bookTag, ts }, token);
    check(r.status === 201, '第 ' + seq + ' 笔写入失败');
    head = hash;
  }
  await req('/api/profile', 'POST', { profile: 'encrypted-book-directory' }, token);
  const before = (await req('/api/health')).json;
  const chainBefore = (await req('/api/anchors/' + fp)).json;
  console.log('1. 灾前：' + before.entries + ' 笔，链头 ' + head.slice(0, 16) + '…，锚点 ' + before.anchorCount + ' 个');

  const env = { ...process.env, LEDGER_DATA_DIR: dataDir, LEDGER_BACKUP_DIR: backupDir,
    LEDGER_BACKUP_PASSPHRASE: PASS };
  const report = JSON.parse(execFileSync(process.execPath, [BACKUP], { env, encoding: 'utf8' }));
  check(report.encrypted && report.lines > 0, '备份生成失败');
  console.log('2. 已生成加密备份：' + path.basename(report.file) + '（' + report.lines + ' 行）');

  await stop();
  fs.rmSync(dataDir, { recursive: true, force: true });
  console.log('3. 已关闭服务并删除整个数据目录（模拟服务器关闭 + 磁盘丢失）');

  fs.mkdirSync(dataDir, { recursive: true });
  const restored = path.join(dataDir, 'events.jsonl');
  execFileSync(process.execPath, [VERIFY, report.file, '--out', restored], { env, encoding: 'utf8' });
  console.log('4. 从加密备份还原 events.jsonl，GCM 认证与锚链校验通过');

  await start();
  const after = (await req('/api/health')).json;
  check(after.entries === before.entries, '记录数不一致');
  check(after.anchorHead === before.anchorHead, '锚链头不一致');
  check(after.merkleRoot === before.merkleRoot, 'Merkle 根不一致');
  const chainAfter = (await req('/api/anchors/' + fp)).json;
  check(chainAfter.head === chainBefore.head && chainAfter.chain.length === 3, '哈希链未完整恢复');
  console.log('5. 重启后：' + after.entries + ' 笔，链头/锚链头/Merkle 根与灾前完全一致');

  const lookup = await req('/api/lookup', 'POST', { verifier: mnemonicVerifier });
  check(lookup.status === 200 && lookup.json.bundle === 'encrypted-key-bundle', '密钥包未随备份恢复');
  check(lookup.json.profile === 'encrypted-book-directory', '加密账本目录未随备份恢复');
  console.log('6. 助记词校验值可找回密钥包与加密账本目录 → 用户可用原助记词恢复身份并解密');

  const forged = JSON.parse(fs.readFileSync(report.file, 'utf8'));
  check(!forged.payload.includes('drill-cipher'), '备份中不应出现明文');
  console.log('\n演练通过：服务器关闭且原数据全丢时，凭「加密备份 + 备份口令 + 用户助记词」可完整找回账本。');
  console.log('注意：这只证明密文与身份材料可恢复；明文始终需要用户自己的助记词在浏览器中解开。');
} catch (e) {
  console.error('\n演练失败：' + (e.stack || e.message));
  process.exitCode = 1;
} finally {
  await stop();
  fs.rmSync(tmp, { recursive: true, force: true });
}
