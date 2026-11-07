/* 服务端 HTTP 集成测试：起真实进程、用临时数据目录，覆盖注册、写入、幂等、
   分叉、增量同步、辅助校验、账本目录、重放与损坏日志的 fail-fast。 */
import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { spawn, execFileSync } from 'node:child_process';
import crypto from 'node:crypto';
import fs from 'node:fs';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const SERVER = path.join(ROOT, 'web', 'server.mjs');
const sha = s => crypto.createHash('sha256').update(s).digest('hex');
const GENESIS = '0'.repeat(64);
let child = null;
let BASE = '';
let DIR = '';

after(async () => {
  if (child && !child.killed) child.kill();
  if (DIR) fs.rmSync(DIR, { recursive: true, force: true });
});

function freePort() {
  return new Promise(resolve => {
    const s = net.createServer();
    s.listen(0, '127.0.0.1', () => { const p = s.address().port; s.close(() => resolve(p)); });
  });
}
async function waitHealth(base, timeoutMs = 8000) {
  const start = Date.now();
  while (Date.now() - start < timeoutMs) {
    try {
      const r = await fetch(base + '/api/health');
      if (r.ok) return await r.json();
    } catch (e) { /* 尚未监听 */ }
    await new Promise(r => setTimeout(r, 60));
  }
  throw new Error('服务端未能在超时时间内就绪');
}
function launch(dir, port, extraEnv) {
  return spawn(process.execPath, [SERVER], {
    cwd: ROOT,
    env: { ...process.env, PORT: String(port), HOST: '127.0.0.1', LEDGER_DATA_DIR: dir, ...extraEnv },
    stdio: ['ignore', 'pipe', 'pipe']
  });
}
async function stop(proc) {
  if (!proc || proc.exitCode !== null) return;
  await new Promise(resolve => { proc.once('exit', resolve); proc.kill(); });
}
async function req(p, method = 'GET', body, token) {
  const r = await fetch(BASE + p, {
    method,
    headers: { 'Content-Type': 'application/json', ...(token ? { Authorization: 'Bearer ' + token } : {}) },
    body: body === undefined ? undefined : JSON.stringify(body)
  });
  return { status: r.status, json: await r.json() };
}
function newKey() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  return { jwk: publicKey.export({ format: 'jwk' }), privateKey };
}
const sign = (k, data) => crypto.sign('sha256', Buffer.from(data),
  { key: k.privateKey, dsaEncoding: 'ieee-p1363' }).toString('base64');
function makeEntry(key, fp, seq, prevHash, tag, text) {
  const ts = Date.now() + seq;
  const cipher = Buffer.from('cipher-' + text + '-' + seq).toString('base64');
  const bookTag = tag;
  const hash = sha([seq, prevHash, fp, cipher, bookTag, ts].join('|'));
  return { seq, prevHash, hash, cipher, sig: sign(key, hash), bookTag, ts };
}

test('服务端集成：身份、只追加账本、增量同步、校验与重放', async t => {
  DIR = fs.mkdtempSync(path.join(os.tmpdir(), 'jianji-server-test-'));
  const port = await freePort();
  BASE = 'http://127.0.0.1:' + port;
  child = launch(DIR, port);
  const health = await waitHealth(BASE);
  const key = newKey();
  const fp = sha(key.jwk.x + '|' + key.jwk.y).slice(0, 20);
  const verifier = sha('jianji-verifier|test-mnemonic');
  let token = '', head = GENESIS, seq = 0;

  await t.test('初始状态为空，且未登录不能读取账目', async () => {
    assert.equal(health.owners, 0);
    assert.equal(health.anchorCount, 0);
    const s = await req('/api/status');
    assert.equal(s.json.anchorHead, GENESIS);
    assert.deepEqual(s.json.heads, []);
    const denied = await req('/api/entries');
    assert.equal(denied.status, 401);
  });

  await t.test('挑战绑定身份指纹，私钥签名登录并登记身份', async () => {
    const ch = await req('/api/challenge', 'POST', { fp });
    assert.equal(ch.status, 200);
    const wrongFp = await req('/api/session', 'POST', {
      fp: 'another-fingerprint', pubSign: key.jwk, nonce: ch.json.nonce, sig: sign(key, ch.json.nonce)
    });
    assert.equal(wrongFp.status, 400);
    const ok = await req('/api/session', 'POST', {
      fp, pubSign: key.jwk, pubDh: key.jwk, nonce: ch.json.nonce, sig: sign(key, ch.json.nonce),
      bundle: 'encrypted-private-key-bundle', verifier
    });
    assert.equal(ok.status, 200);
    assert.equal(ok.json.isNew, true);
    token = ok.json.token;
  });

  await t.test('顺序写入、幂等重试与分叉拒绝', async () => {
    const e1 = makeEntry(key, fp, 1, head, 'tag-a', 'one');
    const r1 = await req('/api/entries', 'POST', e1, token);
    assert.equal(r1.status, 201);
    head = e1.hash; seq = 1;
    const dup = await req('/api/entries', 'POST', e1, token);
    assert.equal(dup.json.existing, true);
    const fork = makeEntry(key, fp, 2, GENESIS, 'tag-a', 'fork');
    const rFork = await req('/api/entries', 'POST', fork, token);
    assert.equal(rFork.status, 409);
    for (let n = 2; n <= 3; n++) {
      const e = makeEntry(key, fp, n, head, 'tag-a', 'seq' + n);
      const r = await req('/api/entries', 'POST', e, token);
      assert.equal(r.status, 201);
      head = e.hash; seq = n;
    }
    const all = await req('/api/entries', 'GET', undefined, token);
    assert.equal(all.json.entries.length, 3);
    assert.equal(all.json.entries[0].fp, fp);
  });

  await t.test('since 只返回连续后缀', async () => {
    const inc = await req('/api/entries?since=2', 'GET', undefined, token);
    assert.equal(inc.json.since, 2);
    assert.equal(inc.json.entries.length, 1);
    assert.equal(inc.json.entries[0].seq, 3);
    assert.equal(inc.json.head, head);
    const none = await req('/api/entries?since=3', 'GET', undefined, token);
    assert.equal(none.json.entries.length, 0);
  });

  await t.test('/api/verify 只认可已登记身份的完整链', async () => {
    const all = await req('/api/entries', 'GET', undefined, token);
    const good = await req('/api/verify', 'POST', { fp, chain: all.json.entries });
    assert.equal(good.json.ok, true, JSON.stringify(good.json));
    const tampered = all.json.entries.slice();
    tampered[0] = { ...tampered[0], hash: GENESIS };
    const bad = await req('/api/verify', 'POST', { fp, chain: tampered });
    assert.equal(bad.json.ok, false);
    assert.equal(bad.json.broken, 1);
    const short = await req('/api/verify', 'POST', { fp, chain: all.json.entries.slice(0, 2) });
    assert.equal(short.json.ok, false);
    assert.equal(short.json.lengthOk, false);

    /* 伪造一条完全自洽、由另一把私钥签名的链：不能借未登记身份盖章。 */
    const fakeKey = newKey(), fakeFp = 'never-registered-fp';
    let prev = GENESIS;
    const fakeChain = [];
    for (let i = 1; i <= 2; i++) {
      const ts = 1700000000000 + i, cipher = 'ZmFrZQ==', bookTag = 'fake';
      const hash = sha([i, prev, fakeFp, cipher, bookTag, ts].join('|'));
      fakeChain.push({ seq: i, prevHash: prev, hash, cipher, bookTag, ts, sig: sign(fakeKey, hash), fp: fakeFp });
      prev = hash;
    }
    const forged = await req('/api/verify', 'POST', { fp: fakeFp, chain: fakeChain, pubSign: fakeKey.jwk });
    assert.equal(forged.status, 404);
    const forgedUnderRealFp = await req('/api/verify', 'POST', { fp, chain: fakeChain, pubSign: fakeKey.jwk });
    assert.equal(forgedUnderRealFp.json.ok, false);
  });

  await t.test('加密账本目录可随身份恢复，重复提交不写日志', async () => {
    const profile = 'encrypted-book-directory-blob';
    const put = await req('/api/profile', 'POST', { profile }, token);
    assert.equal(put.json.ok, true);
    const me = await req('/api/me', 'GET', undefined, token);
    assert.equal(me.json.profile, profile);
    const lookup = await req('/api/lookup', 'POST', { verifier });
    assert.equal(lookup.json.profile, profile);
    const again = await req('/api/profile', 'POST', { profile }, token);
    assert.equal(again.json.unchanged, true);
    const before = (await req('/api/health')).json.anchorCount;
    await req('/api/profile', 'POST', { profile: profile + '-2' }, token);
    const after = (await req('/api/health')).json.anchorCount;
    assert.equal(after, before + 1);
  });

  await t.test('批量同步逐条追加，并在中途失败时保留已处理结果', async () => {
    const next = [];
    let p = head;
    for (let n = seq + 1; n <= seq + 3; n++) {
      const e = makeEntry(key, fp, n, p, 'tag-a', 'batch' + n);
      next.push(e); p = e.hash;
    }
    const r = await req('/api/entries/sync', 'POST', { entries: next }, token);
    assert.equal(r.json.ok, true);
    assert.equal(r.json.results.length, 3);
    assert.equal(r.json.seq, seq + 3);
    seq += 3; head = p;

    const badBatch = [makeEntry(key, fp, seq + 1, head, 'tag-a', 'good'),
      makeEntry(key, fp, seq + 2, GENESIS, 'tag-a', 'broken-prefix')];
    const partial = await req('/api/entries/sync', 'POST', { entries: badBatch }, token);
    assert.equal(partial.status, 409);
    assert.equal(partial.json.results.length, 1);
    assert.equal(partial.json.conflict, true);
    seq += 1; head = badBatch[0].hash;
  });

  await t.test('/api/status 的摘要足够驱动轻量探测', async () => {
    const s = await req('/api/status');
    const mine = s.json.heads.find(h => h.fp === fp);
    assert.equal(mine.seq, seq);
    assert.equal(mine.head, head);
    assert.ok(s.json.anchorCount > 0);
    assert.equal(s.json.anchorHead, (await req('/api/health')).json.anchorHead);
  });

  await t.test('重启重放后链高、链头与账本目录完全一致', async () => {
    await stop(child);
    child = launch(DIR, port);
    const h = await waitHealth(BASE);
    assert.equal(h.entries, seq);
    const me = await req('/api/me', 'GET', undefined, token);
    assert.equal(me.status, 401, '重启后内存会话密钥更换，旧 token 应失效');
    const ch = await req('/api/challenge', 'POST', { fp });
    const re = await req('/api/session', 'POST', {
      fp, pubSign: key.jwk, pubDh: key.jwk, nonce: ch.json.nonce,
      sig: sign(key, ch.json.nonce), verifier
    });
    assert.equal(re.json.seq, seq);
    assert.equal(re.json.head, head);
    const fresh = await req('/api/me', 'GET', undefined, re.json.token);
    assert.ok(fresh.json.profile.startsWith('encrypted-book-directory-blob'));
  });

  await t.test('损坏的事件日志拒绝启动，而不是静默跳过', async () => {
    const brokenDir = fs.mkdtempSync(path.join(os.tmpdir(), 'jianji-broken-'));
    fs.writeFileSync(path.join(brokenDir, 'events.jsonl'),
      '{"t":"identity","fp":"x"}\n{broken json\n{"t":"anchor","seq":1}\n');
    const p2 = await freePort();
    const proc = launch(brokenDir, p2);
    let stderr = '';
    proc.stderr.on('data', d => { stderr += d.toString(); });
    const code = await new Promise(resolve => proc.once('exit', resolve));
    assert.equal(code, 1);
    assert.match(stderr, /拒绝启动/);
    fs.rmSync(brokenDir, { recursive: true, force: true });
  });

  await t.test('只有尾部半行时可显式允许截断后启动', async () => {
    const tailDir = fs.mkdtempSync(path.join(os.tmpdir(), 'jianji-tail-'));
    fs.writeFileSync(path.join(tailDir, 'events.jsonl'), '{"t":"identity","fp":"x"}\n{"t":"an');
    const p3 = await freePort();
    const proc = launch(tailDir, p3, { LEDGER_ALLOW_TAIL_LOSS: '1' });
    const h = await waitHealth('http://127.0.0.1:' + p3);
    assert.equal(h.ok, true);
    await stop(proc);
    fs.rmSync(tailDir, { recursive: true, force: true });
  });

  await t.test('末行缺少换行时自动补写，之后追加不会与旧行粘连', async () => {
    const nlDir = fs.mkdtempSync(path.join(os.tmpdir(), 'jianji-newline-'));
    const log = path.join(nlDir, 'events.jsonl');
    fs.writeFileSync(log, '{"t":"identity","fp":"legacy"}');
    const p4 = await freePort();
    const proc = launch(nlDir, p4);
    const base = 'http://127.0.0.1:' + p4;
    await waitHealth(base);
    const saved = BASE; BASE = base;
    try {
      const k = newKey();
      const nfp = sha(k.jwk.x + '|' + k.jwk.y).slice(0, 20);
      const ch = await req('/api/challenge', 'POST', { fp: nfp });
      const ok = await req('/api/session', 'POST', {
        fp: nfp, pubSign: k.jwk, pubDh: k.jwk, nonce: ch.json.nonce,
        sig: sign(k, ch.json.nonce), bundle: 'b', verifier: 'v'
      });
      assert.equal(ok.status, 200);
      const rows = fs.readFileSync(log, 'utf8').split('\n').filter(x => x.trim());
      assert.equal(rows.length, 3);
      for (const row of rows) assert.doesNotThrow(() => JSON.parse(row));
      assert.equal(JSON.parse(rows[0]).fp, 'legacy');
    } finally {
      BASE = saved;
      await stop(proc);
      fs.rmSync(nlDir, { recursive: true, force: true });
    }
  });

  await t.test('严格 CSP 与生产安全头', async () => {
    const r = await fetch(BASE + '/api/health');
    assert.equal(r.headers.get('x-content-type-options'), 'nosniff');
    assert.equal(r.headers.get('x-frame-options'), 'DENY');
    assert.equal(r.headers.get('referrer-policy'), 'no-referrer');
    const csp = r.headers.get('content-security-policy') || '';
    assert.match(csp, /default-src 'self'/);
    assert.match(csp, /script-src 'self';/);
    assert.equal(csp.includes("script-src 'self' 'unsafe-inline'"), false, '不应允许内联脚本');
    const page = await fetch(BASE + '/index.html');
    assert.match(page.headers.get('content-security-policy') || '', /default-src 'self'/);
    const https = await fetch(BASE + '/api/health', { headers: { 'x-forwarded-proto': 'https' } });
    assert.match(https.headers.get('strict-transport-security') || '', /max-age=/);
  });

  await t.test('健康检查暴露降级标志与日志体积', async () => {
    const h = (await req('/api/health')).json;
    assert.equal(h.degraded, false);
    assert.equal(h.inviteRequired, false);
    assert.deepEqual(h.warnings, []);
    assert.ok(h.logBytes > 0);
  });

  await t.test('邀请码闸门只约束新身份注册，已有身份登录不受影响', async () => {
    const invDir = fs.mkdtempSync(path.join(os.tmpdir(), 'jianji-invite-'));
    const p = await freePort();
    const proc = launch(invDir, p, { LEDGER_INVITE_CODE: 'INVITE-2026-TEST' });
    const base = 'http://127.0.0.1:' + p;
    await waitHealth(base);
    const saved = BASE; BASE = base;
    try {
      assert.equal((await req('/api/status')).json.inviteRequired, true);
      const k = newKey();
      const fp = sha(k.jwk.x + '|' + k.jwk.y).slice(0, 20);
      const payload = nonce => ({ fp, pubSign:k.jwk, pubDh:k.jwk, nonce,
        sig:sign(k, nonce), bundle:'b', verifier:'v' });
      const c1 = await req('/api/challenge', 'POST', { fp });
      assert.equal((await req('/api/session', 'POST', payload(c1.json.nonce))).status, 403);
      const c2 = await req('/api/challenge', 'POST', { fp });
      const ok = await req('/api/session', 'POST',
        Object.assign(payload(c2.json.nonce), { inviteCode:'INVITE-2026-TEST' }));
      assert.equal(ok.status, 200);
      assert.equal(ok.json.isNew, true);
      const c3 = await req('/api/challenge', 'POST', { fp });
      const again = await req('/api/session', 'POST', payload(c3.json.nonce));
      assert.equal(again.status, 200, '已登记身份重新登录不应再要邀请码');
      assert.equal(again.json.isNew, false);
    } finally {
      BASE = saved;
      await stop(proc);
      fs.rmSync(invDir, { recursive: true, force: true });
    }
  });

  await t.test('加密备份可生成、可校验，且能检出篡改', () => {
    const backupDir = fs.mkdtempSync(path.join(os.tmpdir(), 'jianji-backup-'));
    const env = { ...process.env, LEDGER_DATA_DIR: DIR, LEDGER_BACKUP_DIR: backupDir,
      LEDGER_BACKUP_PASSPHRASE: 'unit-test-passphrase-ABC123' };
    const backupScript = path.join(ROOT, 'scripts', 'backup-log.mjs');
    const verifyScript = path.join(ROOT, 'scripts', 'verify-backup.mjs');
    try {
      const report = JSON.parse(execFileSync(process.execPath, [backupScript], { env, encoding: 'utf8' }));
      assert.equal(report.ok, true);
      assert.equal(report.encrypted, true);
      assert.ok(report.lines > 0 && report.anchors > 0);
      const checked = JSON.parse(execFileSync(process.execPath, [verifyScript, report.file], { env, encoding: 'utf8' }));
      assert.equal(checked.ok, true);
      assert.equal(checked.anchors, report.anchors);
      const pack = JSON.parse(fs.readFileSync(report.file, 'utf8'));
      assert.equal(pack.payload.includes('"t":"entry"'), false, '备份文件不得出现明文事件');
      pack.payload = Buffer.from('tampered').toString('base64');
      fs.writeFileSync(report.file, JSON.stringify(pack));
      assert.throws(() => execFileSync(process.execPath, [verifyScript, report.file],
        { env, encoding: 'utf8', stdio: 'pipe' }));
    } finally {
      fs.rmSync(backupDir, { recursive: true, force: true });
    }
  });

  await t.test('/api/replicas 只暴露份数与时间，不泄露路径或内容', async () => {
    const r = (await req('/api/replicas')).json;
    assert.equal(r.ok, true);
    assert.ok(Array.isArray(r.targets) && r.configured >= 1);
    assert.equal(typeof r.totalBackups, 'number');
    assert.equal(typeof r.lastBackupAt, 'number');
    assert.equal(JSON.stringify(r).includes(DIR), false, '不应泄露服务端数据目录路径');
    assert.match(r.note, /不含路径/);
  });

  await t.test('存在加密备份时 /api/replicas 能正确统计', async () => {
    const repDir = fs.mkdtempSync(path.join(os.tmpdir(), 'jianji-replicas-'));
    const repData = fs.mkdtempSync(path.join(os.tmpdir(), 'jianji-replicas-data-'));
    const p = await freePort();
    const env = { ...process.env, LEDGER_DATA_DIR: repData, LEDGER_BACKUP_DIRS: repDir,
      LEDGER_BACKUP_PASSPHRASE: 'replica-test-pass' };
    fs.writeFileSync(path.join(repData, 'events.jsonl'), '{"t":"identity","fp":"x","ts":1}\n');
    execFileSync(process.execPath, [path.join(ROOT, 'scripts', 'backup-log.mjs')],
      { env, encoding: 'utf8' });
    const proc = launch(repData, p, { LEDGER_BACKUP_DIRS: repDir });
    const base = 'http://127.0.0.1:' + p;
    await waitHealth(base);
    const saved = BASE; BASE = base;
    try {
      const r = (await req('/api/replicas')).json;
      assert.equal(r.configured, 1);
      assert.equal(r.totalBackups, 1);
      assert.ok(r.lastBackupAt > 0);
      assert.equal(r.targets[0].count, 1);
      assert.equal(JSON.stringify(r).includes(repDir), false);
    } finally {
      BASE = saved;
      await stop(proc);
      fs.rmSync(repDir, { recursive: true, force: true });
      fs.rmSync(repData, { recursive: true, force: true });
    }
  });
});
