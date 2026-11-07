import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { fileURLToPath } from 'node:url';

const ROOT = path.dirname(fileURLToPath(import.meta.url));
const PUB = path.join(ROOT, 'public');
const DATA = path.resolve(process.env.LEDGER_DATA_DIR || path.join(ROOT, 'data'));
const LOG = path.join(DATA, 'events.jsonl');
let logFd = null;
const PORT = process.env.PORT === undefined ? 3000 : Number(process.env.PORT);
const SECRET = crypto.randomBytes(32);
const GENESIS = '0'.repeat(64);
const MAX_BODY = 2e6;
const MAX_CIPHER = 200000;
const MAX_PROFILE = 20000;
/* 设置后，只有持邀请码的人才能注册新身份；已存在的身份登录不受影响。 */
const INVITE_CODE = String(process.env.LEDGER_INVITE_CODE || '').trim();
const BACKUP_DIRS = Array.from(new Set(
  (process.env.LEDGER_BACKUP_DIRS || process.env.LEDGER_BACKUP_DIR || path.join(ROOT, 'backups'))
    .split(',').map(s => s.trim()).filter(Boolean).map(s => path.resolve(s))
));
let writeErrors = 0;
let degradedReason = '';

const owners = new Map();
const grants = new Map();
const revoked = new Set();
const challenges = new Map();
const rateBuckets = new Map();
const anchors = [];
let anchorHead = GENESIS;
let anchorClock = 0;

const sha = s => crypto.createHash('sha256').update(s).digest('hex');
const b64u = b => Buffer.from(b).toString('base64url');
const clean = s => String(s == null ? '' : s);
const merkleRoot = () => sha(Array.from(owners.values()).map(o => o.fp + ':' + o.head).sort().join('|'));
function safeEqual(a, b) {
  const x = Buffer.from(String(a)), y = Buffer.from(String(b));
  return x.length === y.length && crypto.timingSafeEqual(x, y);
}
function healthFlags() {
  return { inviteRequired:!!INVITE_CODE, degraded:writeErrors > 0,
    warnings:writeErrors ? [degradedReason] : [],
    logBytes:(() => { try { return fs.statSync(LOG).size; } catch (e) { return 0; } })() };
}
/* 副本状态：只统计份数、体积与时间，不暴露路径或任何账目内容。
   客户端据此提示「此笔此刻只有本机一份」，避免把离线记录误认为已经永存。 */
function replicaInfo() {
  const targets = BACKUP_DIRS.map((dir, i) => {
    let stats = [];
    try {
      stats = fs.readdirSync(dir)
        .filter(f => f.startsWith('jianji-') && f.endsWith('.jsonl.enc'))
        .map(f => { try { return fs.statSync(path.join(dir, f)); } catch (e) { return null; } })
        .filter(Boolean);
    } catch (e) { /* 目标目录尚未创建 */ }
    return { index:i + 1, count:stats.length,
      bytes:stats.reduce((s, x) => s + x.size, 0),
      lastAt:stats.length ? Math.max(...stats.map(x => Math.floor(x.mtimeMs))) : 0 };
  });
  return { ok:true, configured:targets.length, targets,
    totalBackups:targets.reduce((s, t) => s + t.count, 0),
    lastBackupAt:Math.max(0, ...targets.map(t => t.lastAt)),
    logBytes:healthFlags().logBytes, anchors:anchors.length,
    note:'仅含加密备份份数与时间，不含路径、密文或账目内容' };
}

function fpOf(pub) { return sha(clean(pub && pub.x) + '|' + clean(pub && pub.y)).slice(0, 20); }
function verifySig(pubJwk, data, sigB64) {
  try {
    const key = crypto.createPublicKey({ key: pubJwk, format: 'jwk' });
    return crypto.verify('sha256', Buffer.from(data, 'utf8'),
      { key, dsaEncoding: 'ieee-p1363' }, Buffer.from(sigB64, 'base64'));
  } catch (e) { return false; }
}
function signToken(fp) {
  const exp = Date.now() + 12 * 3600 * 1000;
  const body = b64u(JSON.stringify({ fp, exp }));
  return body + '.' + b64u(crypto.createHmac('sha256', SECRET).update(body).digest());
}
function readToken(t) {
  if (!t || t.indexOf('.') < 0) return null;
  const [body, mac] = t.split('.');
  const want = b64u(crypto.createHmac('sha256', SECRET).update(body).digest());
  const got = Buffer.from(mac), expected = Buffer.from(want);
  if (got.length !== expected.length || !crypto.timingSafeEqual(got, expected)) return null;
  try {
    const d = JSON.parse(Buffer.from(body, 'base64url').toString());
    return typeof d.fp === 'string' && d.exp > Date.now() ? d.fp : null;
  } catch (e) { return null; }
}
function rateLimited(key, limit, windowMs) {
  const now = Date.now();
  let bucket = rateBuckets.get(key);
  if (!bucket || now - bucket.start >= windowMs) {
    bucket = { start: now, count: 0 };
    rateBuckets.set(key, bucket);
  }
  bucket.count++;
  if (rateBuckets.size > 2000) {
    for (const [k, v] of rateBuckets) if (now - v.start >= windowMs) rateBuckets.delete(k);
  }
  return bucket.count > limit;
}

/* 只追加事件日志：启动时重放，运行期只 append，没有任何改删路径。
   profile 是「只追加的最新值」：历史版本仍完整留在日志里，内存只保留最后一条。 */
function apply(ev) {
  switch (ev.t) {
    case 'identity':
      if (!owners.has(ev.fp)) owners.set(ev.fp, {
        fp: ev.fp, pubSign: ev.pubSign, pubDh: ev.pubDh, bundle: ev.bundle,
        verifier: ev.verifier, profile: '', byHash: new Map(),
        seq: 0, head: GENESIS, chain: [], created: ev.ts
      });
      break;
    case 'entry': {
      const o = owners.get(ev.fp); if (!o) break;
      o.chain.push({ seq: ev.seq, prevHash: ev.prevHash, hash: ev.hash, ts: ev.ts, sig: ev.sig,
        cipher: ev.cipher, bookTag: ev.bookTag });
      o.byHash.set(ev.hash, Number(ev.seq));
      o.seq = ev.seq; o.head = ev.hash; o.updated = ev.ts;
      break;
    }
    case 'profile': {
      const o = owners.get(ev.fp); if (o) o.profile = clean(ev.profile);
      break;
    }
    case 'grant': if (!revoked.has(ev.id)) grants.set(ev.id, ev); break;
    case 'revoke': revoked.add(ev.grantId); grants.delete(ev.grantId); break;
    case 'anchor': anchors.push(ev); anchorHead = ev.hash; anchorClock = Math.max(anchorClock, ev.ts || 0); break;
  }
}
function writeLine(o) {
  const buf = Buffer.from(JSON.stringify(o) + '\n', 'utf8');
  let offset = 0;
  try {
    while (offset < buf.length) {
      const n = fs.writeSync(logFd, buf, offset, buf.length - offset);
      if (n <= 0) throw new Error('日志写入返回 0 字节');
      offset += n;
    }
  } catch (e) {
    writeErrors++;
    degradedReason = '事件日志写入失败：' + (e.message || '未知错误');
    console.error(degradedReason);
    throw e;
  }
}
/* 每个事件后立刻追加一条锚点：Merkle 根被串进只追加的锚链。
   事后替换整个存储会破坏锚链前缀，任何人用旧锚点即可发现。 */
function append(ev) {
  writeLine(ev); apply(ev);
  anchorClock = Math.max(anchorClock + 1, Date.now());
  const a = { t:'anchor', seq:anchors.length + 1, prevHash:anchorHead,
    root:merkleRoot(), ts:anchorClock, hash:'' };
  a.hash = sha([a.seq, a.prevHash, a.root, a.ts].join('|'));
  writeLine(a); apply(a);
}

/* 重放必须 fail-fast：静默跳过损坏行会让「只追加不可篡改」变成一句空话。
   仅当最后一行被截断（写入中断）且显式设置 LEDGER_ALLOW_TAIL_LOSS=1 时，
   才允许丢弃这一个不完整行，并在启动日志里留下警告。 */
function replay() {
  fs.mkdirSync(DATA, { recursive: true });
  if (!fs.existsSync(LOG)) return;
  const text = fs.readFileSync(LOG, 'utf8');
  const raw = Buffer.from(text, 'utf8');
  const endsWithNewline = raw.length === 0 || raw[raw.length - 1] === 0x0a;
  const lines = text.split(/\r?\n/);
  if (lines.length && lines[lines.length - 1] === '') lines.pop();
  let usable = lines.length;
  if (usable && lines[usable - 1].trim() && !isJsonLine(lines[usable - 1])) {
    if (process.env.LEDGER_ALLOW_TAIL_LOSS !== '1')
      failStartup('事件日志最后一行不完整；如确认只是写入中断，可设置 LEDGER_ALLOW_TAIL_LOSS=1 丢弃该行');
    console.warn('警告：事件日志最后一行不完整，已截断该行后继续（LEDGER_ALLOW_TAIL_LOSS=1）');
    const kept = lines.slice(0, usable - 1);
    fs.truncateSync(LOG, kept.length ? Buffer.byteLength(kept.join('\n') + '\n', 'utf8') : 0);
    usable -= 1;
  } else if (!endsWithNewline && usable && lines[usable - 1].trim()) {
    /* 末行是完整 JSON 只是缺换行：不补的话下一次追加会与它粘成一行，破坏 JSONL。 */
    fs.appendFileSync(LOG, '\n');
    console.warn('警告：事件日志末尾缺少换行，已补写（内容未改动）');
  }
  for (let i = 0; i < usable; i++) {
    if (!lines[i].trim()) continue;
    let ev;
    try { ev = JSON.parse(lines[i]); }
    catch (e) { failStartup('事件日志第 ' + (i + 1) + ' 行不是有效 JSON'); }
    if (!ev || typeof ev.t !== 'string') failStartup('事件日志第 ' + (i + 1) + ' 行缺少事件类型');
    apply(ev);
  }
  let seq = 0, prev = GENESIS;
  for (const a of anchors) {
    seq++;
    if (a.seq !== seq || a.prevHash !== prev ||
        a.hash !== sha([a.seq, a.prevHash, a.root, a.ts].join('|')))
      failStartup('锚链在第 ' + seq + ' 条断开或哈希不匹配');
    prev = a.hash;
  }
  if (prev !== anchorHead) failStartup('锚链头与重放结果不一致');
}
function isJsonLine(line) { try { JSON.parse(line); return true; } catch (e) { return false; } }
function failStartup(msg) {
  console.error('拒绝启动：' + msg);
  console.error('事件日志是账本的唯一权威副本，请先备份 ' + LOG + '，再检查或修复损坏行；' +
    '不要删除中间行，否则锚链校验会继续拒绝启动。');
  process.exit(1);
}
replay();
/* 持久追加描述符：避免每条事件都重新按路径打开文件，仍保持同步写入顺序。 */
logFd = fs.openSync(LOG, 'a');

const anchorOf = o => ({ fp: o.fp, seq: o.seq, head: o.head, count: o.chain.length, updated: o.updated || o.created });
const publicChain = o => o.chain.map(e => ({ seq: e.seq, prevHash: e.prevHash, hash: e.hash, ts: e.ts, sig: e.sig }));
const ownedEntries = o => o.chain.map(e => Object.assign({ fp: o.fp }, e));

function appendEntry(me, data) {
  const ts = Number(data.ts);
  if (!Number.isInteger(ts) || ts <= 0) return { status:'error', code:400, error:'记录时间戳无效' };
  if (typeof data.cipher !== 'string' || !data.cipher || data.cipher.length > MAX_CIPHER)
    return { status:'error', code:400, error:'密文格式无效' };
  if (typeof data.hash !== 'string' || data.hash.length !== 64)
    return { status:'error', code:400, error:'记录哈希格式无效' };
  const knownSeq = me.byHash.get(data.hash);
  if (knownSeq !== undefined) return { status:'existing', seq: knownSeq, hash: data.hash };
  if (data.seq !== me.seq + 1) return { status:'error', code:409, error:'序号不连续，账本可能已在别处更新' };
  if (data.prevHash !== me.head) return { status:'error', code:409, error:'前序哈希不匹配，检测到账本分叉' };
  const calc = sha([data.seq, data.prevHash, me.fp, data.cipher, data.bookTag, ts].join('|'));
  if (calc !== data.hash) return { status:'error', code:400, error:'记录哈希不匹配' };
  if (!verifySig(me.pubSign, data.hash, data.sig)) return { status:'error', code:401, error:'记录签名无效' };
  append({ t:'entry', fp:me.fp, seq:data.seq, prevHash:data.prevHash, hash:data.hash,
    cipher:data.cipher, sig:data.sig, bookTag:clean(data.bookTag), ts });
  return { status:'accepted', seq:me.seq, hash:data.hash };
}

/* 生产安全头。script-src 严格限同源（内联脚本已外置），connect-src 允许任意 HTTPS
   是为了公开验证页能读取用户指定的 GitHub Raw 锚点地址。 */
function applySecurityHeaders(req, res) {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('Referrer-Policy', 'no-referrer');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
  res.setHeader('Content-Security-Policy',
    "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; " +
    "img-src 'self' data:; connect-src 'self' https:; font-src 'self'; " +
    "object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'");
  if (req.headers['x-forwarded-proto'] === 'https' || process.env.LEDGER_TRUST_PROXY === '1')
    res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
}
function send(res, code, obj, type) {
  if (res.destroyed || res.writableEnded) return;
  const body = type === 'text' ? obj : JSON.stringify(obj);
  res.writeHead(code, { 'Content-Type': type === 'text' ? 'text/plain; charset=utf-8' : 'application/json; charset=utf-8',
    'Cache-Control': 'no-store' });
  res.end(body);
}
function body(req) {
  return new Promise((resolve, reject) => {
    let s = '', settled = false;
    const done = (err, value) => { if (settled) return; settled = true; err ? reject(err) : resolve(value); };
    req.on('data', c => {
      if (settled) return;
      s += c;
      if (s.length > MAX_BODY) { done(new Error('请求体超过 2 MB')); req.destroy(); }
    });
    req.on('end', () => {
      if (settled) return;
      try { done(null, s ? JSON.parse(s) : {}); } catch (e) { done(e); }
    });
    req.on('error', e => done(e));
    req.on('aborted', () => done(new Error('请求被中断')));
  });
}
const MIME = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8',
  '.cjs': 'text/javascript; charset=utf-8', '.css': 'text/css; charset=utf-8',
  '.json': 'application/json; charset=utf-8', '.svg': 'image/svg+xml',
  '.webmanifest': 'application/manifest+json; charset=utf-8', '.png': 'image/png' };
function serveStatic(req, res, pathname) {
  const rel = pathname === '/' ? 'index.html' : pathname.replace(/^\/+/, '');
  const file = path.resolve(PUB, rel);
  if (file !== PUB && !file.startsWith(PUB + path.sep)) return send(res, 403, { error:'forbidden' });
  fs.readFile(file, (err, buf) => {
    if (err) return send(res, 404, { error:'not found' });
    res.writeHead(200, { 'Content-Type': MIME[path.extname(file)] || 'application/octet-stream', 'Cache-Control':'no-cache' });
    res.end(buf);
  });
}

const server = http.createServer(async (req, res) => {
  applySecurityHeaders(req, res);
  const u = new URL(req.url, 'http://localhost');
  const p = u.pathname;
  if (!p.startsWith('/api/')) return serveStatic(req, res, p);
  try {
    const ip = req.socket.remoteAddress || 'unknown';
    const auth = readToken((req.headers.authorization || '').replace(/^Bearer\s+/i, ''));
    const data = req.method === 'POST' ? await body(req) : {};

    /* ---- 公开接口：只有哈希承诺，永不包含密文 ---- */
    if (p === '/api/health' && req.method === 'GET')
      return send(res, 200, Object.assign({ ok:true, version:3, owners:owners.size,
        entries:Array.from(owners.values()).reduce((s, o) => s + o.chain.length, 0),
        merkleRoot:merkleRoot(), anchorCount:anchors.length, anchorHead }, healthFlags()));
    /* 轻量探测：客户端每 30 秒只取这一份约 200 字节的摘要，没变化就不必拉全量账本。 */
    if (p === '/api/status' && req.method === 'GET')
      return send(res, 200, Object.assign({ ok:true, anchorHead, anchorCount:anchors.length, merkleRoot:merkleRoot(),
        heads:Array.from(owners.values()).map(o => ({ fp:o.fp, seq:o.seq, head:o.head, count:o.chain.length })),
        grantsVersion:grants.size + revoked.size }, healthFlags()));
    if (p === '/api/replicas' && req.method === 'GET')
      return send(res, 200, replicaInfo());
    if (p === '/api/anchors' && req.method === 'GET')
      return send(res, 200, { merkleRoot:merkleRoot(), owners:Array.from(owners.values()).map(anchorOf),
        anchorHead, anchorCount:anchors.length, recentAnchors:anchors.slice(-6),
        policy:'append-only / ciphertext-never-public / hash-commitment-only' });
    if (p === '/api/anchor-proof' && req.method === 'GET')
      return send(res, 200, { version:2, generatedAt:new Date().toISOString(),
        merkleRoot:merkleRoot(), anchorHead, anchorCount:anchors.length,
        owners:Array.from(owners.values()).map(o => ({ fp:o.fp, seq:o.seq, head:o.head, count:o.chain.length })),
        anchors, policy:'append-only anchor chain / no ciphertext published' });
    if (p.startsWith('/api/anchors/') && req.method === 'GET') {
      const o = owners.get(p.slice('/api/anchors/'.length));
      return o ? send(res, 200, Object.assign(anchorOf(o), { chain:publicChain(o), pubSign:o.pubSign }))
        : send(res, 404, { error:'identity not found' });
    }
    /* 助记词找回：verifier 是高熵哈希；bundle 与 profile 都由助记词加密，服务端解不开。 */
    if (p === '/api/lookup' && req.method === 'POST') {
      const v = clean(data.verifier);
      const o = Array.from(owners.values()).find(x => x.verifier === v);
      return o ? send(res, 200, { fp:o.fp, bundle:o.bundle, pubSign:o.pubSign, pubDh:o.pubDh, profile:o.profile || '' })
        : send(res, 404, { error:'没有找到该助记词对应的身份，请检查是否抄写正确' });
    }
    if (p.startsWith('/api/pub/') && req.method === 'GET') {
      const o = owners.get(p.slice('/api/pub/'.length));
      return o ? send(res, 200, { fp:o.fp, pubSign:o.pubSign, pubDh:o.pubDh })
        : send(res, 404, { error:'identity not found' });
    }
    /* 辅助校验：绑定已注册身份，用服务端的 fp 与公钥逐条重算并验签；
       调用方需提供含 fp、cipher、bookTag、ts、sig 的完整链（GET /api/entries 的返回即可）。 */
    if (p === '/api/verify' && req.method === 'POST') {
      const o = owners.get(clean(data.fp));
      if (!o) return send(res, 404, { error:'身份不存在，无法对未登记的历史出具校验结论' });
      const chain = Array.isArray(data.chain) ? data.chain : [];
      let prev = GENESIS, broken = -1;
      for (let i = 0; i < chain.length; i++) {
        const e = chain[i];
        const calc = sha([e.seq, e.prevHash, o.fp, e.cipher, e.bookTag, e.ts].join('|'));
        if (e.seq !== i + 1 || e.prevHash !== prev || e.hash !== calc ||
            !verifySig(o.pubSign, e.hash, e.sig)) { broken = i + 1; break; }
        prev = e.hash;
      }
      const headOk = prev === o.head, lengthOk = chain.length === o.seq;
      return send(res, 200, { ok:broken < 0 && headOk && lengthOk, broken,
        count:chain.length, head:prev, expectedHead:o.head, headOk, lengthOk });
    }

    /* ---- 挑战应答：私钥签名即登录，服务端只存公钥 ---- */
    if (p === '/api/challenge' && req.method === 'POST') {
      if (rateLimited('challenge:' + ip, 60, 60000)) return send(res, 429, { error:'请求过于频繁，请稍后再试' });
      const now = Date.now();
      for (const [k, v] of challenges) if (v.exp < now) challenges.delete(k);
      if (challenges.size > 5000) return send(res, 429, { error:'待处理挑战过多，请稍后再试' });
      const nonce = crypto.randomBytes(24).toString('base64url');
      challenges.set(nonce, { fp:clean(data.fp), exp:now + 120000 });
      return send(res, 200, { nonce, exp:120 });
    }
    if (p === '/api/session' && req.method === 'POST') {
      if (rateLimited('session:' + ip, 60, 60000)) return send(res, 429, { error:'请求过于频繁，请稍后再试' });
      const c = challenges.get(data.nonce);
      if (!c || c.exp < Date.now()) return send(res, 401, { error:'挑战已过期' });
      if (clean(c.fp) !== clean(data.fp)) return send(res, 400, { error:'挑战绑定的身份与请求不一致' });
      if (!data.pubSign || fpOf(data.pubSign) !== clean(data.fp)) return send(res, 400, { error:'公钥与身份指纹不匹配' });
      if (!verifySig(data.pubSign, data.nonce, data.sig)) return send(res, 401, { error:'签名验证失败' });
      challenges.delete(data.nonce);
      let isNew = false;
      if (!owners.has(data.fp)) {
        if (INVITE_CODE && !safeEqual(clean(data.inviteCode), INVITE_CODE))
          return send(res, 403, { error:'需要有效的邀请码才能创建身份' });
        if (!data.bundle || !data.verifier || !data.pubDh) return send(res, 400, { error:'新身份需要密钥包与校验值' });
        append({ t:'identity', fp:data.fp, pubSign:data.pubSign, pubDh:data.pubDh,
          bundle:data.bundle, verifier:data.verifier, ts:Date.now() });
        isNew = true;
      } else {
        const o = owners.get(data.fp);
        if (data.verifier && o.verifier && data.verifier !== o.verifier) return send(res, 401, { error:'助记词不匹配该身份' });
        if (fpOf(o.pubSign) !== data.fp) return send(res, 401, { error:'身份公钥不一致' });
      }
      return send(res, 200, { token:signToken(data.fp), fp:data.fp, isNew,
        seq:owners.get(data.fp).seq, head:owners.get(data.fp).head });
    }

    /* ---- 以下均需有效签名会话 ---- */
    if (!auth) return send(res, 401, { error:'需要登录' });
    const me = owners.get(auth);
    if (!me) return send(res, 401, { error:'身份不存在' });

    if (p === '/api/me' && req.method === 'GET')
      return send(res, 200, { fp:me.fp, pubSign:me.pubSign, pubDh:me.pubDh, bundle:me.bundle,
        verifier:me.verifier, profile:me.profile || '', seq:me.seq, head:me.head, count:me.chain.length });

    /* 加密账本目录随身份走：换设备后仍能派生出原有账本密钥。profile 只追加，不覆盖历史。 */
    if (p === '/api/profile' && req.method === 'POST') {
      if (typeof data.profile !== 'string' || data.profile.length > MAX_PROFILE)
        return send(res, 400, { error:'加密账本目录格式无效' });
      if (data.profile === me.profile) return send(res, 200, { ok:true, unchanged:true });
      append({ t:'profile', fp:me.fp, profile:data.profile, ts:Date.now() });
      return send(res, 200, { ok:true });
    }

    if (p === '/api/entries' && req.method === 'POST') {
      const result = appendEntry(me, data);
      if (result.status === 'error') return send(res, result.code, { error:result.error });
      return send(res, result.status === 'accepted' ? 201 : 200,
        { ok:true, existing:result.status === 'existing', seq:me.seq, head:me.head, merkleRoot:merkleRoot() });
    }
    /* 离线队列批量恢复：逐条校验、顺序追加；hash 已存在则幂等确认。
       中途遇到分叉时返回已经处理的结果，客户端可安全落盘后再暂停。 */
    if (p === '/api/entries/sync' && req.method === 'POST') {
      if (!Array.isArray(data.entries) || data.entries.length < 1 || data.entries.length > 50)
        return send(res, 400, { error:'同步批次应包含 1–50 条记录' });
      const results = [];
      for (const entry of data.entries) {
        const result = appendEntry(me, entry);
        if (result.status === 'error')
          return send(res, result.code, { error:result.error, results, seq:me.seq, head:me.head, conflict:result.code === 409 });
        results.push(result);
      }
      return send(res, 200, { ok:true, results, seq:me.seq, head:me.head, merkleRoot:merkleRoot() });
    }
    /* since = 本机已有的条数，只返回之后的连续后缀，避免每轮全量重传密文。 */
    if (p === '/api/entries' && req.method === 'GET') {
      const raw = Number(u.searchParams.get('since'));
      const since = Number.isInteger(raw) && raw >= 0 ? Math.min(raw, me.chain.length) : 0;
      const all = ownedEntries(me);
      return send(res, 200, { entries:all.slice(since), head:me.head, seq:me.seq, since });
    }

    if (p === '/api/grants' && req.method === 'POST') {
      if (!owners.has(clean(data.to))) return send(res, 404, { error:'对方身份不存在' });
      if (!data.id || !data.wrappedKey || !data.bookTag) return send(res, 400, { error:'授权参数不完整' });
      if (typeof data.wrappedKey !== 'string' || data.wrappedKey.length > 20000 ||
          typeof data.id !== 'string' || data.id.length > 120)
        return send(res, 400, { error:'授权参数超长' });
      append({ t:'grant', id:clean(data.id), from:me.fp, to:clean(data.to),
        bookTag:clean(data.bookTag), wrappedKey:data.wrappedKey, label:clean(data.label), ts:Date.now() });
      return send(res, 201, { ok:true });
    }
    if (p === '/api/grants' && req.method === 'GET')
      return send(res, 200, { out:Array.from(grants.values()).filter(g => g.from === me.fp),
        in:Array.from(grants.values()).filter(g => g.to === me.fp) });
    if (p === '/api/revoke' && req.method === 'POST') {
      const g = grants.get(clean(data.grantId));
      if (!g || g.from !== me.fp) return send(res, 404, { error:'授权不存在或无权撤销' });
      append({ t:'revoke', grantId:g.id, fp:me.fp, ts:Date.now() });
      return send(res, 200, { ok:true });
    }
    if (p === '/api/shared' && req.method === 'GET') {
      const mine = Array.from(grants.values()).filter(g => g.to === me.fp);
      const out = [];
      for (const g of mine) {
        const owner = owners.get(g.from); if (!owner) continue;
        out.push({ grantId:g.id, from:g.from, label:g.label, wrappedKey:g.wrappedKey,
          entries:owner.chain.filter(e => e.bookTag === g.bookTag) });
      }
      return send(res, 200, { shared:out });
    }
    return send(res, 404, { error:'unknown endpoint' });
  } catch (e) {
    return send(res, 400, { error:e.message || 'bad request' });
  }
});

server.listen(PORT, process.env.HOST || '127.0.0.1', () =>
  console.log('简记联网账本 running on ' + (process.env.HOST || '127.0.0.1') + ':' + server.address().port));
