import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { fileURLToPath } from 'node:url';

const ROOT = path.dirname(fileURLToPath(import.meta.url));
const PUB = path.join(ROOT, 'public');
const DATA = path.join(ROOT, 'data');
const LOG = path.join(DATA, 'events.jsonl');
const PORT = Number(process.env.PORT) || 3000;
const SECRET = crypto.randomBytes(32);
const GENESIS = '0'.repeat(64);

const owners = new Map();
const grants = new Map();
const revoked = new Set();
const challenges = new Map();
const anchors = [];
let anchorHead = GENESIS;
let anchorClock = 0;

const sha = s => crypto.createHash('sha256').update(s).digest('hex');
const b64u = b => Buffer.from(b).toString('base64url');
const clean = s => String(s == null ? '' : s);

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
  if (mac !== want) return null;
  try { const d = JSON.parse(Buffer.from(body, 'base64url').toString()); return d.exp > Date.now() ? d.fp : null; }
  catch (e) { return null; }
}

/* 只追加事件日志：启动时重放，运行期只 append，没有任何改删路径 */
function apply(ev) {
  switch (ev.t) {
    case 'identity':
      if (!owners.has(ev.fp)) owners.set(ev.fp, {
        fp: ev.fp, pubSign: ev.pubSign, pubDh: ev.pubDh, bundle: ev.bundle,
        verifier: ev.verifier, seq: 0, head: GENESIS, chain: [], created: ev.ts
      });
      break;
    case 'entry': {
      const o = owners.get(ev.fp); if (!o) break;
      o.chain.push({ seq: ev.seq, prevHash: ev.prevHash, hash: ev.hash, ts: ev.ts, sig: ev.sig,
        cipher: ev.cipher, bookTag: ev.bookTag });
      o.seq = ev.seq; o.head = ev.hash; o.updated = ev.ts;
      break;
    }
    case 'grant': if (!revoked.has(ev.id)) grants.set(ev.id, ev); break;
    case 'revoke': revoked.add(ev.grantId); grants.delete(ev.grantId); break;
    case 'anchor': anchors.push(ev); anchorHead = ev.hash; anchorClock = Math.max(anchorClock, ev.ts || 0); break;
  }
}
function writeLine(o) { fs.appendFileSync(LOG, JSON.stringify(o) + '\n', 'utf8'); }
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
fs.mkdirSync(DATA, { recursive: true });
if (fs.existsSync(LOG)) {
  for (const line of fs.readFileSync(LOG, 'utf8').split(/\r?\n/)) {
    if (!line.trim()) continue;
    try { apply(JSON.parse(line)); } catch (e) { console.warn('跳过损坏事件行'); }
  }
}
const merkleRoot = () => sha(Array.from(owners.values()).map(o => o.fp + ':' + o.head).sort().join('|'));
const anchorOf = o => ({ fp: o.fp, seq: o.seq, head: o.head, count: o.chain.length, updated: o.updated || o.created });
const publicChain = o => o.chain.map(e => ({ seq: e.seq, prevHash: e.prevHash, hash: e.hash, ts: e.ts, sig: e.sig }));

function send(res, code, obj, type) {
  const body = type === 'text' ? obj : JSON.stringify(obj);
  res.writeHead(code, { 'Content-Type': type === 'text' ? 'text/plain; charset=utf-8' : 'application/json; charset=utf-8',
    'Cache-Control': 'no-store' });
  res.end(body);
}
function body(req) {
  return new Promise((resolve, reject) => {
    let s = '';
    req.on('data', c => { s += c; if (s.length > 2e6) req.destroy(); });
    req.on('end', () => { try { resolve(s ? JSON.parse(s) : {}); } catch (e) { reject(e); } });
    req.on('error', reject);
  });
}
const MIME = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8', '.json': 'application/json; charset=utf-8', '.svg': 'image/svg+xml' };
function serveStatic(req, res, pathname) {
  const rel = pathname === '/' ? 'index.html' : pathname.replace(/^\/+/, '');
  const file = path.resolve(PUB, rel);
  if (!file.startsWith(PUB)) return send(res, 403, { error: 'forbidden' });
  fs.readFile(file, (err, buf) => {
    if (err) return send(res, 404, { error: 'not found' });
    res.writeHead(200, { 'Content-Type': MIME[path.extname(file)] || 'application/octet-stream', 'Cache-Control': 'no-cache' });
    res.end(buf);
  });
}

const server = http.createServer(async (req, res) => {
  const u = new URL(req.url, 'http://localhost');
  const p = u.pathname;
  if (!p.startsWith('/api/')) return serveStatic(req, res, p);
  try {
    const auth = readToken((req.headers.authorization || '').replace(/^Bearer\s+/i, ''));
    const data = req.method === 'POST' ? await body(req) : {};

    /* ---- 公开接口：只有哈希承诺，永不包含密文 ---- */
    if (p === '/api/health' && req.method === 'GET')
      return send(res, 200, { ok: true, version: 2, owners: owners.size,
        entries: Array.from(owners.values()).reduce((s, o) => s + o.chain.length, 0),
        merkleRoot: merkleRoot(), anchorCount: anchors.length, anchorHead });
    if (p === '/api/anchors' && req.method === 'GET')
      return send(res, 200, { merkleRoot: merkleRoot(), owners: Array.from(owners.values()).map(anchorOf),
        anchorHead: anchorHead, anchorCount: anchors.length, recentAnchors: anchors.slice(-6),
        policy: 'append-only / ciphertext-never-public / hash-commitment-only' });
    /* 自包含锚定证明：任何人保存这份文件，日后都能验证服务端有没有回滚历史 */
    if (p === '/api/anchor-proof' && req.method === 'GET')
      return send(res, 200, { version: 2, generatedAt: new Date().toISOString(),
        merkleRoot: merkleRoot(), anchorHead: anchorHead, anchorCount: anchors.length,
        owners: Array.from(owners.values()).map(o => ({ fp:o.fp, seq:o.seq, head:o.head, count:o.chain.length })),
        anchors: anchors, policy: 'append-only anchor chain / no ciphertext published' });
    if (p.startsWith('/api/anchors/') && req.method === 'GET') {
      const o = owners.get(p.slice('/api/anchors/'.length));
      return o ? send(res, 200, Object.assign(anchorOf(o), { chain: publicChain(o), pubSign: o.pubSign }))
        : send(res, 404, { error: 'identity not found' });
    }
    /* 助记词找回：verifier 是高熵哈希，返回的密钥包本身由助记词加密，服务端解不开 */
    if (p === '/api/lookup' && req.method === 'POST') {
      const v = clean(data.verifier);
      const o = Array.from(owners.values()).find(x => x.verifier === v);
      return o ? send(res, 200, { fp: o.fp, bundle: o.bundle, pubSign: o.pubSign, pubDh: o.pubDh })
        : send(res, 404, { error: '没有找到该助记词对应的身份，请检查是否抄写正确' });
    }
    if (p.startsWith('/api/pub/') && req.method === 'GET') {
      const o = owners.get(p.slice('/api/pub/'.length));
      return o ? send(res, 200, { fp: o.fp, pubSign: o.pubSign, pubDh: o.pubDh })
        : send(res, 404, { error: 'identity not found' });
    }
    if (p === '/api/verify' && req.method === 'POST') {
      const chain = Array.isArray(data.chain) ? data.chain : [];
      let prev = GENESIS, broken = -1;
      for (let i = 0; i < chain.length; i++) {
        const e = chain[i];
        if (e.seq !== i + 1 || e.prevHash !== prev || e.hash !== sha([e.seq, e.prevHash, e.fp, e.cipher, e.bookTag, e.ts].join('|'))) { broken = i + 1; break; }
        prev = e.hash;
      }
      if (broken < 0 && data.pubSign && chain.length) {
        const last = chain[chain.length - 1];
        if (!verifySig(data.pubSign, last.hash, last.sig)) broken = chain.length;
      }
      return send(res, 200, { ok: broken < 0, broken, count: chain.length, head: prev });
    }

    /* ---- 挑战应答：私钥签名即登录，服务端只存公钥 ---- */
    if (p === '/api/challenge' && req.method === 'POST') {
      const nonce = crypto.randomBytes(24).toString('base64url');
      challenges.set(nonce, { fp: clean(data.fp), exp: Date.now() + 120000 });
      return send(res, 200, { nonce, exp: 120 });
    }
    if (p === '/api/session' && req.method === 'POST') {
      const c = challenges.get(data.nonce);
      if (!c || c.exp < Date.now()) return send(res, 401, { error: '挑战已过期' });
      if (!data.pubSign || fpOf(data.pubSign) !== clean(data.fp)) return send(res, 400, { error: '公钥与身份指纹不匹配' });
      if (!verifySig(data.pubSign, data.nonce, data.sig)) return send(res, 401, { error: '签名验证失败' });
      challenges.delete(data.nonce);
      let isNew = false;
      if (!owners.has(data.fp)) {
        if (!data.bundle || !data.verifier || !data.pubDh) return send(res, 400, { error: '新身份需要密钥包与校验值' });
        append({ t: 'identity', fp: data.fp, pubSign: data.pubSign, pubDh: data.pubDh,
          bundle: data.bundle, verifier: data.verifier, ts: Date.now() });
        isNew = true;
      } else {
        const o = owners.get(data.fp);
        if (data.verifier && o.verifier && data.verifier !== o.verifier) return send(res, 401, { error: '助记词不匹配该身份' });
        if (fpOf(o.pubSign) !== data.fp) return send(res, 401, { error: '身份公钥不一致' });
      }
      return send(res, 200, { token: signToken(data.fp), fp: data.fp, isNew,
        seq: owners.get(data.fp).seq, head: owners.get(data.fp).head });
    }

    /* ---- 以下均需有效签名会话 ---- */
    if (!auth) return send(res, 401, { error: '需要登录' });
    const me = owners.get(auth);
    if (!me) return send(res, 401, { error: '身份不存在' });

    if (p === '/api/me' && req.method === 'GET')
      return send(res, 200, { fp: me.fp, pubSign: me.pubSign, pubDh: me.pubDh, bundle: me.bundle,
        verifier: me.verifier, seq: me.seq, head: me.head, count: me.chain.length });

    if (p === '/api/entries' && req.method === 'POST') {
      if (data.seq !== me.seq + 1) return send(res, 409, { error: '序号不连续，账本可能已在别处更新' });
      if (data.prevHash !== me.head) return send(res, 409, { error: '前序哈希不匹配' });
      const calc = sha([data.seq, data.prevHash, me.fp, data.cipher, data.bookTag, data.ts].join('|'));
      if (calc !== data.hash) return send(res, 400, { error: '记录哈希不匹配' });
      if (!verifySig(me.pubSign, data.hash, data.sig)) return send(res, 401, { error: '记录签名无效' });
      if (typeof data.cipher !== 'string' || data.cipher.length > 200000) return send(res, 400, { error: '密文格式无效' });
      append({ t: 'entry', fp: me.fp, seq: data.seq, prevHash: data.prevHash, hash: data.hash,
        cipher: data.cipher, sig: data.sig, bookTag: clean(data.bookTag), ts: Number(data.ts) || Date.now() });
      return send(res, 201, { ok: true, seq: me.seq, head: me.head, merkleRoot: merkleRoot() });
    }
    if (p === '/api/entries' && req.method === 'GET')
      return send(res, 200, { entries: me.chain, head: me.head, seq: me.seq });

    if (p === '/api/grants' && req.method === 'POST') {
      if (!owners.has(clean(data.to))) return send(res, 404, { error: '对方身份不存在' });
      if (!data.id || !data.wrappedKey || !data.bookTag) return send(res, 400, { error: '授权参数不完整' });
      append({ t: 'grant', id: clean(data.id), from: me.fp, to: clean(data.to),
        bookTag: clean(data.bookTag), wrappedKey: data.wrappedKey, label: clean(data.label), ts: Date.now() });
      return send(res, 201, { ok: true });
    }
    if (p === '/api/grants' && req.method === 'GET')
      return send(res, 200, { out: Array.from(grants.values()).filter(g => g.from === me.fp),
        in: Array.from(grants.values()).filter(g => g.to === me.fp) });
    if (p === '/api/revoke' && req.method === 'POST') {
      const g = grants.get(clean(data.grantId));
      if (!g || g.from !== me.fp) return send(res, 404, { error: '授权不存在或无权撤销' });
      append({ t: 'revoke', grantId: g.id, fp: me.fp, ts: Date.now() });
      return send(res, 200, { ok: true });
    }
    if (p === '/api/shared' && req.method === 'GET') {
      const mine = Array.from(grants.values()).filter(g => g.to === me.fp);
      const out = [];
      for (const g of mine) {
        const owner = owners.get(g.from); if (!owner) continue;
        out.push({ grantId: g.id, from: g.from, label: g.label, wrappedKey: g.wrappedKey,
          entries: owner.chain.filter(e => e.bookTag === g.bookTag) });
      }
      return send(res, 200, { shared: out });
    }
    return send(res, 404, { error: 'unknown endpoint' });
  } catch (e) {
    return send(res, 400, { error: e.message || 'bad request' });
  }
});

server.listen(PORT, '0.0.0.0', () => console.log('简记联网账本 running on port ' + PORT));
