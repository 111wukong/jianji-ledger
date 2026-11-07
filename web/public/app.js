'use strict';
/* 简记 · 离线优先的统一不可变账本。
   明文只在当前页面内存中出现；IndexedDB 与服务端都只保存密文、签名和哈希。 */

const WORDS = `abandon ability able about above absent absorb abstract absurd abuse access accident account accuse achieve
acid acoustic acquire across act action actor actress actual adapt add addict address adjust admit
adult advance advice affair afford afraid again age agent agree ahead aim air airport aisle
alarm album alcohol alert alien all alley allow almost alone alpha already also alter always
amateur amazing among amount amused analyst anchor ancient anger angle angry animal ankle announce
annual another answer antique anxiety any apart apology appear apple approve april arch arctic
area arena argue arm armed armor army around arrange arrest arrive arrow art artist artwork
aspect asset assist assume asthma athlete atom attack attend attitude attract auction audit august
aunt author auto autumn average avocado avoid awake aware awesome awful awkward axis baby
bachelor bacon badge bag balance balcony ball bamboo banana banner bar barely bargain barrel
base basic basket battle beach bean beauty because become beef before begin behave behind
believe below belt bench benefit best betray better between beyond bicycle bid bike bind
biology bird birth bitter black blade blame blanket blast bleak bless blind blood blossom
blouse blue blur blush board boat body boil bomb bone bonus book boost border boring
borrow boss bottom bounce box boy bracket brain brand brass brave bread breeze brick
bridge brief bright bring brisk broccoli broken bronze broom brother brown brush bubble buddy
cabin cable cactus cage cake calm camera camp canal cancel candy cannon canoe canvas canyon capable capital captain car carbon card cargo carpet carry cart`.trim().split(/\s+/);

const $ = (s, r = document) => r.querySelector(s);
const $$ = (s, r = document) => Array.from(r.querySelectorAll(s));
const enc = s => new TextEncoder().encode(String(s));
const dec = b => new TextDecoder().decode(b);
const esc = s => String(s == null ? '' : s).replace(/[&<>"']/g, c => ({ '&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;' }[c]));
const uid = () => Date.now().toString(36) + Math.random().toString(36).slice(2, 8);
const today = () => { const d = new Date(); return d.getFullYear() + '-' + String(d.getMonth()+1).padStart(2,'0') + '-' + String(d.getDate()).padStart(2,'0'); };
const fmt = c => '¥' + (Number(c || 0) / 100).toLocaleString('zh-CN', { minimumFractionDigits: 2, maximumFractionDigits: 2 });
const shortHash = (s, n) => esc(String(s || '').slice(0, n || 14));
const GENESIS = '0'.repeat(64);
function b64(buf) { const a = new Uint8Array(buf); let s = ''; for (let i = 0; i < a.length; i++) s += String.fromCharCode(a[i]); return btoa(s); }
function unb64(s) { return Uint8Array.from(atob(s), c => c.charCodeAt(0)); }
const subtle = () => crypto.subtle;
async function sha256hex(s) { const d = await subtle().digest('SHA-256', enc(s)); return Array.from(new Uint8Array(d), x => x.toString(16).padStart(2,'0')).join(''); }
async function aesKey(raw, usages, extractable) { return subtle().importKey('raw', raw, 'AES-GCM', !!extractable, usages || ['encrypt','decrypt']); }
async function aesEnc(key, obj) {
  const raw = enc(JSON.stringify(obj)), block = 512;
  const pad = block - (raw.length % block);
  const buf = new Uint8Array(raw.length + pad);
  buf.set(raw); buf.fill(32, raw.length);
  return aesEncRaw(key, buf);
}
async function aesDec(key, str) { return JSON.parse(dec(await aesDecRaw(key, str))); }
async function aesEncRaw(key, bytes) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await subtle().encrypt({ name:'AES-GCM', iv }, key, bytes);
  const out = new Uint8Array(iv.length + ct.byteLength); out.set(iv); out.set(new Uint8Array(ct), iv.length);
  return b64(out);
}
async function aesDecRaw(key, str) {
  const a = unb64(str);
  return new Uint8Array(await subtle().decrypt({ name:'AES-GCM', iv:a.slice(0,12) }, key, a.slice(12)));
}
const SIG_ALG = { name:'ECDSA', namedCurve:'P-256' };
const DH_ALG = { name:'ECDH', namedCurve:'P-256' };
const importSignPriv = id => subtle().importKey('jwk', id.priv.sign, SIG_ALG, false, ['sign']);
const importDhPriv = id => subtle().importKey('jwk', id.priv.dh, DH_ALG, false, ['deriveBits']);
const importDhPub = jwk => subtle().importKey('jwk', jwk, DH_ALG, false, []);
const importSignPub = jwk => subtle().importKey('jwk', jwk, SIG_ALG, false, ['verify']);

async function derive(mnemonic) {
  const base = await subtle().importKey('raw', enc(mnemonic), 'HKDF', false, ['deriveBits']);
  const bits = await subtle().deriveBits({ name:'HKDF', hash:'SHA-256', salt:enc('jianji.cloud.v1'), info:enc('master-keys') }, base, 512);
  const master = await aesKey(new Uint8Array(bits, 0, 32), ['encrypt','decrypt']);
  const hkBase = await subtle().importKey('raw', new Uint8Array(bits, 32, 32), 'HKDF', false, ['deriveKey']);
  return { mnemonic, master, hkBase, verifier: await sha256hex('jianji-verifier|' + mnemonic) };
}
async function bookKey(id, book) {
  return subtle().deriveKey({ name:'HKDF', hash:'SHA-256', salt:enc('jianji-book'), info:enc('book|' + book) },
    id.keys.hkBase, { name:'AES-GCM', length:256 }, true, ['encrypt','decrypt']);
}
const bookTag = (id, book) => sha256hex('jianji-tag|' + id.keys.mnemonic + '|' + book).then(h => h.slice(0,24));
function newMnemonic() {
  const b = crypto.getRandomValues(new Uint8Array(16));
  return Array.from(b, x => WORDS[x % WORDS.length]).join(' ');
}
function normMnemonic(s) { return String(s || '').trim().toLowerCase().replace(/\s+/g, ' '); }
async function createIdentity(m) {
  const keys = await derive(m);
  const sp = await subtle().generateKey(SIG_ALG, true, ['sign','verify']);
  const dp = await subtle().generateKey(DH_ALG, true, ['deriveBits']);
  const pubSign = await subtle().exportKey('jwk', sp.publicKey);
  const pubDh = await subtle().exportKey('jwk', dp.publicKey);
  const priv = { sign: await subtle().exportKey('jwk', sp.privateKey), dh: await subtle().exportKey('jwk', dp.privateKey) };
  const bundle = await aesEnc(keys.master, priv);
  return { keys, pubSign, pubDh, priv, bundle, fp: (await sha256hex(pubSign.x + '|' + pubSign.y)).slice(0,20) };
}
const ID_CACHE = 'jianji.identity.v1';
function cacheIdentity(id) {
  try { localStorage.setItem(ID_CACHE, JSON.stringify({ verifier:id.keys.verifier, bundle:id.bundle,
    fp:id.fp, pubSign:id.pubSign, pubDh:id.pubDh })); } catch (e) {}
}
function cachedIdentity() { try { return JSON.parse(localStorage.getItem(ID_CACHE) || 'null'); } catch (e) { return null; } }
async function restoreIdentity(m) {
  const keys = await derive(m);
  let r = null;
  try { r = await api('/api/lookup', 'POST', { verifier: keys.verifier }, false); }
  catch (e) {
    const c = cachedIdentity();
    if (!c || c.verifier !== keys.verifier)
      throw new Error(e.network ? '离线恢复需要使用这台设备保存过的身份；也可以先导入加密账本备份' : '没有找到该助记词对应的身份：请检查抄写，或先导入之前导出的加密账本文件');
    r = c;
  }
  let priv;
  try { priv = await aesDec(keys.master, r.bundle); }
  catch (e) { throw new Error('助记词无法解开该身份的密钥包，请检查抄写是否正确'); }
  return { keys, pubSign:r.pubSign, pubDh:r.pubDh, priv, bundle:r.bundle, fp:r.fp };
}
async function login(id) {
  const c = await api('/api/challenge', 'POST', { fp: id.fp }, false);
  const sig = b64(await subtle().sign({ name:'ECDSA', hash:'SHA-256' }, await importSignPriv(id), enc(c.nonce)));
  return api('/api/session', 'POST', { fp:id.fp, pubSign:id.pubSign, pubDh:id.pubDh,
    nonce:c.nonce, sig, bundle:id.bundle, verifier:id.keys.verifier }, false);
}

let TOKEN = '';
const ST = {
  id:null, me:{ seq:0, head:GENESIS }, entries:[], outbox:[], plain:[], tab:'overview', book:'个人账',
  books:['个人账','公司资金'], mode:'create', tmp:null, anchors:null, proof:null, grants:null, shared:null,
  filter:{ text:'', book:'all', status:'all' }, writing:false, syncing:false, syncAgain:false,
  sync:{ online:navigator.onLine, status:navigator.onLine ? 'idle' : 'offline', error:'', conflict:'', lastSync:0 }
};

async function api(path, method, data, noAuth) {
  const headers = { 'Content-Type':'application/json' };
  if (!noAuth && TOKEN) headers.Authorization = 'Bearer ' + TOKEN;
  let r;
  try {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 15000);
    try { r = await fetch(path, { method:method || 'GET', headers, body:data ? JSON.stringify(data) : undefined, signal:controller.signal }); }
    finally { clearTimeout(timer); }
  } catch (e) {
    ST.sync.online = false; ST.sync.status = 'offline'; paintSync();
    const err = new Error('当前无法连接服务端，账目仍会安全保存在本机'); err.network = true; throw err;
  }
  let j; try { j = await r.json(); } catch (e) { throw new Error('服务端返回异常'); }
  if (!r.ok) { const err = new Error(j.error || ('HTTP ' + r.status)); err.status = r.status; err.data = j; throw err; }
  ST.sync.online = true;
  return j;
}
async function ensureSession() {
  if (!ST.id) throw new Error('请先恢复身份');
  if (TOKEN) return;
  const r = await login(ST.id); TOKEN = r.token;
}
async function authed(path, method, data) {
  await ensureSession();
  try { return await api(path, method, data); }
  catch (err) {
    if (err.status !== 401) throw err;
    TOKEN = ''; await ensureSession();
    return api(path, method, data);
  }
}

function toast(msg, kind) {
  const el = $('#toast'); if (!el) return;
  el.textContent = msg; el.className = 'toast show' + (kind === 'err' ? ' err' : kind === 'warn' ? ' warn' : '');
  clearTimeout(toast._t); toast._t = setTimeout(() => el.className = 'toast', 4200);
}
function modal(html) {
  const d = document.createElement('div'); d.className = 'modal-bg';
  d.innerHTML = '<div class="modal" role="dialog" aria-modal="true">' + html + '</div>';
  d.addEventListener('click', e => { if (e.target === d || e.target.dataset.act === 'close-modal') d.remove(); });
  document.body.appendChild(d); return d;
}
async function copy(text) { try { await navigator.clipboard.writeText(text); toast('已复制'); } catch (e) { toast('复制失败，请手动选中', 'err'); } }
function downloadJSON(obj, filename) {
  const blob = new Blob([JSON.stringify(obj, null, 2)], { type:'application/json' });
  const a = document.createElement('a'); a.href = URL.createObjectURL(blob); a.download = filename;
  document.body.appendChild(a); a.click(); a.remove(); setTimeout(() => URL.revokeObjectURL(a.href), 800);
}
function savedAnchors() { try { return JSON.parse(localStorage.getItem('jianji.anchors.v1') || '[]'); } catch (e) { return []; } }
function writeSavedAnchors(a) { try { localStorage.setItem('jianji.anchors.v1', JSON.stringify(a)); } catch (e) {} }

function syncLabel() {
  if (ST.syncing) return '正在同步';
  if (ST.sync.conflict) return '同步已暂停';
  if (!navigator.onLine || !ST.sync.online || ST.sync.status === 'offline') return '离线可用';
  if (ST.sync.status === 'error') return '同步待重试';
  if (ST.outbox.length) return ST.outbox.length + ' 笔待同步';
  return ST.sync.lastSync ? '已同步' : '已连接';
}
function syncKind() {
  if (ST.sync.conflict || ST.sync.status === 'error') return 'bad';
  if (ST.syncing) return 'working';
  if (!navigator.onLine || !ST.sync.online || ST.outbox.length) return 'pending';
  return 'good';
}
function paintSync() {
  $$('[data-sync-label]').forEach(el => { el.textContent = syncLabel(); });
  $$('[data-sync-dot]').forEach(el => { el.className = 'status-dot ' + syncKind(); });
  $$('[data-pending-count]').forEach(el => { el.textContent = String(ST.outbox.length); });
}
async function refreshLocal() {
  if (!ST.id) return;
  const rows = await LedgerStore.all(ST.id.fp);
  ST.entries = rows;
  ST.outbox = rows.filter(r => r.pending).map(r => r.entry).sort((a,b) => a.seq - b.seq);
  const ordered = rows.map(r => r.entry).sort((a,b) => a.seq - b.seq);
  const last = ordered[ordered.length - 1];
  ST.me = { fp:ST.id.fp, seq:last ? Number(last.seq) : 0, head:last ? last.hash : GENESIS };
  const tagMap = {};
  for (const b of ST.books) tagMap[await bookTag(ST.id, b)] = b;
  const pendingHashes = new Set(ST.outbox.map(e => e.hash));
  const plain = [];
  for (const row of rows) {
    const e = row.entry, b = tagMap[e.bookTag]; if (!b) continue;
    try {
      const p = await aesDec(await bookKey(ST.id, b), e.cipher);
      plain.push(Object.assign({}, p, { seq:e.seq, hash:e.hash, prevHash:e.prevHash, book:b, pending:pendingHashes.has(e.hash) }));
    } catch (err) { /* 其他账本或损坏记录不暴露明文，也不阻塞可用记录 */ }
  }
  ST.plain = plain.sort((a,b) => a.seq - b.seq);
  paintSync();
}
async function startIdentity(id) {
  ST.id = id; TOKEN = ''; ST.tmp = null; ST.anchors = null; ST.proof = null; ST.grants = null; ST.shared = null;
  ST.sync.conflict = ''; ST.sync.error = ''; ST.tab = 'overview';
  cacheIdentity(id);
  ST.books = await LedgerStore.getMeta('books:' + id.fp, ['个人账','公司资金']);
  if (!ST.books.includes(ST.book)) ST.book = ST.books[0];
  ST.sync.lastSync = await LedgerStore.getMeta('lastSync:' + id.fp, 0);
  await refreshLocal(); render();
  if (navigator.storage && navigator.storage.persist) navigator.storage.persist().catch(() => {});
  synchronize();
}
async function adoptServer(serverEntries) {
  const cachedSynced = ST.entries.filter(r => !r.pending).map(r => r.entry);
  const prefix = SyncCore.prefixProblem(cachedSynced, serverEntries);
  if (prefix) {
    const err = new Error('服务端历史与本机已确认前缀不一致，已停止同步，请先导出本机密文备份'); err.conflict = true; throw err;
  }
  const plan = SyncCore.assessOutbox(serverEntries, ST.outbox);
  if (plan.conflict) {
    const err = new Error('检测到另一段账本历史：另一台设备可能已离线记账。为保护只追加历史，系统不会自动覆盖或合并'); err.conflict = true; err.detail = plan.conflict; throw err;
  }
  for (const e of plan.existing) await LedgerStore.markSynced(ST.id.fp, e);
  await LedgerStore.replaceSynced(ST.id.fp, serverEntries);
  return plan.pending;
}
async function applySyncResults(results) {
  for (const result of results || []) {
    if (result.status !== 'accepted' && result.status !== 'existing') continue;
    const entry = ST.outbox.find(e => e.hash === result.hash);
    if (entry) await LedgerStore.markSynced(ST.id.fp, entry);
  }
  if (results && results.length) await refreshLocal();
}
async function refreshAncillary() {
  try {
    const [anchors, proof, grants, shared] = await Promise.all([
      api('/api/anchors', 'GET', null, false), api('/api/anchor-proof', 'GET', null, false),
      authed('/api/grants', 'GET'), authed('/api/shared', 'GET')
    ]);
    ST.anchors = anchors; ST.proof = proof; ST.grants = grants; ST.shared = shared.shared;
  } catch (e) { /* 核心账目已同步时，辅助信息失败不反向标记为失败 */ }
}
async function synchronize() {
  if (!ST.id) return;
  if (ST.syncing) { ST.syncAgain = true; return; }
  if (!navigator.onLine) { ST.sync.online = false; ST.sync.status = 'offline'; paintSync(); return; }
  ST.syncing = true; ST.syncAgain = false; ST.sync.status = 'syncing'; ST.sync.error = ''; paintSync();
  try {
    for (let guard = 0; guard < 20; guard++) {
      await refreshLocal();
      const r = await authed('/api/entries', 'GET');
      const pending = await adoptServer(r.entries);
      await refreshLocal();
      if (!pending.length) break;
      const plan = SyncCore.uploadBatch(r.entries, ST.outbox, 50);
      if (plan.conflict) { const err = new Error('离线队列与服务端历史不连续，同步已暂停'); err.conflict = true; throw err; }
      if (!plan.batch.length) break;
      try { await authed('/api/entries/sync', 'POST', { entries:plan.batch }); }
      catch (err) { if (err.data && err.data.results) await applySyncResults(err.data.results); throw err; }
      await refreshLocal();
    }
    await refreshAncillary();
    await refreshLocal();
    ST.sync.online = true; ST.sync.conflict = ''; ST.sync.status = ST.outbox.length ? 'idle' : 'synced';
    ST.sync.lastSync = Date.now();
    await LedgerStore.setMeta('lastSync:' + ST.id.fp, ST.sync.lastSync);
  } catch (err) {
    if (err.conflict || (err.data && err.data.conflict)) {
      ST.sync.conflict = err.message; ST.sync.status = 'conflict';
    } else if (err.network || !navigator.onLine) {
      ST.sync.online = false; ST.sync.status = 'offline';
    } else {
      ST.sync.error = err.message; ST.sync.status = 'error';
    }
  } finally {
    ST.syncing = false;
    try { await refreshLocal(); } catch (e) { ST.sync.error = e.message; }
    render();
    if (ST.syncAgain && navigator.onLine && !ST.sync.conflict) { ST.syncAgain = false; setTimeout(synchronize, 120); }
  }
}

async function addEntry(preset) {
  if (ST.writing || !ST.id) return;
  ST.writing = true;
  try {
    let plain;
    if (preset) plain = preset;
    else {
      const amount = Math.round(Number(String($('#f-amount').value).replace(/[^\d.]/g,'')) * 100);
      if (!amount || amount <= 0) throw new Error('请输入有效金额');
      plain = { type:$('#f-type').value, amount, book:$('#f-book').value, date:$('#f-date').value || today(),
        note:$('#f-note').value.trim(), party:$('#f-party').value.trim(), voucher:$('#f-voucher').value.trim() };
    }
    await refreshLocal();
    const book = plain.book;
    const cipher = await aesEnc(await bookKey(ST.id, book), plain);
    const tag = await bookTag(ST.id, book);
    const seq = ST.me.seq + 1, prevHash = ST.me.head, ts = Date.now();
    const hash = await sha256hex([seq, prevHash, ST.id.fp, cipher, tag, ts].join('|'));
    const sig = b64(await subtle().sign({ name:'ECDSA', hash:'SHA-256' }, await importSignPriv(ST.id), enc(hash)));
    const entry = { seq, prevHash, hash, cipher, sig, bookTag:tag, ts };
    await LedgerStore.put(ST.id.fp, entry, true);
    await refreshLocal(); ST.writing = false; render(true);
    toast(navigator.onLine && ST.sync.online ? '已加密封存在本机，正在自动同步' : '已离线封存，恢复联网后自动上传');
  } finally { ST.writing = false; }
  synchronize();
}

/* ---------------- 统一界面 ---------------- */
function brand(compact) {
  return '<div class="brand ' + (compact ? 'compact' : '') + '"><span class="brand-symbol" aria-hidden="true"><i></i><i></i><i></i></span>' +
    '<span><b>简记</b><small>JIANJI LEDGER</small></span></div>';
}
function viewWelcome() {
  const wordsHtml = ST.tmp ? '<div class="words">' + ST.tmp.split(' ').map((w,i) =>
    '<div class="word"><b>' + String(i+1).padStart(2,'0') + '</b><span>' + esc(w) + '</span></div>').join('') + '</div>' : '';
  let auth;
  if (ST.tmp) {
    auth = '<div class="eyebrow">最后一步</div><h2>抄下你的 16 个助记词</h2>' +
      '<p class="muted">它们是身份与账本的唯一恢复凭据。服务端不保存明文，也无法替你找回。</p>' + wordsHtml +
      '<label class="check-line"><input type="checkbox" id="words-ack"> 我已离线抄写，并明白丢失后无法找回</label>' +
      '<div class="button-stack"><button class="btn primary wide" data-act="confirm-words">创建身份并进入账本</button>' +
      '<div class="row"><button class="btn secondary" data-act="copy-words">复制助记词</button><button class="btn ghost" data-act="cancel-words">返回</button></div></div>';
  } else if (ST.mode === 'restore') {
    auth = '<div class="eyebrow">欢迎回来</div><h2>恢复你的身份</h2><p class="muted">输入 16 个助记词。已使用过的设备即使断网，也能解开本机账本。</p>' +
      '<div class="field"><label for="restore-words">助记词（空格分隔）</label><textarea class="inp" id="restore-words" rows="4" autocomplete="off" spellcheck="false" placeholder="abandon ability able ..."></textarea></div>' +
      '<button class="btn primary wide" data-act="restore">恢复并进入账本</button>' +
      '<button class="text-btn" data-act="mode" data-v="create">第一次使用？创建新身份</button>';
  } else {
    auth = '<div class="eyebrow">开始使用</div><h2>你的账本，由你的密钥掌控</h2>' +
      '<p class="muted">不需要邮箱或手机号。生成助记词后，即可离线记账；联网时身份会自动登记，记录会自动同步。</p>' +
      '<div class="auth-facts"><div><b>本机先行</b><span>记录先加密封存，网络不是前提</span></div><div><b>恢复自动</b><span>联网后按顺序上传，重复提交会去掉</span></div><div><b>历史可查</b><span>哈希链、签名与外部锚点独立验证</span></div></div>' +
      '<button class="btn primary wide" data-act="gen-words">生成我的专属密钥</button>' +
      '<button class="text-btn" data-act="mode" data-v="restore">已有助记词？恢复身份</button>';
  }
  $('#app').innerHTML = '<div class="auth-shell"><section class="auth-story">' + brand() +
    '<div class="story-copy"><div class="eyebrow">离线优先 · 自动同步 · 只追加</div><h1>断网也能记，<br>联网自然同步。</h1>' +
    '<p>一套账本，一种体验。无论网络是否可用，记录都会先在你的设备上完成加密、签名和封存。</p></div>' +
    '<div class="story-proof"><span>端到端加密</span><span>本机待同步队列</span><span>公开哈希验证</span></div>' +
    '<div class="public-inline" id="public-status">正在读取公开账本状态…</div></section>' +
    '<section class="auth-panel"><div class="auth-card">' + auth + '</div><p class="auth-foot">明文不离开浏览器 · 没有修改或删除接口</p></section></div>';
  loadPublicStatus();
}
async function loadPublicStatus() {
  const el = $('#public-status'); if (!el) return;
  if (!navigator.onLine) { el.textContent = '当前离线：仍可创建身份并开始记账'; return; }
  try {
    const a = await api('/api/anchors', 'GET', null, false); ST.anchors = a;
    const target = $('#public-status'); if (!target) return;
    target.innerHTML = '<span class="status-dot good"></span> 服务可用 · ' + a.owners.length + ' 个公开身份 · Merkle 根 ' + shortHash(a.merkleRoot, 12) + '…';
  } catch (e) { const target = $('#public-status'); if (target) target.textContent = '服务暂不可达：仍可离线创建身份并记账'; }
}

const NAV = [
  ['overview','总览','01'], ['entry','记一笔','02'], ['records','账目明细','03'],
  ['verify','公开验证','04'], ['grants','共享授权','05'], ['identity','身份备份','06']
];
const PAGE_COPY = {
  overview:['工作台','账目与同步状态，一屏看清'], entry:['记一笔','先保存在本机，再按顺序同步'],
  records:['账目明细','每一笔都有序号、哈希与同步状态'], verify:['公开验证','只公开承诺，不公开账目内容'],
  grants:['共享授权','只把指定账本的读取能力交给指定身份'], identity:['身份与备份','管理助记词、本机密文与迁移文件']
};
function syncPill(button) {
  return '<' + (button ? 'button data-act="sync-now"' : 'div') + ' class="sync-pill ' + syncKind() + '">' +
    '<span class="status-dot ' + syncKind() + '" data-sync-dot></span><span data-sync-label>' + esc(syncLabel()) + '</span>' +
    (button ? '<span class="sync-action">立即同步</span>' : '') + '</' + (button ? 'button' : 'div') + '>';
}
function viewMain() {
  const copy = PAGE_COPY[ST.tab] || PAGE_COPY.overview;
  $('#app').innerHTML = '<div class="app-shell"><aside class="sidebar">' + brand() +
    '<nav class="side-nav" aria-label="主导航">' + NAV.map(n => '<button data-act="tab" data-v="' + n[0] + '" class="nav-item ' + (ST.tab === n[0] ? 'active' : '') + '"><span class="nav-num">' + n[2] + '</span><span>' + n[1] + '</span></button>').join('') + '</nav>' +
    '<div class="sidebar-bottom"><div class="security-note"><span class="status-dot good"></span><div><b>本机密文存储</b><small>明文仅在当前页面内存中</small></div></div>' +
    '<div class="identity-mini"><span>身份指纹</span><code>' + esc(ST.id.fp) + '</code></div>' +
    '<div class="sidebar-actions"><button class="text-btn" data-act="theme">切换主题</button><button class="text-btn" data-act="logout">锁定并退出</button></div></div></aside>' +
    '<section class="workspace"><header class="topbar"><div class="mobile-brand">' + brand(true) + '</div>' +
    '<div class="page-heading"><span>' + esc(copy[0]) + '</span><p>' + esc(copy[1]) + '</p></div>' + syncPill(true) + '</header>' +
    '<main class="page" id="main-content"></main></section>' +
    '<nav class="mobile-nav" aria-label="移动导航">' + NAV.map(n => '<button data-act="tab" data-v="' + n[0] + '" class="' + (ST.tab === n[0] ? 'active' : '') + '"><small>' + n[2] + '</small><span>' + n[1].replace('账目','').replace('身份','') + '</span></button>').join('') + '</nav></div>';
  const views = { overview:viewOverview, entry:viewEntry, records:viewRecords, verify:viewVerify, grants:viewGrants, identity:viewIdentity };
  $('#main-content').innerHTML = views[ST.tab]();
  paintSync();
}
function syncNotice() {
  if (ST.sync.conflict) return '<div class="notice danger"><b>同步已暂停</b><p>' + esc(ST.sync.conflict) + '</p><span>请先在「身份备份」导出本机加密账本。不要清空浏览器数据，也不要在另一设备继续写入。</span></div>';
  if (!navigator.onLine || !ST.sync.online || ST.sync.status === 'offline') return '<div class="notice offline"><b>当前离线，记账不受影响</b><p>新记录会加密保存在这台设备，并进入待同步队列。恢复网络后无需手动补录。</p></div>';
  if (ST.sync.status === 'error') return '<div class="notice warning"><b>本次同步未完成</b><p>' + esc(ST.sync.error || '将在下次连接时自动重试') + '</p><span>记录仍保存在本机，不会丢失或重复上传。</span></div>';
  if (ST.outbox.length) return '<div class="notice pending"><b>' + ST.outbox.length + ' 笔记录等待上传</b><p>它们已经完成本机加密与签名，将按账本顺序自动同步。</p></div>';
  return '<div class="notice success"><b>本机与服务端一致</b><p>所有已解密记录均已同步。最近确认：' + (ST.sync.lastSync ? new Date(ST.sync.lastSync).toLocaleString('zh-CN') : '本次会话') + '</p></div>';
}
function totals() {
  const income = ST.plain.filter(x => x.type === 'income').reduce((s,x) => s + x.amount, 0);
  const expense = ST.plain.filter(x => x.type !== 'income').reduce((s,x) => s + x.amount, 0);
  return { income, expense, net:income - expense };
}
function entryForm() {
  return '<form class="entry-form" id="entry-form"><div class="form-grid"><div class="field span-2"><label for="f-amount">金额</label><div class="amount-input"><span>¥</span><input class="inp" id="f-amount" inputmode="decimal" autocomplete="off" placeholder="0.00" required></div></div>' +
    '<div class="field"><label for="f-type">收支方向</label><select class="inp" id="f-type"><option value="expense">支出 / 减少</option><option value="income">收入 / 增加</option></select></div>' +
    '<div class="field"><label for="f-date">日期</label><input class="inp" type="date" id="f-date" value="' + today() + '"></div>' +
    '<div class="field span-2"><label for="f-note">摘要</label><input class="inp" id="f-note" maxlength="120" placeholder="这笔钱因何发生？"></div>' +
    '<div class="field"><label for="f-book">所属账本</label><select class="inp" id="f-book">' + ST.books.map(b => '<option' + (b === ST.book ? ' selected' : '') + '>' + esc(b) + '</option>').join('') + '</select></div>' +
    '<div class="field"><label for="f-party">往来 / 经办</label><input class="inp" id="f-party" maxlength="80" placeholder="选填"></div>' +
    '<div class="field"><label for="f-voucher">凭证号</label><input class="inp" id="f-voucher" maxlength="80" placeholder="选填"></div>' +
    '<div class="field book-add"><label>&nbsp;</label><button type="button" class="btn ghost" data-act="add-book">新增账本</button></div></div>' +
    '<div class="form-footer"><span>提交后不可修改；记错时追加红字冲销。</span><button class="btn primary" type="submit" ' + (ST.writing ? 'disabled' : '') + '>加密并记入账本</button></div></form>';
}
function emptyState(title, text) { return '<div class="empty"><b>' + esc(title) + '</b><p>' + esc(text) + '</p></div>'; }
function recentRows(list, actions) {
  if (!list.length) return emptyState('还没有账目', '第一笔记录会同时出现在本机明细与同步队列中。');
  return '<div class="transaction-list">' + list.map(p => '<div class="transaction"><div class="transaction-main"><div class="transaction-title">' + esc(p.note || (p.type === 'income' ? '收入' : '支出')) + (p.reversalOf ? '<span class="tag neutral">冲销</span>' : '') + '</div>' +
    '<div class="transaction-meta">' + esc(p.date) + '<i></i>' + esc(p.book) + '<i></i>#' + p.seq + '</div></div>' +
    '<div class="transaction-side"><div class="amount ' + (p.type === 'income' ? 'income' : 'expense') + '">' + (p.type === 'income' ? '+' : '−') + fmt(p.amount) + '</div>' +
    '<span class="tag ' + (p.pending ? 'pending' : 'good') + '">' + (p.pending ? '待同步' : '已同步') + '</span></div>' +
    (actions ? '<button class="text-btn reverse-link" data-act="reverse-entry" data-hash="' + esc(p.hash) + '">红字冲销</button>' : '') + '</div>').join('') + '</div>';
}
function viewOverview() {
  const t = totals(), recent = ST.plain.slice().reverse().slice(0,6);
  return '<section class="page-intro"><div><div class="eyebrow">' + new Date().toLocaleDateString('zh-CN', { month:'long', day:'numeric', weekday:'long' }) + '</div><h1>今天，也把账记清楚。</h1><p>网络只决定何时上传，不决定能否记账。</p></div><button class="btn secondary desktop-only" data-act="tab" data-v="records">查看全部明细</button></section>' +
    '<section class="kpi-grid"><div class="kpi"><span>净额</span><strong>' + fmt(t.net) + '</strong><small>收入减去支出，含本机待同步</small></div>' +
    '<div class="kpi"><span>累计收入</span><strong class="income">' + fmt(t.income) + '</strong><small>' + ST.plain.filter(x => x.type === 'income').length + ' 笔已解密记录</small></div>' +
    '<div class="kpi"><span>累计支出</span><strong>' + fmt(t.expense) + '</strong><small>' + ST.plain.filter(x => x.type !== 'income').length + ' 笔已解密记录</small></div>' +
    '<div class="kpi sync-kpi"><span>待同步</span><strong data-pending-count>' + ST.outbox.length + '</strong><small>本机已封存，联网自动上传</small></div></section>' +
    syncNotice() +
    '<div class="overview-grid"><section class="panel"><div class="panel-head"><div><span class="section-kicker">QUICK ENTRY</span><h2>快速记一笔</h2></div><span class="tag neutral">只追加</span></div>' + entryForm() + '</section>' +
    '<section class="panel"><div class="panel-head"><div><span class="section-kicker">RECENT</span><h2>最近账目</h2></div><button class="text-btn" data-act="tab" data-v="records">全部</button></div>' + recentRows(recent, false) + '</section></div>';
}
function viewEntry() {
  return '<div class="entry-layout"><section class="panel"><div class="panel-head"><div><span class="section-kicker">NEW ENTRY</span><h1>记录一笔资金变化</h1></div></div>' + entryForm() + '</section>' +
    '<aside class="entry-aside">' + syncNotice() + '<section class="plain-section"><span class="section-kicker">发生了什么</span><h2>先封存，再上传</h2><ol class="steps"><li><b>本机加密</b><span>摘要、金额和往来信息不会以明文写入数据库。</span></li><li><b>签名并接续哈希</b><span>记录获得连续序号、前序哈希和身份签名。</span></li><li><b>联网自动同步</b><span>按顺序上传；已存在的哈希直接确认，不会记重。</span></li></ol></section></aside></div>';
}
function filteredRecords() {
  const q = ST.filter.text.toLowerCase();
  return ST.plain.filter(p => (ST.filter.book === 'all' || p.book === ST.filter.book) &&
    (ST.filter.status === 'all' || (ST.filter.status === 'pending') === !!p.pending) &&
    (!q || [p.note,p.party,p.voucher,p.date,p.book].some(x => String(x || '').toLowerCase().includes(q)))).reverse();
}
function viewRecords() {
  const list = filteredRecords();
  return '<section class="page-intro compact-intro"><div><h1>全部账目</h1><p>共 ' + ST.plain.length + ' 笔可解密记录，当前显示 ' + list.length + ' 笔。</p></div><button class="btn primary" data-act="tab" data-v="entry">记一笔</button></section>' +
    '<section class="panel filter-panel"><div class="filters"><div class="field"><label for="record-search">搜索</label><input class="inp" id="record-search" value="' + esc(ST.filter.text) + '" placeholder="摘要、往来、凭证或日期"></div>' +
    '<div class="field"><label for="record-book">账本</label><select class="inp" id="record-book"><option value="all">全部账本</option>' + ST.books.map(b => '<option value="' + esc(b) + '" ' + (ST.filter.book === b ? 'selected' : '') + '>' + esc(b) + '</option>').join('') + '</select></div>' +
    '<div class="field"><label for="record-status">同步状态</label><select class="inp" id="record-status"><option value="all">全部状态</option><option value="synced" ' + (ST.filter.status === 'synced' ? 'selected' : '') + '>已同步</option><option value="pending" ' + (ST.filter.status === 'pending' ? 'selected' : '') + '>待同步</option></select></div>' +
    '<button class="btn secondary filter-submit" data-act="apply-filters">筛选</button></div></section>' +
    '<section class="panel records-panel"><div class="records-head"><span>账目</span><span>金额与状态</span></div>' + recentRows(list, true) + '</section>';
}

function consistency(proof, saved) {
  const n = Number(saved.anchorCount || saved.count || 0), head = saved.anchorHead || saved.head;
  if (!n || !head) return { ok:false, msg:'锚点文件格式不正确' };
  const arr = proof.anchors || [];
  if (!arr[n-1]) return { ok:false, msg:'当前锚链比保存时更短，可能回滚或环境重建' };
  if (arr[n-1].hash !== head) return { ok:false, msg:'锚点哈希不匹配，历史可能被替换' };
  return { ok:true, extended:arr.length - n };
}
function viewVerify() {
  const a = ST.anchors || { merkleRoot:'—', owners:[] };
  const proof = ST.proof || { anchors:[], anchorHead:'—', anchorCount:0 };
  const savedRows = savedAnchors().slice().reverse().map(s => {
    const c = consistency(proof, s);
    return '<div class="audit-row"><div><b>#' + (s.anchorCount || s.count) + ' · ' + shortHash(s.anchorHead || s.head, 20) + '…</b><span>' + esc(s.savedAt || '') + ' · ' + esc(c.ok ? '一致，此后新增 ' + c.extended + ' 个锚点' : c.msg) + '</span></div><span class="tag ' + (c.ok ? 'good' : 'bad') + '">' + (c.ok ? '一致' : '异常') + '</span></div>';
  }).join('') || emptyState('尚未保存锚点', '联网后保存当前锚点，可用于日后发现历史回滚。');
  const own = (a.owners || []).map(o => '<div class="audit-row"><div><b class="mono">' + esc(o.fp) + (o.fp === ST.id.fp ? ' <span class="tag info">当前身份</span>' : '') + '</b><span>' + o.count + ' 条 · 链头 ' + shortHash(o.head, 20) + '…</span></div><button class="btn small secondary" data-act="verify-one" data-fp="' + esc(o.fp) + '">独立校验</button></div>').join('') || emptyState('暂无公开身份', '联网后这里会显示仅含哈希的公开状态。');
  return '<div class="verify-grid"><section class="panel span-full"><div class="panel-head"><div><span class="section-kicker">PUBLIC COMMITMENT</span><h1>全局哈希承诺</h1></div><button class="btn secondary" data-act="refresh-anchors">刷新公开状态</button></div>' +
    '<div class="hash-block"><span>MERKLE ROOT</span><code>' + esc(a.merkleRoot) + '</code></div><p class="muted">公开接口只返回序号、前序哈希、本条哈希、时间戳与签名，不返回密文或账目内容。</p></section>' +
    '<section class="panel"><div class="panel-head"><h2>身份链</h2><span class="tag neutral">' + (a.owners || []).length + ' 个</span></div>' + own + '</section>' +
    '<section class="panel" id="verify-detail"><div class="panel-head"><h2>独立校验结果</h2></div><p class="muted">选择一条身份链，浏览器会在本地重算连续性并验签，而不是直接相信服务端结论。</p></section>' +
    '<section class="panel span-full"><div class="panel-head"><div><span class="section-kicker">ROLLBACK DETECTION</span><h2>锚定证明与回滚检测</h2></div><span class="tag ' + (proof.anchorCount ? 'good' : 'neutral') + '">' + (proof.anchorCount || 0) + ' 个锚点</span></div>' +
    '<div class="hash-block"><span>ANCHOR HEAD</span><code>' + esc(proof.anchorHead || '—') + '</code></div>' +
    '<div class="button-row"><button class="btn secondary" data-act="save-anchor">保存当前锚点</button><button class="btn secondary" data-act="export-proof">下载锚定证明</button><button class="btn secondary" data-act="import-anchor">导入历史锚点</button><button class="btn ghost" data-act="open-public">公开验证页</button><button class="btn ghost" data-act="copy-public">复制公开链接</button></div><div class="audit-list">' + savedRows + '</div></section></div>';
}
function viewGrants() {
  const g = ST.grants || { out:[], in:[] };
  const outRows = g.out.length ? g.out.map(x => '<div class="audit-row"><div><b>' + esc(x.label || x.bookTag.slice(0,10)) + ' → <span class="mono">' + esc(x.to) + '</span></b><span>' + new Date(x.ts).toLocaleString('zh-CN') + '</span></div><button class="btn small danger" data-act="revoke" data-id="' + esc(x.id) + '">撤销</button></div>').join('') : emptyState('没有发出的授权', '你的账本默认只有你能解开。');
  const inRows = (ST.shared && ST.shared.length) ? ST.shared.map(x => '<div class="audit-row"><div><b>' + esc(x.label || '共享账本') + '</b><span>来自 <span class="mono">' + esc(x.from) + '</span> · ' + x.entries.length + ' 条</span></div><button class="btn small secondary" data-act="view-shared" data-id="' + esc(x.grantId) + '">解密查看</button></div>').join('') : emptyState('没有收到的授权', '对方需要你的身份指纹才能授权。');
  return '<div class="grant-grid"><section class="panel"><div class="panel-head"><div><span class="section-kicker">SELECTIVE DISCLOSURE</span><h1>授权指定账本</h1></div></div><p class="muted">账本数据密钥会用对方公钥封装。服务端只转交封装结果，无法因此看到明文。</p>' +
    '<div class="field"><label for="g-to">对方身份指纹</label><input class="inp mono" id="g-to" placeholder="20 位身份指纹"></div><div class="field"><label for="g-book">授权账本</label><select class="inp" id="g-book">' + ST.books.map(b => '<option>' + esc(b) + '</option>').join('') + '</select></div>' +
    '<button class="btn primary" data-act="grant">生成并发送授权</button><div class="fine-print">撤销只阻止之后读取；对方已经看到或保存的内容无法密码学收回。此操作需要联网。</div></section>' +
    '<div><section class="panel"><div class="panel-head"><h2>我发出的授权</h2></div>' + outRows + '</section><section class="panel"><div class="panel-head"><h2>别人授权给我</h2></div>' + inRows + '</section></div></div>';
}
function viewIdentity() {
  return '<div class="identity-grid"><section class="panel"><div class="panel-head"><div><span class="section-kicker">IDENTITY</span><h1>我的身份</h1></div><span class="tag good">密钥即身份</span></div>' +
    '<div class="field"><label>身份指纹（可安全分享）</label><div class="hash-block"><code>' + esc(ST.id.fp) + '</code></div></div><div class="button-row"><button class="btn secondary" data-act="copy-fp">复制指纹</button><button class="btn ghost" data-act="show-words">查看助记词</button></div>' +
    '<p class="muted">服务端只保存公钥、助记词加密的私钥包、密文记录与哈希链，没有邮箱、手机号或密码。</p></section>' +
    '<section class="panel"><div class="panel-head"><div><span class="section-kicker">BACKUP</span><h2>加密备份与迁移</h2></div></div><p class="muted">导出文件包含本机全部已同步与待同步密文。导入另一台设备后，会并入待同步队列，由幂等规则去掉服务端已有记录。</p>' +
    '<div class="storage-stats"><div><span>本机密文记录</span><b>' + ST.entries.length + '</b></div><div><span>待同步</span><b>' + ST.outbox.length + '</b></div><div><span>本机链高</span><b>' + ST.me.seq + '</b></div></div>' +
    '<div class="button-row"><button class="btn primary" data-act="export-ledger">导出加密账本</button><button class="btn secondary" data-act="import-ledger">导入账本文件</button></div><div class="fine-print warn-text">清除浏览器数据会删除尚未上传的本机记录。重要账目请同时保留加密导出文件；助记词请离线抄写。</div></section>' +
    '<section class="panel span-full"><div class="panel-head"><h2>同步与技术边界</h2></div><div class="boundary-grid"><div><b>离线持久化</b><p>本机数据库只存密文与签名；重新打开页面后，需要助记词才能解密查看。</p></div><div><b>多设备分叉</b><p>同一身份在多台设备同时离线追加可能形成不同历史。系统会暂停，不会自动覆盖。</p></div><div><b>外部锚定</b><p>GitHub 锚点用于发现服务端回滚；公开文件只有哈希，不含密文或助记词。</p></div><div><b>部署持久卷</b><p>正式服务端必须为事件日志配置持久存储，浏览器备份不是服务端容灾的替代品。</p></div></div></section></div>';
}

function render(clearDraft) {
  const ids = ['f-amount','f-type','f-date','f-note','f-book','f-party','f-voucher'];
  const draft = {};
  if (!clearDraft) for (const id of ids) { const el = document.getElementById(id); if (el) draft[id] = el.value; }
  if (ST.id) viewMain(); else viewWelcome();
  if (!clearDraft) for (const id of Object.keys(draft)) { const el = document.getElementById(id); if (el) el.value = draft[id]; }
}

async function verifyOne(fp) {
  const a = await api('/api/anchors/' + fp, 'GET', null, false);
  let prev = GENESIS, broken = -1, sigOk = true;
  const pub = await importSignPub(a.pubSign);
  for (let i = 0; i < a.chain.length; i++) {
    const e = a.chain[i];
    if (e.seq !== i + 1 || e.prevHash !== prev) { broken = i + 1; break; }
    try { sigOk = await subtle().verify({ name:'ECDSA', hash:'SHA-256' }, pub, unb64(e.sig), enc(e.hash)) && sigOk; }
    catch (err) { sigOk = false; }
    prev = e.hash;
  }
  const headOk = prev === a.head, ok = broken < 0 && headOk && sigOk;
  const rows = a.chain.slice(0, 12).map(e => '<div class="chain-row"><span>#' + e.seq + '</span><code>' + esc(e.hash) + '</code></div>').join('');
  const el = $('#verify-detail'); if (!el) return;
  el.innerHTML = '<div class="panel-head"><h2>独立校验</h2><span class="tag ' + (ok ? 'good' : 'bad') + '">' + (ok ? '校验通过' : '发现异常') + '</span></div>' +
    '<p class="muted">链长 ' + a.chain.length + ' · 序号连续：' + (broken < 0 ? '是' : '否') + ' · 签名有效：' + (sigOk ? '是' : '否') + ' · 链头一致：' + (headOk ? '是' : '否') + '</p>' +
    '<div class="chain-list">' + (rows || emptyState('空账本','还没有可校验的记录')) + '</div>';
}
async function grant() {
  if (!navigator.onLine) throw new Error('授权需要联网；离线记账不受影响');
  const to = $('#g-to').value.trim(), book = $('#g-book').value;
  if (!to) throw new Error('请填对方身份指纹');
  const other = await api('/api/pub/' + to, 'GET', null, false);
  const bits = await subtle().deriveBits({ name:'ECDH', public:await importDhPub(other.pubDh) }, await importDhPriv(ST.id), 256);
  const wrap = await aesKey(new Uint8Array(bits), ['encrypt','decrypt']);
  const raw = await subtle().exportKey('raw', await bookKey(ST.id, book));
  const wrappedKey = await aesEncRaw(wrap, new Uint8Array(raw));
  await authed('/api/grants', 'POST', { id:uid(), to, bookTag:await bookTag(ST.id, book), wrappedKey, label:book });
  await refreshAncillary(); render(); toast('授权已生成，对方现在可以解开这个账本');
}
async function viewShared(grantId) {
  const g = (ST.shared || []).find(x => x.grantId === grantId); if (!g) return;
  const other = await api('/api/pub/' + g.from, 'GET', null, false);
  const bits = await subtle().deriveBits({ name:'ECDH', public:await importDhPub(other.pubDh) }, await importDhPriv(ST.id), 256);
  const wrap = await aesKey(new Uint8Array(bits), ['encrypt','decrypt']);
  const raw = await aesDecRaw(wrap, g.wrappedKey), bk = await aesKey(raw, ['decrypt']);
  const rows = [];
  for (const e of g.entries) {
    try { const p = await aesDec(bk, e.cipher); rows.push({ plain:Object.assign({}, p, { seq:e.seq, hash:e.hash, pending:false }) }); }
    catch (err) {}
  }
  modal('<div class="eyebrow">共享账本</div><h2>' + esc(g.label || '共享账本') + '</h2><p class="muted">来自 ' + esc(g.from) + ' · 已用当前私钥解开</p>' +
    (rows.length ? recentRows(rows.map(x => x.plain).reverse(), false) : emptyState('暂无可解密记录','这个账本还没有记录')) +
    '<div class="button-row"><button class="btn secondary" data-act="close-modal">关闭</button></div>');
}

/* ---------------- 交互 ---------------- */
document.addEventListener('submit', async e => {
  if (e.target.id !== 'entry-form') return;
  e.preventDefault();
  try { await addEntry(); } catch (err) { toast(err.message || '记账失败', 'err'); }
});

document.addEventListener('click', async e => {
  const el = e.target.closest('[data-act]'); if (!el) return;
  const a = el.dataset.act;
  try {
    switch (a) {
      case 'mode': ST.mode = el.dataset.v; ST.tmp = null; render(); break;
      case 'gen-words': ST.tmp = newMnemonic(); render(); break;
      case 'cancel-words': ST.tmp = null; render(); break;
      case 'copy-words': await copy(ST.tmp); break;
      case 'confirm-words': {
        if (!$('#words-ack') || !$('#words-ack').checked) { toast('请先确认已离线抄写助记词', 'warn'); break; }
        const id = await createIdentity(ST.tmp);
        await startIdentity(id);
        toast('身份已创建。现在即使断网，也可以开始记账'); break;
      }
      case 'restore': {
        const m = normMnemonic($('#restore-words').value);
        if (m.split(' ').length !== 16) throw new Error('需要 16 个助记词');
        if (m.split(' ').some(w => WORDS.indexOf(w) < 0)) throw new Error('有词不在词表里，请检查拼写');
        const id = await restoreIdentity(m); await startIdentity(id); toast('身份已恢复，本机密文账本已解密'); break;
      }
      case 'logout':
        TOKEN = ''; ST.id = null; ST.plain = []; ST.entries = []; ST.outbox = []; ST.me = { seq:0, head:GENESIS };
        ST.grants = null; ST.shared = null; ST.tmp = null; ST.mode = 'restore'; render(); break;
      case 'theme': {
        const t = document.documentElement.dataset.theme === 'dark' ? 'light' : 'dark';
        document.documentElement.dataset.theme = t;
        try { localStorage.setItem('jianji.theme', t); } catch (err) {}
        break;
      }
      case 'tab': ST.tab = el.dataset.v; render(); break;
      case 'sync-now':
        if (!navigator.onLine) toast('当前无网络；记录会继续保存在本机', 'warn');
        else { toast('正在检查连接与待同步队列'); await synchronize(); }
        break;
      case 'public-check': case 'refresh-anchors':
        ST.anchors = await api('/api/anchors', 'GET', null, false);
        ST.proof = await api('/api/anchor-proof', 'GET', null, false);
        if (!ST.id) loadPublicStatus(); else render();
        toast('公开哈希与锚链已刷新'); break;
      case 'save-anchor': {
        const p = (ST.proof = await api('/api/anchor-proof', 'GET', null, false));
        const arr = savedAnchors();
        arr.push({ anchorCount:p.anchorCount, anchorHead:p.anchorHead, root:p.merkleRoot, savedAt:new Date().toLocaleString('zh-CN') });
        writeSavedAnchors(arr); render(); toast('锚点已保存到本机，可用于日后核对历史'); break;
      }
      case 'export-proof': {
        const p = (ST.proof = await api('/api/anchor-proof', 'GET', null, false));
        downloadJSON(p, '简记_锚定证明_' + today() + '.json'); toast('锚定证明已导出'); break;
      }
      case 'import-anchor': {
        const p = (ST.proof = await api('/api/anchor-proof', 'GET', null, false));
        const input = document.createElement('input'); input.type = 'file'; input.accept = '.json';
        input.onchange = async () => {
          const f = input.files && input.files[0]; if (!f) return;
          try {
            const j = JSON.parse(await f.text());
            const saved = j.anchorHead ? j : (Array.isArray(j) ? j[j.length-1] : null);
            if (!saved) throw new Error('不是有效的锚点或锚定证明文件');
            const c = consistency(p, saved);
            modal('<div class="eyebrow">历史一致性</div><h2>锚点校验结果</h2><div class="notice ' + (c.ok ? 'success' : 'danger') + '"><b>' + (c.ok ? '历史前缀一致' : '发现异常') + '</b><p>' + (c.ok
              ? '保存时的第 ' + (saved.anchorCount || saved.count) + ' 个锚点仍在当前锚链前缀中，此后新增 ' + c.extended + ' 个锚点。' : esc(c.msg)) + '</p></div>' +
              '<div class="hash-block"><span>导入锚链头</span><code>' + esc(String(saved.anchorHead || saved.head)) + '</code></div>' +
              '<div class="button-row"><button class="btn secondary" data-act="close-modal">关闭</button></div>');
          } catch (err) { toast(err.message, 'err'); }
        };
        input.click(); break;
      }
      case 'open-public': window.open('/verify.html?fp=' + ST.id.fp, '_blank'); break;
      case 'copy-public': await copy(location.origin + '/verify.html?fp=' + ST.id.fp); break;
      case 'add-book': {
        const name = prompt('新账本名称（例如：项目 A 备用金）');
        if (name && name.trim() && !ST.books.includes(name.trim())) {
          ST.books.push(name.trim()); ST.book = name.trim();
          await LedgerStore.setMeta('books:' + ST.id.fp, ST.books); render();
        }
        break;
      }
      case 'apply-filters':
        ST.filter.text = $('#record-search').value.trim(); ST.filter.book = $('#record-book').value; ST.filter.status = $('#record-status').value; render(); break;
      case 'reverse-entry': {
        const original = ST.plain.find(p => p.hash === el.dataset.hash); if (!original) break;
        if (ST.plain.some(p => p.reversalOf === original.hash)) { toast('这笔记录已经冲销过，不能重复冲销', 'warn'); break; }
        modal('<div class="eyebrow">APPEND-ONLY CORRECTION</div><h2>确认红字冲销</h2><p class="muted">不会修改原记录，而是追加一笔等额、反向的新记录。两笔都会永久保留。</p>' +
          '<div class="reversal-summary"><span>' + esc(original.date) + ' · ' + esc(original.book) + '</span><b>' + esc(original.note || '未填写摘要') + '</b><strong>' + (original.type === 'income' ? '+' : '−') + fmt(original.amount) + '</strong></div>' +
          '<div class="button-row"><button class="btn danger" data-act="confirm-reversal" data-hash="' + esc(original.hash) + '">追加冲销记录</button><button class="btn secondary" data-act="close-modal">取消</button></div>'); break;
      }
      case 'confirm-reversal': {
        const original = ST.plain.find(p => p.hash === el.dataset.hash); if (!original) break;
        $('.modal-bg')?.remove();
        await addEntry({ type:original.type === 'income' ? 'expense' : 'income', amount:original.amount, book:original.book,
          date:today(), note:'冲销：' + (original.note || '未填写摘要'), party:original.party || '', voucher:original.voucher || '', reversalOf:original.hash });
        break;
      }
      case 'verify-one': await verifyOne(el.dataset.fp); break;
      case 'grant': await grant(); break;
      case 'revoke': await authed('/api/revoke', 'POST', { grantId:el.dataset.id }); await refreshAncillary(); render(); toast('授权已撤销'); break;
      case 'view-shared': await viewShared(el.dataset.id); break;
      case 'copy-fp': await copy(ST.id.fp); break;
      case 'show-words':
        modal('<div class="eyebrow">敏感信息</div><h2>你的助记词</h2><div class="notice danger"><b>确认周围没有人</b><p>任何看到这 16 个词的人都能控制你的身份并解开账本。</p></div>' +
          '<div class="words">' + ST.id.keys.mnemonic.split(' ').map((w,i) => '<div class="word"><b>' + String(i+1).padStart(2,'0') + '</b><span>' + esc(w) + '</span></div>').join('') + '</div>' +
          '<div class="button-row"><button class="btn secondary" data-act="copy-words-now">复制</button><button class="btn ghost" data-act="close-modal">关闭</button></div>'); break;
      case 'copy-words-now': await copy(ST.id.keys.mnemonic); break;
      case 'export-ledger': {
        await refreshLocal();
        const entries = ST.entries.map(r => r.entry).sort((a,b) => a.seq - b.seq);
        downloadJSON({ app:'简记统一离线账本', version:3, fp:ST.id.fp, exportedAt:new Date().toISOString(),
          pubSign:ST.id.pubSign, identity:cachedIdentity(), books:ST.books, entries, anchors:ST.anchors, proof:ST.proof },
          '简记_加密账本_' + today() + '.json');
        toast('已导出 ' + entries.length + ' 条密文，包含待同步记录'); break;
      }
      case 'import-ledger': {
        const input = document.createElement('input'); input.type = 'file'; input.accept = '.json';
        input.onchange = async () => {
          const f = input.files && input.files[0]; if (!f) return;
          try {
            const pack = JSON.parse(await f.text());
            if (!pack.fp || !Array.isArray(pack.entries)) throw new Error('不是有效的简记加密账本');
            if (pack.fp !== ST.id.fp) throw new Error('这份账本属于身份 ' + pack.fp + '，请用对应助记词登录');
            const problem = SyncCore.chainProblem(pack.entries);
            if (problem) throw new Error('备份文件哈希链序号或前序不连续，已拒绝导入');
            const local = await LedgerStore.all(ST.id.fp);
            const localBySeq = new Map(local.map(r => [Number(r.entry.seq), r.entry.hash]));
            const known = new Set(local.map(r => r.entry.hash));
            for (const entry of pack.entries) {
              if (localBySeq.has(Number(entry.seq)) && localBySeq.get(Number(entry.seq)) !== entry.hash)
                throw new Error('备份与本机在第 ' + entry.seq + ' 条发生分叉，未导入任何记录');
            }
            const fresh = pack.entries.filter(entry => !known.has(entry.hash));
            if (fresh.length) await LedgerStore.putMany(ST.id.fp, fresh, true);
            if (pack.identity && pack.identity.verifier === ST.id.keys.verifier) {
              try { localStorage.setItem(ID_CACHE, JSON.stringify(pack.identity)); } catch (err) {}
            }
            if (Array.isArray(pack.books)) {
              ST.books = Array.from(new Set(ST.books.concat(pack.books.filter(x => typeof x === 'string'))));
              await LedgerStore.setMeta('books:' + ST.id.fp, ST.books);
            }
            await refreshLocal(); render();
            modal('<div class="eyebrow">备份已并入</div><h2>导入完成</h2><p class="muted">新增 ' + fresh.length + ' 条密文记录；服务端已经存在的记录会在同步时自动确认，不会重复入账。</p>' +
              '<div class="notice success"><b>本机链高 ' + ST.me.seq + '</b><p>当前共有 ' + ST.outbox.length + ' 笔等待联网确认。</p></div><div class="button-row"><button class="btn primary" data-act="close-modal">完成</button></div>');
            if (fresh.length) synchronize();
          } catch (err) { toast(err.message, 'err'); }
        };
        input.click(); break;
      }
    }
  } catch (err) { toast(err.message || '操作失败', 'err'); }
});

window.addEventListener('online', () => {
  ST.sync.online = true; ST.sync.status = 'idle'; paintSync();
  if (ST.id) { toast('网络已恢复，正在自动上传本机记录'); synchronize(); }
});
window.addEventListener('offline', () => { ST.sync.online = false; ST.sync.status = 'offline'; paintSync(); if (ST.id) render(); });
document.addEventListener('visibilitychange', () => { if (!document.hidden && ST.id && navigator.onLine) synchronize(); });
setInterval(() => { if (ST.id && navigator.onLine && !ST.syncing && !ST.sync.conflict) synchronize(); }, 30000);

try {
  const savedTheme = localStorage.getItem('jianji.theme');
  document.documentElement.dataset.theme = savedTheme || (matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light');
} catch (e) { document.documentElement.dataset.theme = 'light'; }
if (!crypto || !crypto.subtle || !window.isSecureContext) {
  $('#app').innerHTML = '<div class="fatal"><h1>需要安全上下文</h1><p>Web Crypto 要求 HTTPS 或 localhost。请通过部署后的 HTTPS 地址，或本机 http://127.0.0.1 访问。</p></div>';
} else {
  render();
  if ('serviceWorker' in navigator) window.addEventListener('load', () => navigator.serviceWorker.register('/sw.js').catch(() => {}));
}
