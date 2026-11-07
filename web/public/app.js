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
/* 加密的账本目录：账本名参与派生 bookKey / bookTag，必须与身份一起可恢复。
   用主密钥加密后随身份存到服务端（只追加的 profile 事件），服务端解不开。 */
async function encodeProfile(id, books) {
  return aesEnc(id.keys.master, { books:Array.from(new Set(books)) });
}
async function decodeProfile(id, text) {
  if (!text) return [];
  try {
    const p = await aesDec(id.keys.master, text);
    return Array.isArray(p.books) ? Array.from(new Set(p.books.filter(x => typeof x === 'string' && x.trim()).map(x => x.trim()))) : [];
  } catch (e) { return []; }
}

const ID_CACHE = 'jianji.identity.v1';
const QUICK_KEY = 'jianji.quickunlock.v1';
/* 身份凭据可在不接触服务端的情况下重建身份：助记词 + 私钥 JWK 都在里面。 */
function credentialFromId(id) {
  return { mnemonic:id.keys.mnemonic, priv:id.priv, pubSign:id.pubSign, pubDh:id.pubDh,
    bundle:id.bundle, fp:id.fp, verifier:id.keys.verifier };
}
async function identityFromCredential(c) {
  const keys = await derive(c.mnemonic);
  return { keys, priv:c.priv, pubSign:c.pubSign, pubDh:c.pubDh, bundle:c.bundle, fp:c.fp,
    profile:(cachedIdentity() || {}).profile || '' };
}
function cacheIdentity(id) {
  try { localStorage.setItem(ID_CACHE, JSON.stringify({ verifier:id.keys.verifier, bundle:id.bundle,
    fp:id.fp, pubSign:id.pubSign, pubDh:id.pubDh, profile:id.profile || '' })); } catch (e) {}
}
function cachedIdentity() { try { return JSON.parse(localStorage.getItem(ID_CACHE) || 'null'); } catch (e) { return null; } }
async function restoreIdentity(m) {
  const keys = await derive(m);
  let r = null;
  try { r = await api('/api/lookup', 'POST', { verifier: keys.verifier }, false); }
  catch (e) {
    const c = cachedIdentity();
    if (!c || c.verifier !== keys.verifier) {
      if (e.status === 404)
        throw new Error('服务端没有登记过这个身份。助记词必须配合密钥包使用：若身份是在离线时创建且从未联网，请回到原设备，或导入之前导出的加密账本备份');
      throw new Error(e.network ? '离线恢复需要使用这台设备保存过的身份；也可以先导入加密账本备份'
        : '没有找到该助记词对应的身份：请检查抄写，或导入之前导出的加密账本文件');
    }
    r = c;
  }
  let priv;
  try { priv = await aesDec(keys.master, r.bundle); }
  catch (e) { throw new Error('助记词无法解开该身份的密钥包，请检查抄写是否正确'); }
  return { keys, pubSign:r.pubSign, pubDh:r.pubDh, priv, bundle:r.bundle, fp:r.fp,
    profile:r.profile || (cachedIdentity() || {}).profile || '' };
}
async function login(id) {
  const c = await api('/api/challenge', 'POST', { fp: id.fp }, false);
  const sig = b64(await subtle().sign({ name:'ECDSA', hash:'SHA-256' }, await importSignPriv(id), enc(c.nonce)));
  return api('/api/session', 'POST', { fp:id.fp, pubSign:id.pubSign, pubDh:id.pubDh,
    nonce:c.nonce, sig, bundle:id.bundle, verifier:id.keys.verifier,
    inviteCode:ST.inviteCode || '' }, false);
}

let TOKEN = '';
const ST = {
  id:null, me:{ seq:0, head:GENESIS }, entries:[], outbox:[], plain:[], undecryptable:0,
  tab:'overview', book:'个人账',
  books:['个人账','公司资金'], mode:'create', tmp:null, anchors:null, proof:null, grants:null, shared:null,
  lastAnchorHead:null, lastGrantsVersion:null,
  replicas:{ configured:0, totalBackups:0, lastBackupAt:0, targets:[], error:'' },
  archive:{ status:'idle', count:0, bytes:0, lastAt:0, error:'' }, archiving:false,
  quick:{ available:false, fp:'', attempts:0 },
  inviteCode:'', inviteRequired:false,
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
  let undecryptable = 0;
  for (const row of rows) {
    const e = row.entry, b = tagMap[e.bookTag];
    if (!b) { undecryptable++; continue; }
    try {
      const p = await aesDec(await bookKey(ST.id, b), e.cipher);
      plain.push(Object.assign({}, p, { seq:e.seq, hash:e.hash, prevHash:e.prevHash, book:b, pending:pendingHashes.has(e.hash) }));
    } catch (err) { undecryptable++; /* 损坏记录不暴露明文，也不阻塞可用记录 */ }
  }
  /* 账本名缺失或密文损坏时绝不能静默少算：显式计数，界面负责提示。 */
  ST.undecryptable = undecryptable;
  ST.plain = plain.sort((a,b) => a.seq - b.seq);
  paintSync();
}
async function startIdentity(id) {
  ST.id = id; TOKEN = ''; ST.tmp = null; ST.anchors = null; ST.proof = null; ST.grants = null; ST.shared = null;
  ST.sync.conflict = ''; ST.sync.error = ''; ST.tab = 'overview';
  ST.lastAnchorHead = null; ST.lastGrantsVersion = null;
  ST.archive = { status:'idle', count:0, bytes:0, lastAt:0, error:'' };
  id.needProfilePush = false;
  cacheIdentity(id);
  ST.books = await LedgerStore.getMeta('books:' + id.fp, ['个人账','公司资金']);
  /* 换设备恢复时，服务端 /api/lookup 或本机缓存里的加密账本目录必须先于解密生效。 */
  const restored = await decodeProfile(id, id.profile || (cachedIdentity() || {}).profile || '');
  if (restored.length) {
    ST.books = Array.from(new Set(ST.books.concat(restored)));
    await LedgerStore.setMeta('books:' + id.fp, ST.books);
  }
  if (!ST.books.includes(ST.book)) ST.book = ST.books[0];
  ST.sync.lastSync = await LedgerStore.getMeta('lastSync:' + id.fp, 0);
  try {
    const st = await LedgerStore.archiveStats(id.fp);
    const state = await LedgerStore.getMeta('archiveState:' + id.fp, null);
    ST.archive.count = st.count; ST.archive.bytes = st.bytes;
    ST.archive.lastAt = state ? state.at : 0;
    ST.archive.status = st.count ? 'ready' : 'idle';
  } catch (e) { /* 归档库尚不可用时不影响主流程 */ }
  await refreshLocal(); render();
  if (navigator.storage && navigator.storage.persist) navigator.storage.persist().catch(() => {});
  synchronize();
}
/* 与服务端同步加密账本目录。只在目录真的变化时追加 profile 事件，避免每次轮询都写日志。 */
async function syncProfile() {
  if (!ST.id || !TOKEN) return;
  const me = await authed('/api/me', 'GET');
  const remote = await decodeProfile(ST.id, me.profile);
  const merged = Array.from(new Set(ST.books.concat(remote)));
  if (merged.length !== ST.books.length) {
    ST.books = merged;
    await LedgerStore.setMeta('books:' + ST.id.fp, ST.books);
    ST.id.needProfilePush = true;
    await refreshLocal();
  }
  if (ST.id.needProfilePush || !me.profile || remote.length !== ST.books.length) {
    const profile = await encodeProfile(ST.id, ST.books);
    await authed('/api/profile', 'POST', { profile });
    ST.id.needProfilePush = false;
    ST.id.profile = profile;
    cacheIdentity(ST.id);
  }
}
async function adoptServer(serverEntries, newFrom) {
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
  /* 只写入本次新增的后缀，不再每轮删光重写全部已同步记录。 */
  if (typeof newFrom === 'number' && newFrom >= 0 && newFrom <= serverEntries.length)
    await LedgerStore.putSynced(ST.id.fp, serverEntries.slice(newFrom));
  else
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
/* 副本状态只含份数与时间，很轻；每次成功同步后拉一次，用于提示「仅本机一份」的风险窗口。 */
async function refreshReplicas() {
  try {
    const r = await api('/api/replicas', 'GET', null, true);
    ST.replicas = Object.assign({}, r, { error:'' });
  } catch (e) { ST.replicas.error = e.message || '副本状态不可读'; }
}
/* 锚定证明是全量且随记录数线性增长，只在锚链头或授权集合变化时才拉取。 */
async function refreshAncillary(status, force) {
  try {
    const s = status || await api('/api/status', 'GET', null, true);
    if (!force && s.anchorHead === ST.lastAnchorHead && s.grantsVersion === ST.lastGrantsVersion) return;
    const [anchors, proof, grants, shared] = await Promise.all([
      api('/api/anchors', 'GET', null, true), api('/api/anchor-proof', 'GET', null, true),
      authed('/api/grants', 'GET'), authed('/api/shared', 'GET')
    ]);
    ST.anchors = anchors; ST.proof = proof; ST.grants = grants; ST.shared = shared.shared;
    ST.lastAnchorHead = s.anchorHead; ST.lastGrantsVersion = s.grantsVersion;
  } catch (e) { /* 核心账目已同步时，辅助信息失败不反向标记为失败 */ }
}
/* ---- 本机加密归档 ----
   首次使用即在后台静默保存「当前身份有权看到的全部账目」：自己的记录 + 被授权共享给自己看的记录。
   归档里的 cipher 本来就已是密文，这里再用独立的高强度归档密钥做第二层 AES-256-GCM 加密，
   密钥由助记词经 PBKDF2-SHA256 60 万次 + 随机 salt 派生，与身份/账本密钥分域隔离。
   归档不上传、不改变正常读写路径、不打断界面；状态在「身份备份」页安静可见，可随时清除。 */
async function archiveVault(id) {
  const k = 'archiveVault:' + id.fp;
  let p = await LedgerStore.getMeta(k, null);
  if (!p) {
    p = await ArchiveCore.createVault(id.keys.mnemonic);
    await LedgerStore.setMeta(k, p);
  }
  return ArchiveCore.openVault(id.keys.mnemonic, p);
}
async function archiveSync(status, force) {
  if (!ST.id || ST.archiving || !navigator.onLine) return;
  ST.archiving = true;
  try {
    const fp = ST.id.fp;
    const stateKey = 'archiveState:' + fp;
    const state = await LedgerStore.getMeta(stateKey, { seq:-1, anchorHead:'', count:0, at:0 });
    const s = status || await api('/api/status', 'GET', null, true);
    const mine = (s.heads || []).find(h => h.fp === fp) || { seq:0 };
    const statsNow = async () => {
      const st = await LedgerStore.archiveStats(fp);
      ST.archive = Object.assign({}, ST.archive, { count:st.count, bytes:st.bytes });
    };
    if (!force && state.seq === mine.seq && state.anchorHead === s.anchorHead) {
      await statsNow(); ST.archive.status = 'ready'; ST.archive.lastAt = state.at; return;
    }
    const vault = await archiveVault(ST.id);
    const [all, shared] = await Promise.all([
      authed('/api/entries?since=0', 'GET'), authed('/api/shared', 'GET')
    ]);
    const rows = [];
    for (const e of all.entries)
      rows.push(await ArchiveCore.seal(vault.key, { fp, source:'own', seq:e.seq,
        prevHash:e.prevHash, hash:e.hash, ts:e.ts, sig:e.sig, cipher:e.cipher, bookTag:e.bookTag },
        vault.params));
    for (const g of (shared.shared || []))
      for (const e of g.entries)
        rows.push(await ArchiveCore.seal(vault.key, { fp:g.from, source:'shared',
          grantId:g.grantId, label:g.label || '', seq:e.seq, prevHash:e.prevHash,
          hash:e.hash, ts:e.ts, sig:e.sig, cipher:e.cipher, bookTag:e.bookTag },
          vault.params));
    await LedgerStore.archiveReplace(fp, rows);
    const at = Date.now();
    await LedgerStore.setMeta(stateKey, { seq:mine.seq, anchorHead:s.anchorHead, count:rows.length, at });
    await statsNow();
    ST.archive = { status:'ready', count:ST.archive.count, bytes:ST.archive.bytes, lastAt:at, error:'' };
  } catch (e) {
    ST.archive.status = 'error';
    ST.archive.error = e.message || '归档失败';
  } finally { ST.archiving = false; }
}
/* 服务端历史丢失时，从本机归档把自己的密文记录恢复到正常读写库。
   共享给我的记录不回放（它们属于对方的历史，不该写进我的链）。 */
async function restoreFromArchive() {
  if (!ST.id) return 0;
  const fp = ST.id.fp;
  const vault = await archiveVault(ST.id);
  const rows = await LedgerStore.archiveAll(fp);
  let restored = 0, skipped = 0;
  for (const row of rows) {
    if (row.source !== 'own') continue;
    try {
      const r = await ArchiveCore.open(vault.key, row);
      await LedgerStore.put(fp, { seq:r.seq, prevHash:r.prevHash, hash:r.hash,
        ts:r.ts, sig:r.sig, cipher:r.cipher, bookTag:r.bookTag }, false);
      restored++;
    } catch (e) { skipped++; }
  }
  await refreshLocal(); render();
  return { restored, skipped };
}

async function synchronize() {
  if (!ST.id) return;
  if (ST.syncing) { ST.syncAgain = true; return; }
  let lastStatus = null;
  if (!navigator.onLine) { ST.sync.online = false; ST.sync.status = 'offline'; paintSync(); return; }
  ST.syncing = true; ST.syncAgain = false; ST.sync.status = 'syncing'; ST.sync.error = ''; paintSync();
  try {
    /* 先登记身份并同步加密账本目录，否则换设备后旧账本会被当成无法解密而漏算。 */
    await ensureSession();
    await syncProfile();
    const status = await api('/api/status', 'GET', null, true);
    lastStatus = status;
    const mine = (status.heads || []).find(h => h.fp === ST.id.fp) || { seq:0, head:GENESIS };
    const cachedSynced = ST.entries.filter(r => !r.pending).map(r => r.entry).sort((a,b) => a.seq - b.seq);
    const cachedHead = cachedSynced.length ? cachedSynced[cachedSynced.length - 1].hash : GENESIS;
    const serverUnchanged = mine.seq === cachedSynced.length && mine.head === cachedHead;
    let shrunk = mine.seq < cachedSynced.length;
    let serverChain = shrunk ? [] : cachedSynced.slice();

    /* 服务端没变化且本机没有待上传记录时，完全跳过密文与锚点的全量传输。 */
    if (!serverUnchanged || ST.outbox.length || shrunk) {
      for (let guard = 0; guard < 20; guard++) {
        await refreshLocal();
        const since = shrunk ? 0 : serverChain.length;
        const r = await authed('/api/entries?since=' + since, 'GET');
        const from = Number(r.since) || 0;
        serverChain = shrunk ? r.entries.slice() : serverChain.slice(0, from).concat(r.entries);
        shrunk = false;
        const pending = await adoptServer(serverChain, from);
        await refreshLocal();
        if (!pending.length) break;
        const plan = SyncCore.uploadBatch(serverChain, ST.outbox, 50);
        if (plan.conflict) { const err = new Error('离线队列与服务端历史不连续，同步已暂停'); err.conflict = true; throw err; }
        if (!plan.batch.length) break;
        try { await authed('/api/entries/sync', 'POST', { entries:plan.batch }); }
        catch (err) { if (err.data && err.data.results) await applySyncResults(err.data.results); throw err; }
        await refreshLocal();
      }
    }
    await refreshAncillary(status);
    await refreshReplicas();
    await refreshLocal();
    ST.sync.online = true; ST.sync.conflict = ''; ST.sync.status = ST.outbox.length ? 'idle' : 'synced';
    ST.sync.lastSync = Date.now();
    await LedgerStore.setMeta('lastSync:' + ST.id.fp, ST.sync.lastSync);
  } catch (err) {
    if (err.conflict || (err.data && err.data.conflict)) {
      ST.sync.conflict = err.message; ST.sync.status = 'conflict';
      ST.sync.forkDetail = err.detail || (err.data && err.data.conflict) || null;
    } else if (err.network || !navigator.onLine) {
      ST.sync.online = false; ST.sync.status = 'offline';
    } else {
      ST.sync.error = err.message; ST.sync.status = 'error';
    }
  } finally {
    ST.syncing = false;
    try { await refreshLocal(); } catch (e) { ST.sync.error = e.message; }
    render();
    /* 归档是后台灾备，不阻塞同步结果、不改变状态文案；失败只记在归档状态里。 */
    if (!ST.sync.conflict && navigator.onLine) setTimeout(() => archiveSync(lastStatus), 0);
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
  if (ST.quick.available && ST.mode !== 'restore' && !ST.tmp) {
    auth = '<div class="eyebrow">欢迎回来</div><h2>一键解锁本机账本</h2>' +
      '<p class="muted">这台设备已保存加密的身份凭据。输入 PIN 即可继续记账，不用每次抄写 16 个助记词。</p>' +
      '<div class="field"><label for="quick-pin">本机 PIN</label><input class="inp" id="quick-pin" type="password" inputmode="numeric" autocomplete="off" placeholder="至少 6 位"></div>' +
      '<button class="btn primary wide" data-act="unlock">解锁并进入账本</button>' +
      (ST.quick.attempts ? '<p class="fine-print warn-text">PIN 已错误 ' + ST.quick.attempts + ' 次；累计 ' + UnlockCore.MAX_ATTEMPTS + ' 次将清除本机快捷解锁。</p>' : '') +
      '<button class="text-btn" data-act="mode" data-v="restore">改用助记词 / 凭据文件恢复</button>';
  } else if (ST.tmp) {
    auth = '<div class="eyebrow">最后一步</div><h2>抄下你的 16 个助记词</h2>' +
      '<p class="muted">助记词需要配合密钥包才能恢复身份。密钥包会自动保存在本机，联网登记后也会在服务端存一份加密副本；服务端不保存明文，无法替你找回。建议联网后立即导出一份加密账本备份。</p>' + wordsHtml +
      '<label class="check-line"><input type="checkbox" id="words-ack"> 我已离线抄写，并明白助记词、密钥包与备份的关系</label>' +
      '<div class="button-stack"><button class="btn primary wide" data-act="confirm-words">创建身份并进入账本</button>' +
      '<div class="row"><button class="btn secondary" data-act="copy-words">复制助记词</button><button class="btn ghost" data-act="cancel-words">返回</button></div></div>';
  } else if (ST.mode === 'restore') {
    auth = '<div class="eyebrow">欢迎回来</div><h2>恢复你的身份</h2><p class="muted">输入 16 个助记词。已使用过的设备即使断网，也能解开本机账本。</p>' +
      '<div class="field"><label for="restore-words">助记词（空格分隔）</label><textarea class="inp" id="restore-words" rows="4" autocomplete="off" spellcheck="false" placeholder="abandon ability able ..."></textarea></div>' +
      '<button class="btn primary wide" data-act="restore">恢复并进入账本</button>' +
      '<button class="btn secondary wide" data-act="import-credential">导入身份凭据文件（无需服务端）</button>' +
      '<p class="fine-print">凭据文件内含助记词与私钥，可完全替代手抄的 16 个词；请离线保管，不要通过聊天工具传输。</p>' +
      (ST.quick.available ? '<button class="text-btn" data-act="mode" data-v="create">返回 PIN 解锁</button>' : '') +
      '<button class="text-btn" data-act="mode" data-v="create">第一次使用？创建新身份</button>';
  } else {
    auth = '<div class="eyebrow">开始使用</div><h2>你的账本，由你的密钥掌控</h2>' +
      '<p class="muted">不需要邮箱或手机号。生成助记词后，即可离线记账；联网时身份会自动登记，记录会自动同步。</p>' +
      '<div class="auth-facts"><div><b>本机先行</b><span>记录先加密封存，网络不是前提</span></div><div><b>恢复自动</b><span>联网后按顺序上传，重复提交会去掉</span></div><div><b>历史可查</b><span>哈希链、签名与外部锚点独立验证</span></div></div>' +
      (ST.inviteRequired ? '<div class="field"><label for="invite-code">邀请码</label><input class="inp" id="invite-code" autocomplete="off" placeholder="由服务管理员提供"></div>' : '') +
      '<button class="btn primary wide" data-act="gen-words">生成我的专属密钥</button>' +
      '<button class="text-btn" data-act="mode" data-v="restore">已有助记词？恢复身份</button>';
  }
  $('#app').innerHTML = '<div class="auth-shell"><section class="auth-story">' + brand() +
    '<div class="story-copy"><div class="eyebrow">离线优先 · 自动同步 · 只追加</div><h1>断网也能记，<br>联网自然同步。</h1>' +
    '<p>一套账本，一种体验。无论网络是否可用，记录都会先在你的设备上完成加密、签名和封存。</p></div>' +
    '<div class="story-proof"><span>端到端加密</span><span>本机待同步队列</span><span>公开哈希验证</span></div>' +
    '<div class="public-inline" id="public-status">正在读取公开账本状态…</div></section>' +
    '<section class="auth-panel"><div class="auth-card">' + auth + '</div><p class="auth-foot">首次使用会在本机后台自动保存一份加密归档（仅你有权看到的内容），可在「身份备份」查看状态或清除。明文不离开浏览器 · 没有修改或删除接口</p></section></div>';
  loadPublicStatus();
}
async function loadPublicStatus() {
  const el = $('#public-status'); if (!el) return;
  if (!navigator.onLine) { el.textContent = '当前离线：仍可创建身份并开始记账'; return; }
  try {
    const [a, s] = await Promise.all([
      api('/api/anchors', 'GET', null, true), api('/api/status', 'GET', null, true)
    ]);
    ST.anchors = a;
    const was = ST.inviteRequired;
    ST.inviteRequired = !!s.inviteRequired;
    if (!was && ST.inviteRequired && !ST.id) { render(); return; }
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
  if (ST.sync.conflict) return '<div class="notice danger"><b>同步已暂停</b><p>' + esc(ST.sync.conflict) + '</p><span>请先在「身份备份」导出本机加密账本。不要清空浏览器数据，也不要在另一设备继续写入。</span>' +
    '<div class="button-row"><button class="btn small danger" data-act="export-fork">导出分叉证据</button>' +
    '<button class="btn small secondary" data-act="resolve-fork">以服务端为准重建本机</button></div></div>';
  if (ST.undecryptable) return '<div class="notice warning"><b>' + ST.undecryptable + ' 笔密文未能解密，金额统计不完整</b><p>本机缺少这些记录对应的账本名称或密钥，总览与明细的合计不包含它们，请暂时不要据此对账。</p><span>联网后会自动从服务端同步加密的账本目录；也可在「身份备份」导入此前导出的加密账本文件。</span></div>';
  if (!navigator.onLine || !ST.sync.online || ST.sync.status === 'offline') return '<div class="notice offline"><b>当前离线，记账不受影响</b><p>新记录会加密保存在这台设备，并进入待同步队列。恢复网络后无需手动补录。</p></div>';
  if (ST.sync.status === 'error') return '<div class="notice warning"><b>本次同步未完成</b><p>' + esc(ST.sync.error || '将在下次连接时自动重试') + '</p><span>记录仍保存在本机，不会丢失或重复上传。</span></div>';
  if (ST.outbox.length) return '<div class="notice pending"><b>' + ST.outbox.length + ' 笔记录等待上传</b><p>它们已经完成本机加密与签名，将按账本顺序自动同步。</p></div>';
  return '<div class="notice success"><b>本机与服务端一致</b><p>所有已解密记录均已同步。最近确认：' + (ST.sync.lastSync ? new Date(ST.sync.lastSync).toLocaleString('zh-CN') : '本次会话') + '</p></div>';
}
function replicaNotice() {
  const r = ST.replicas || {};
  const last = r.lastBackupAt ? new Date(r.lastBackupAt).toLocaleString('zh-CN') : '尚未生成';
  const ok = (r.totalBackups || 0) > 0;
  return '<section class="panel replica-panel"><div class="panel-head"><div>' +
    '<span class="section-kicker">REPLICAS</span><h2>数据副本</h2></div>' +
    '<span class="tag ' + (ok ? 'good' : 'pending') + '">' + (ok ? '已有加密异地备份' : '未配置加密异地备份') + '</span></div>' +
    '<div class="replica-grid">' +
      '<div><span>本机</span><b>1 份</b></div>' +
      '<div><span>服务端</span><b>1 份</b></div>' +
      '<div><span>加密备份</span><b>' + (r.totalBackups || 0) + ' 份 · ' + (r.configured || 0) + ' 个目标</b></div>' +
      '<div><span>最后备份</span><b>' + esc(last) + '</b></div>' +
    '</div>' +
    (ST.outbox.length
      ? '<div class="fine-print warn-text">有 ' + ST.outbox.length + ' 笔尚未同步：此刻它们只在这台设备上，设备损坏或清除浏览器数据会永久丢失，请尽快联网。</div>'
      : '<div class="fine-print">已同步记录在本机、服务端与加密备份中各有副本。备份由服务端守护进程自动生成，可在 <span class="mono">/api/replicas</span> 核对。</div>') +
    (r.error ? '<div class="fine-print warn-text">副本状态读取失败：' + esc(r.error) + '</div>' : '') +
  '</section>';
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
/* 首页随手记：金额 + 方向 + 可选摘要，一步提交；其余字段用默认值，不打断连续记账。 */
function quickEntryForm() {
  return '<form class="quick-entry" id="quick-form">' +
    '<div class="quick-amount"><span>¥</span><input class="inp" id="q-amount" inputmode="decimal" autocomplete="off" placeholder="0.00" aria-label="金额" required></div>' +
    '<select class="inp" id="q-type" aria-label="收支方向"><option value="expense">支出</option><option value="income">收入</option></select>' +
    '<input class="inp" id="q-note" maxlength="120" placeholder="摘要（选填，记下后不可修改）" aria-label="摘要">' +
    '<button class="btn primary" type="submit">记一笔</button></form>';
}
function emptyState(title, text) { return '<div class="empty"><b>' + esc(title) + '</b><p>' + esc(text) + '</p></div>'; }
function recentRows(list, actions) {
  if (!list.length) return emptyState('还没有账目', '第一笔记录会同时出现在本机明细与同步队列中。');
  return '<div class="transaction-list">' + list.map(p => '<div class="transaction"><div class="transaction-main"><div class="transaction-title">' + esc(p.note || (p.type === 'income' ? '收入' : '支出')) + (p.reversalOf ? '<span class="tag neutral">冲销</span>' : '') + '</div>' +
    '<div class="transaction-meta">' + esc(p.date) + '<i></i>' + esc(p.book) + '<i></i>#' + p.seq + '</div></div>' +
    '<div class="transaction-side"><div class="amount ' + (p.type === 'income' ? 'income' : 'expense') + '">' + (p.type === 'income' ? '+' : '−') + fmt(p.amount) + '</div>' +
    '<span class="tag ' + (p.pending ? 'pending' : 'good') + '">' + (p.pending ? '待同步 · 仅本机一份' : '已同步') + '</span></div>' +
    (actions ? '<button class="text-btn reverse-link" data-act="reverse-entry" data-hash="' + esc(p.hash) + '">红字冲销</button>' : '') + '</div>').join('') + '</div>';
}
function viewOverview() {
  const t = totals(), recent = ST.plain.slice().reverse().slice(0,6);
  return '<section class="page-intro"><div><div class="eyebrow">' + new Date().toLocaleDateString('zh-CN', { month:'long', day:'numeric', weekday:'long' }) + '</div><h1>今天，也把账记清楚。</h1><p>网络只决定何时上传，不决定能否记账。</p></div><button class="btn secondary desktop-only" data-act="tab" data-v="records">查看全部明细</button></section>' +
    '<section class="panel quick-panel"><div class="panel-head"><div><span class="section-kicker">QUICK ENTRY</span><h2>随手记一笔</h2></div>' +
      '<span class="tag neutral">默认今天 · 当前账本 ' + esc(ST.book) + '</span></div>' + quickEntryForm() +
      '<div class="fine-print">记下后不可修改；记错请在明细里追加红字冲销。完整表单在「记一笔」页。</div></section>' +
    '<section class="kpi-grid"><div class="kpi"><span>净额</span><strong>' + fmt(t.net) + '</strong><small>收入减去支出，含本机待同步</small></div>' +
    '<div class="kpi"><span>累计收入</span><strong class="income">' + fmt(t.income) + '</strong><small>' + ST.plain.filter(x => x.type === 'income').length + ' 笔已解密记录' + (ST.undecryptable ? ' · ' + ST.undecryptable + ' 笔未计入' : '') + '</small></div>' +
    '<div class="kpi"><span>累计支出</span><strong>' + fmt(t.expense) + '</strong><small>' + ST.plain.filter(x => x.type !== 'income').length + ' 笔已解密记录' + (ST.undecryptable ? ' · ' + ST.undecryptable + ' 笔未计入' : '') + '</small></div>' +
    '<div class="kpi sync-kpi"><span>待同步</span><strong data-pending-count>' + ST.outbox.length + '</strong><small>本机已封存，联网自动上传</small></div></section>' +
    syncNotice() + replicaNotice() +
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
  return '<section class="page-intro compact-intro"><div><h1>全部账目</h1><p>共 ' + ST.plain.length + ' 笔可解密记录，当前显示 ' + list.length + ' 笔。' + (ST.undecryptable ? '另有 ' + ST.undecryptable + ' 笔未能解密，未包含在合计中。' : '') + '</p></div><button class="btn primary" data-act="tab" data-v="entry">记一笔</button></section>' +
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
    '<div class="fine-print">本机快捷解锁：<b>' + (ST.quick.available ? '已启用' : '未启用') + '</b>。' +
      (ST.quick.available ? '每次打开输入 PIN 即可，无需抄写助记词。' : '启用后每次打开只需 PIN，不必抄写 16 个助记词。') +
      ' PIN 只保护本机便利，能接触本机存储的人可离线尝试；助记词仍是唯一跨设备恢复凭据。</div>' +
    '<div class="button-row">' +
      (ST.quick.available ? '<button class="btn secondary" data-act="disable-quick">关闭快捷解锁</button>' : '<button class="btn secondary" data-act="enable-quick">启用快捷解锁</button>') +
      '<button class="btn ghost" data-act="export-credential">导出身份凭据文件</button></div>' +
    '<p class="muted">服务端只保存公钥、助记词加密的私钥包、密文记录与哈希链，没有邮箱、手机号或密码。</p></section>' +
    '<section class="panel"><div class="panel-head"><div><span class="section-kicker">BACKUP</span><h2>加密备份与迁移</h2></div></div><p class="muted">导出文件包含本机全部已同步与待同步密文。导入另一台设备后，会并入待同步队列，由幂等规则去掉服务端已有记录。</p>' +
    '<div class="storage-stats"><div><span>本机密文记录</span><b>' + ST.entries.length + '</b></div><div><span>待同步</span><b>' + ST.outbox.length + '</b></div><div><span>本机链高</span><b>' + ST.me.seq + '</b></div><div><span>未能解密</span><b>' + ST.undecryptable + '</b></div></div>' +
    '<div class="fine-print">本机加密归档：<b>' + ST.archive.count + '</b> 笔 · ' + (ST.archive.bytes / 1024).toFixed(1) + ' KB · ' +
      (ST.archive.status === 'error' ? '<span class="warn-text">' + esc(ST.archive.error) + '</span>'
        : ST.archive.lastAt ? '上次更新 ' + esc(new Date(ST.archive.lastAt).toLocaleString('zh-CN')) : '等待首次归档') + '</div>' +
    '<div class="button-row"><button class="btn primary" data-act="export-ledger">导出加密账本</button><button class="btn secondary" data-act="import-ledger">导入账本文件</button>' +
      '<button class="btn secondary" data-act="export-archive">导出加密归档</button><button class="btn secondary" data-act="import-archive">导入加密归档</button>' +
      '<button class="btn ghost" data-act="clear-archive">清除本机归档</button><button class="btn ghost" data-act="restore-archive">从归档恢复</button></div>' +
    '<div class="fine-print">归档在后台自动保存你有权看到的全部账目（自己的记录 + 被授权共享给你看的记录），并用独立密钥二次加密：PBKDF2-SHA256 60 万次派生 + AES-256-GCM + 逐条随机 IV 与 AAD 绑定 + 格式版本防降级。它不上传、不打扰记账、不含明文；只有输入对应助记词才能解开。你可以随时在这里查看状态或清除。</div>' +
    '<div class="fine-print warn-text">助记词必须配合密钥包才能恢复身份：密钥包会自动保存在本机，联网登记后也存一份加密副本在服务端。离线创建且从未联网的身份，请务必导出加密账本备份。清除浏览器数据会删除尚未上传的本机记录。</div></section>' +
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
  await refreshAncillary(null, true); render(); toast('授权已生成，对方现在可以解开这个账本');
}
async function viewShared(grantId) {
  const g = (ST.shared || []).find(x => x.grantId === grantId); if (!g) return;
  const other = await api('/api/pub/' + g.from, 'GET', null, false);
  const bits = await subtle().deriveBits({ name:'ECDH', public:await importDhPub(other.pubDh) }, await importDhPriv(ST.id), 256);
  const wrap = await aesKey(new Uint8Array(bits), ['encrypt','decrypt']);
  const raw = await aesDecRaw(wrap, g.wrappedKey), bk = await aesKey(raw, ['decrypt']);
  const rows = [];
  for (const e of g.entries) {
    try { const p = await aesDec(bk, e.cipher); rows.push({ plain:Object.assign({}, p, { seq:e.seq, hash:e.hash, book:g.label || '共享账本', pending:false }) }); }
    catch (err) {}
  }
  modal('<div class="eyebrow">共享账本</div><h2>' + esc(g.label || '共享账本') + '</h2><p class="muted">来自 ' + esc(g.from) + ' · 已用当前私钥解开</p>' +
    (rows.length ? recentRows(rows.map(x => x.plain).reverse(), false) : emptyState('暂无可解密记录','这个账本还没有记录')) +
    '<div class="button-row"><button class="btn secondary" data-act="close-modal">关闭</button></div>');
}

/* ---------------- 交互 ---------------- */
document.addEventListener('submit', async e => {
  if (e.target.id === 'quick-form') {
    e.preventDefault();
    try {
      const amount = Math.round(Number(String($('#q-amount').value).replace(/[^\d.]/g, '')) * 100);
      if (!amount || amount <= 0) throw new Error('请输入有效金额');
      await addEntry({ type:$('#q-type').value, amount, book:ST.book, date:today(),
        note:$('#q-note').value.trim(), party:'', voucher:'' });
      const el = $('#q-amount'); if (el) { el.value = ''; el.focus(); }
    } catch (err) { toast(err.message || '记账失败', 'err'); }
    return;
  }
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
        if ($('#invite-code')) ST.inviteCode = $('#invite-code').value.trim();
        const id = await createIdentity(ST.tmp);
        await startIdentity(id);
        toast('身份已创建。现在即使断网，也可以开始记账'); break;
      }
      case 'restore': {
        if ($('#invite-code')) ST.inviteCode = $('#invite-code').value.trim();
        const m = normMnemonic($('#restore-words').value);
        if (m.split(' ').length !== 16) throw new Error('需要 16 个助记词');
        if (m.split(' ').some(w => WORDS.indexOf(w) < 0)) throw new Error('有词不在词表里，请检查拼写');
        const id = await restoreIdentity(m); await startIdentity(id); toast('身份已恢复，本机密文账本已解密'); break;
      }
      case 'logout':
        TOKEN = ''; ST.id = null; ST.plain = []; ST.entries = []; ST.outbox = []; ST.me = { seq:0, head:GENESIS };
        ST.undecryptable = 0; ST.books = ['个人账','公司资金']; ST.book = '个人账';
        ST.lastAnchorHead = null; ST.lastGrantsVersion = null;
        ST.archive = { status:'idle', count:0, bytes:0, lastAt:0, error:'' }; ST.inviteCode = '';
        ST.grants = null; ST.shared = null; ST.tmp = null;
        ST.mode = ST.quick.available ? 'create' : 'restore'; render(); break;
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
      case 'public-check': case 'refresh-anchors': {
        ST.anchors = await api('/api/anchors', 'GET', null, true);
        ST.proof = await api('/api/anchor-proof', 'GET', null, true);
        const s = await api('/api/status', 'GET', null, true);
        ST.lastAnchorHead = s.anchorHead; ST.lastGrantsVersion = s.grantsVersion;
        if (!ST.id) loadPublicStatus(); else render();
        toast('公开哈希与锚链已刷新'); break;
      }
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
          ST.id.needProfilePush = true;
          await LedgerStore.setMeta('books:' + ST.id.fp, ST.books); render();
          if (navigator.onLine) synchronize();
          else toast('账本目录已存本机，联网后会自动同步到服务端', 'warn');
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
      case 'revoke': await authed('/api/revoke', 'POST', { grantId:el.dataset.id }); await refreshAncillary(null, true); render(); toast('授权已撤销'); break;
      case 'view-shared': await viewShared(el.dataset.id); break;
      case 'export-fork': case 'resolve-fork': {
        await refreshLocal();
        const server = await api('/api/anchors/' + encodeURIComponent(ST.id.fp), 'GET', null, true).catch(() => null);
        const evidence = {
          app:'简记分叉证据', version:1, exportedAt:new Date().toISOString(), fp:ST.id.fp,
          conflict:ST.sync.conflict, detail:ST.sync.forkDetail || null,
          server:server ? { head:server.head, seq:server.seq, count:server.count } : null,
          localHead:ST.me.head, localSeq:ST.me.seq,
          entries:ST.entries.map(r => ({ pending:!!r.pending, entry:r.entry })),
          note:'仅含密文与公开哈希，不含账目明文；可安全交给管理员诊断。'
        };
        downloadJSON(evidence, (a === 'export-fork' ? '简记_分叉证据_' : '简记_重建前备份_') + today() + '.json');
        if (a === 'export-fork') { toast('分叉证据已导出'); break; }
        if (!confirm('已先下载本机完整备份。\n\n接下来会清除本机记录，并从服务端重新拉取权威历史。本机独有的待同步记录不会自动合并，需要你从备份里人工核对后重新录入或冲销。\n\n确定继续？')) break;
        if (!confirm('再次确认：此操作会移除本机尚未上传的记录（已保存在刚下载的备份中）。加密归档不会删除。')) break;
        await LedgerStore.clear(ST.id.fp);
        ST.sync.conflict = ''; ST.sync.error = ''; ST.sync.forkDetail = null;
        ST.lastAnchorHead = null; ST.lastGrantsVersion = null;
        await refreshLocal(); render();
        toast('本机已重置，正在从服务端重建');
        synchronize();
        break;
      }
      case 'export-archive': {
        const rows = await LedgerStore.archiveAll(ST.id.fp);
        const params = await LedgerStore.getMeta('archiveVault:' + ST.id.fp, null);
        if (!params) throw new Error('本机尚未生成归档密钥，请先联网同步一次');
        const portable = rows.map(r => r.vault ? r : Object.assign({}, r, { vault:ArchiveCore.publicParams(params) }));
        downloadJSON({ app:'简记加密归档', version:1, fp:ST.id.fp, exportedAt:new Date().toISOString(),
          vault:ArchiveCore.publicParams(params), rows:portable,
          note:'仅含双层加密密文与非秘密密钥参数；必须配合本身份助记词才能解开。' },
          '简记_加密归档_' + today() + '.json');
        toast('已导出 ' + portable.length + ' 条加密归档记录'); break;
      }
      case 'import-archive': {
        const input = document.createElement('input'); input.type = 'file'; input.accept = '.json';
        input.onchange = async () => {
          const f = input.files && input.files[0]; if (!f) return;
          try {
            const pack = JSON.parse(await f.text());
            if (!pack.fp || !Array.isArray(pack.rows)) throw new Error('不是有效的简记加密归档');
            if (pack.fp !== ST.id.fp) throw new Error('这份归档属于身份 ' + pack.fp + '，请用对应助记词登录');
            const params = pack.vault || (pack.rows[0] && pack.rows[0].vault);
            const vault = await ArchiveCore.openVault(ST.id.keys.mnemonic, params);
            let ok = 0;
            for (const row of pack.rows) { await ArchiveCore.open(vault.key, row); ok++; }
            await LedgerStore.archiveReplace(ST.id.fp, pack.rows);
            await LedgerStore.setMeta('archiveVault:' + ST.id.fp, params);
            await LedgerStore.setMeta('archiveState:' + ST.id.fp,
              { seq:-1, anchorHead:'', count:ok, at:Date.now() });
            const stats = await LedgerStore.archiveStats(ST.id.fp);
            ST.archive = { status:'ready', count:stats.count, bytes:stats.bytes, lastAt:Date.now(), error:'' };
            render();
            modal('<div class="eyebrow">归档已导入</div><h2>导入完成</h2><p class="muted">校验通过 ' + ok +
              ' 条加密记录。可点「从归档恢复」把属于你的记录写回本机账本；联网后归档会随服务端最新历史更新，若服务端历史已丢失请先恢复再联网。</p>' +
              '<div class="button-row"><button class="btn primary" data-act="close-modal">完成</button></div>');
          } catch (err) { toast(err.message, 'err'); }
        };
        input.click(); break;
      }
      case 'clear-archive': {
        if (!confirm('确定清除这台设备上的加密归档吗？正常账本与已同步记录不受影响，归档会在下次联网时自动重建。')) break;
        await LedgerStore.archiveClear(ST.id.fp);
        await LedgerStore.setMeta('archiveState:' + ST.id.fp, { seq:-1, anchorHead:'', count:0, at:0 });
        ST.archive = { status:'idle', count:0, bytes:0, lastAt:0, error:'' };
        render(); toast('本机加密归档已清除'); break;
      }
      case 'restore-archive': {
        if (!confirm('从本机加密归档恢复：把归档里属于你的密文记录重新写回本机账本。仅在服务端历史丢失或换设备时使用，继续？')) break;
        const r = await restoreFromArchive();
        toast('已从归档恢复 ' + r.restored + ' 笔' + (r.skipped ? '，跳过 ' + r.skipped + ' 笔异常记录' : '')); break;
      }
      case 'enable-quick': {
        modal('<div class="eyebrow">本机快捷解锁</div><h2>设置解锁 PIN</h2>' +
          '<p class="muted">之后在这台设备打开账本只需输入 PIN，不必每次抄写 16 个助记词。</p>' +
          '<div class="field"><label for="q-pin1">PIN（至少 6 位）</label><input class="inp" id="q-pin1" type="password" inputmode="numeric" autocomplete="new-password"></div>' +
          '<div class="field"><label for="q-pin2">再输入一次</label><input class="inp" id="q-pin2" type="password" inputmode="numeric" autocomplete="new-password"></div>' +
          '<div class="notice warning"><b>请理解安全边界</b><p>PIN 只用于本机便利。浏览器本地存储没有 Secure Enclave 保护，能接触到这台设备存储的人可以离线尝试 PIN；请设 6 位以上，并照常离线保管助记词。</p></div>' +
          '<div class="button-row"><button class="btn primary" data-act="confirm-quick">启用</button><button class="btn ghost" data-act="close-modal">取消</button></div>');
        break;
      }
      case 'confirm-quick': {
        const p1 = $('#q-pin1').value, p2 = $('#q-pin2').value;
        if (p1 !== p2) throw new Error('两次输入的 PIN 不一致');
        const pack = await UnlockCore.seal(p1, credentialFromId(ST.id));
        try { localStorage.setItem(QUICK_KEY, JSON.stringify(pack)); }
        catch (e) { throw new Error('本机存储不可用，无法启用快捷解锁'); }
        ST.quick = { available:true, fp:ST.id.fp, attempts:0 };
        $('.modal-bg')?.remove(); render(); toast('本机快捷解锁已启用'); break;
      }
      case 'unlock': {
        const pin = $('#quick-pin').value;
        let pack = null;
        try { pack = JSON.parse(localStorage.getItem(QUICK_KEY) || 'null'); } catch (e) {}
        if (!pack) throw new Error('本机快捷解锁数据不存在，请用助记词恢复');
        try {
          const c = await UnlockCore.open(pin, pack);
          pack.attempts = 0;
          localStorage.setItem(QUICK_KEY, JSON.stringify(pack));
          ST.quick.attempts = 0;
          const id = await identityFromCredential(c);
          await startIdentity(id);
          toast('已通过本机 PIN 解锁');
        } catch (e) {
          const attempts = (pack.attempts || 0) + 1;
          if (attempts >= UnlockCore.MAX_ATTEMPTS) {
            localStorage.removeItem(QUICK_KEY);
            ST.quick = { available:false, fp:'', attempts:0 };
            render();
            throw new Error('PIN 连续错误过多，已清除本机快捷解锁，请用助记词恢复');
          }
          pack.attempts = attempts;
          localStorage.setItem(QUICK_KEY, JSON.stringify(pack));
          ST.quick.attempts = attempts;
          render();
          throw new Error('PIN 不正确（还可尝试 ' + (UnlockCore.MAX_ATTEMPTS - attempts) + ' 次）');
        }
        break;
      }
      case 'disable-quick': {
        if (!confirm('关闭后这台设备每次打开都需要输入助记词，确定？')) break;
        localStorage.removeItem(QUICK_KEY);
        ST.quick = { available:false, fp:'', attempts:0 };
        render(); toast('本机快捷解锁已关闭'); break;
      }
      case 'export-credential': {
        if (!confirm('即将导出明文身份凭据（含助记词与私钥）。任何人拿到它都能完全控制你的身份并解开全部账目。确定继续？')) break;
        downloadJSON(Object.assign({ app:'简记身份凭据', version:1,
          exportedAt:new Date().toISOString(),
          note:'明文最高敏感材料，请离线保管，不要通过聊天工具传输。' }, credentialFromId(ST.id)),
          '简记_身份凭据_' + today() + '.json');
        toast('身份凭据已导出，请离线保管'); break;
      }
      case 'import-credential': {
        const input = document.createElement('input'); input.type = 'file'; input.accept = '.json';
        input.onchange = async () => {
          const f = input.files && input.files[0]; if (!f) return;
          try {
            const c = JSON.parse(await f.text());
            if (!UnlockCore.validateCredential(c)) throw new Error('不是有效的简记身份凭据文件');
            const id = await identityFromCredential(c);
            cacheIdentity(id);
            await startIdentity(id);
            toast('已从凭据文件恢复身份（无需服务端）');
          } catch (err) { toast(err.message, 'err'); }
        };
        input.click(); break;
      }
      case 'copy-fp': await copy(ST.id.fp); break;
      case 'show-words':
        modal('<div class="eyebrow">敏感信息</div><h2>你的助记词</h2><div class="notice danger"><b>确认周围没有人</b><p>任何看到这 16 个词的人都能控制你的身份并解开账本。</p></div>' +
          '<div class="words">' + ST.id.keys.mnemonic.split(' ').map((w,i) => '<div class="word"><b>' + String(i+1).padStart(2,'0') + '</b><span>' + esc(w) + '</span></div>').join('') + '</div>' +
          '<div class="button-row"><button class="btn secondary" data-act="copy-words-now">复制</button><button class="btn ghost" data-act="close-modal">关闭</button></div>'); break;
      case 'copy-words-now': await copy(ST.id.keys.mnemonic); break;
      case 'export-ledger': {
        await refreshLocal();
        const entries = ST.entries.map(r => r.entry).sort((a,b) => a.seq - b.seq);
        downloadJSON({ app:'简记统一离线账本', version:4, fp:ST.id.fp, exportedAt:new Date().toISOString(),
          pubSign:ST.id.pubSign, identity:cachedIdentity(), books:ST.books, entries,
          archiveVault:await LedgerStore.getMeta('archiveVault:' + ST.id.fp, null),
          anchors:ST.anchors, proof:ST.proof },
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
            /* 迁移包里的归档密钥参数只在本地还没有时写入，避免覆盖既有 salt 导致旧归档解不开。 */
            if (pack.archiveVault && pack.archiveVault.version === ArchiveCore.VERSION &&
                !await LedgerStore.getMeta('archiveVault:' + ST.id.fp, null))
              await LedgerStore.setMeta('archiveVault:' + ST.id.fp, pack.archiveVault);
            if (Array.isArray(pack.books)) {
              const before = ST.books.length;
              ST.books = Array.from(new Set(ST.books.concat(pack.books.filter(x => typeof x === 'string'))));
              if (ST.books.length !== before) ST.id.needProfilePush = true;
              await LedgerStore.setMeta('books:' + ST.id.fp, ST.books);
            }
            await refreshLocal(); render();
            modal('<div class="eyebrow">备份已并入</div><h2>导入完成</h2><p class="muted">新增 ' + fresh.length + ' 条密文记录；服务端已经存在的记录会在同步时自动确认，不会重复入账。</p>' +
              '<div class="notice success"><b>本机链高 ' + ST.me.seq + '</b><p>当前共有 ' + ST.outbox.length + ' 笔等待联网确认。</p></div><div class="button-row"><button class="btn primary" data-act="close-modal">完成</button></div>');
            if (fresh.length || ST.id.needProfilePush) synchronize();
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
  const q = JSON.parse(localStorage.getItem(QUICK_KEY) || 'null');
  if (q && q.version === UnlockCore.VERSION && q.fp)
    ST.quick = { available:true, fp:q.fp, attempts:q.attempts || 0 };
} catch (e) { document.documentElement.dataset.theme = 'light'; }
if (!crypto || !crypto.subtle || !window.isSecureContext) {
  $('#app').innerHTML = '<div class="fatal"><h1>需要安全上下文</h1><p>Web Crypto 要求 HTTPS 或 localhost。请通过部署后的 HTTPS 地址，或本机 http://127.0.0.1 访问。</p></div>';
} else {
  render();
  if ('serviceWorker' in navigator) window.addEventListener('load', () => navigator.serviceWorker.register('/sw.js').catch(() => {}));
}
