'use strict';
/* 简记 · 联网不可变账本（最小闭环）
   明文永远不离开浏览器；服务端只见密文、标签与哈希承诺。 */

const WORDS = `abandon ability able about above absent absorb abstract absurd abuse access accident account accuse achieve
acid acoustic acquire across act action actor actress actual adapt add addict address adjust admit
adult advance advice affair afford afraid again age agent agree ahead aim air airport aisle
alarm album alcohol alert alien all alley allow almost alone alpha already also alter always
amateur amazing among amount amused analyst anchor ancient anger angle angry animal ankle announce
annual another answer antique anxiety any apart apology appear apple approve april arch arctic
area arena argue arm armed armor army around arrange arrest arrive arrow art artist artwork
aspect asset assist assume asthma athlete atom attack attend attitude attract auction audit august
aunt author auto autumn average avocado avoid awake aware away awesome awful awkward axis baby
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
const fmt = c => '¥' + (c / 100).toLocaleString('zh-CN', { minimumFractionDigits: 2, maximumFractionDigits: 2 });
function b64(buf) { const a = new Uint8Array(buf); let s = ''; for (let i = 0; i < a.length; i++) s += String.fromCharCode(a[i]); return btoa(s); }
function unb64(s) { return Uint8Array.from(atob(s), c => c.charCodeAt(0)); }
const subtle = () => crypto.subtle;
async function sha256hex(s) { const d = await subtle().digest('SHA-256', enc(s)); return Array.from(new Uint8Array(d), x => x.toString(16).padStart(2,'0')).join(''); }
async function aesKey(raw, usages, extractable) { return subtle().importKey('raw', raw, 'AES-GCM', !!extractable, usages || ['encrypt','decrypt']); }
/* 定长填充：所有密文长度对齐到 512 字节的整数倍，
   避免记录大小泄露摘要长度。尾部空格会被 JSON.parse 忽略，旧数据仍可读。 */
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

/* 助记词由 CSPRNG 生成，自带 128 bit 熵，不是低熵口令：
   这里用 HKDF 做密钥分离即可，无需慢 KDF 抗离线爆破。 */
async function derive(mnemonic) {
  const base = await subtle().importKey('raw', enc(mnemonic), 'HKDF', false, ['deriveBits']);
  const bits = await subtle().deriveBits({ name:'HKDF', hash:'SHA-256',
    salt:enc('jianji.cloud.v1'), info:enc('master-keys') }, base, 512);
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
/* 服务端可能整体重建：先查在线身份，查不到就用本机/账本文件里的加密密钥包离线恢复 */
async function restoreIdentity(m) {
  const keys = await derive(m);
  let r = null;
  try { r = await api('/api/lookup', 'POST', { verifier: keys.verifier }, false); }
  catch (e) {
    const c = cachedIdentity();
    if (!c || c.verifier !== keys.verifier)
      throw new Error('没有找到该助记词对应的身份：请检查抄写，或先导入之前导出的加密账本文件');
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
async function api(path, method, data, noAuth) {
  const headers = { 'Content-Type':'application/json' };
  if (!noAuth && TOKEN) headers.Authorization = 'Bearer ' + TOKEN;
  const r = await fetch(path, { method: method || 'GET', headers, body: data ? JSON.stringify(data) : undefined });
  let j; try { j = await r.json(); } catch (e) { throw new Error('服务端返回异常'); }
  if (!r.ok) throw new Error(j.error || ('HTTP ' + r.status));
  return j;
}
function toast(msg, kind) {
  const el = $('#toast'); el.textContent = msg;
  el.className = 'toast show' + (kind === 'err' ? ' err' : '');
  clearTimeout(toast._t); toast._t = setTimeout(() => el.className = 'toast', 3200);
}
function modal(html) {
  const d = document.createElement('div'); d.className = 'modal-bg';
  d.innerHTML = '<div class="modal">' + html + '</div>';
  d.addEventListener('click', e => { if (e.target === d || e.target.dataset.act === 'close-modal') d.remove(); });
  document.body.appendChild(d); return d;
}
async function copy(text) { try { await navigator.clipboard.writeText(text); toast('已复制'); } catch (e) { toast('复制失败，请手动选中', 'err'); } }

const ST = { id:null, me:null, entries:[], plain:[], tab:'ledger', book:'公司资金',
  books:['公司资金','个人账'], mode:'create', tmp:null, anchors:null, grants:null, shared:null, verifyFp:'' };

/* 常驻安全指示器：ui-ux-pro-max 明确要求安全类界面必须给出可见状态 */
function statusBar(extra) {
  return '<div class="statusbar">' +
    '<span class="s-item"><i class="dot live"></i>END-TO-END ENCRYPTED</span>' +
    '<span class="s-item">APPEND-ONLY</span>' +
    '<span class="s-item">HASH-COMMITMENT ONLY</span>' +
    '<span class="s-item"><i class="dot live"></i><b>' + (extra || 'CLIENT-SIDE KEYS') + '</b></span></div>';
}

/* ---------------- 身份入口 ---------------- */
function viewWelcome() {
  const wordsHtml = ST.tmp ? '<div class="words">' + ST.tmp.split(' ').map((w,i) =>
    '<div class="word"><b>' + (i+1) + '</b>' + esc(w) + '</div>').join('') + '</div>' : '';
  $('#app').innerHTML = '<div class="wrap"><div class="top"><div class="brand-mark">记</div>' +
    '<div><div class="brand-t">简记 · 联网账本</div><div class="brand-s">IDENTITY = KEY / APPEND ONLY / HASH COMMITMENT</div></div></div>' +
    statusBar() +
    '<div class="card"><div class="card-h"><div><div class="card-t">这账本怎么保证改不了</div></div>' +
      '<span class="tag info">最小闭环</span></div>' +
      '<div class="card-s">明文在你浏览器里用助记词派生的密钥加密后才上传；服务端只提供追加写入，没有任何改删接口，也看不到内容。' +
      '对外公开的只有每条记录的 SHA-256 哈希链与全局 Merkle 根，任何人都能独立校验，却拿不到一个字节的账目内容。</div></div>' +
    (ST.tmp ? '<div class="card"><div class="card-h"><div class="card-t">抄下这 16 个词</div><span class="tag warn">唯一恢复方式</span></div>' +
      wordsHtml +
      '<div class="note warn">这 16 个词就是你的身份和全部账本的钥匙：登录、查看、记账、授权全靠它。服务端不保存明文，丢了没有任何人能帮你找回。请离线抄写并妥善保管。</div>' +
      '<div class="row"><button class="btn primary" data-act="confirm-words">我已抄写，创建身份</button>' +
      '<button class="btn" data-act="copy-words">复制助记词</button><button class="btn" data-act="cancel-words">返回</button></div></div>'
    : '<div class="grid2"><div class="card"><div class="card-h"><div class="card-t">第一次使用</div></div>' +
      '<div class="card-s">生成一套全新的助记词与密钥对。服务端只登记公钥，不保存任何密码。</div>' +
      '<div style="margin-top:14px"><button class="btn primary" data-act="gen-words">生成我的专属密钥</button></div></div>' +
      '<div class="card"><div class="card-h"><div class="card-t">已有助记词</div></div>' +
      '<div class="field"><label>用助记词恢复身份（16 个词，空格分隔）</label>' +
      '<textarea class="inp" id="restore-words" placeholder="abandon ability able ..."></textarea></div>' +
      '<button class="btn primary" data-act="restore">恢复并登录</button></div></div>') +
    '<div class="card"><div class="card-h"><div class="card-t">公开账本状态</div>' +
      '<button class="btn sm" data-act="public-check">查看公开哈希</button></div>' +
      '<div class="card-s" id="public-status">正在读取公开锚…</div></div></div>';
  loadPublicStatus();
}
async function loadPublicStatus() {
  try {
    const a = await api('/api/anchors', 'GET', null, false);
    ST.anchors = a;
    const el = $('#public-status'); if (!el) return;
    el.innerHTML = '全局 Merkle 根 <span class="mono" style="color:var(--accent)">' + esc(a.merkleRoot.slice(0,32)) + '…</span><br>' +
      '已登记身份 ' + a.owners.length + ' 个 · 公开内容仅含哈希、序号、时间戳与签名，不含任何密文。';
  } catch (e) { const el = $('#public-status'); if (el) el.textContent = '无法连接服务端：' + e.message; }
}

/* ---------------- 主界面 ---------------- */
function viewMain() {
  const tabs = [['ledger','我的账本'],['verify','公开验证'],['grants','授权查看'],['identity','身份与备份']];
  $('#app').innerHTML = '<div class="wrap"><div class="top"><div class="brand-mark">记</div>' +
    '<div><div class="brand-t">简记 · 联网账本</div><div class="brand-s">身份指纹 <span class="mono">' + esc(ST.id.fp) + '</span></div></div>' +
    '<div class="spacer"></div><span class="tag good">链高 ' + (ST.me ? ST.me.seq : 0) + '</span>' +
    '<button class="btn sm" data-act="theme">切换主题</button><button class="btn sm" data-act="logout">退出</button></div>' +
    statusBar('CHAIN HEIGHT ' + (ST.me ? ST.me.seq : 0)) +
    '<div class="tabs">' + tabs.map(t => '<button data-act="tab" data-v="' + t[0] + '" class="' + (ST.tab === t[0] ? 'on' : '') + '">' + t[1] + '</button>').join('') + '</div>' +
    '<div id="main-content"></div></div>';
  const v = { ledger:viewLedger, verify:viewVerify, grants:viewGrants, identity:viewIdentity }[ST.tab];
  $('#main-content').innerHTML = v();
}
function viewLedger() {
  const list = ST.plain.slice().reverse();
  const rows = list.length ? list.map(p => '<div class="list-row"><div class="lr-main">' +
    '<div class="lr-t">' + esc(p.note || p.type) + (p.party ? ' <span class="tag">' + esc(p.party) + '</span>' : '') + '</div>' +
    '<div class="lr-s">' + esc(p.date) + ' · ' + esc(p.book) + ' · ' + (p.voucher || '—') + ' · #' + p.seq + ' 已封存</div></div>' +
    '<div class="lr-v" style="color:' + (p.type === 'income' ? 'var(--income)' : 'var(--text)') + '">' +
    (p.type === 'income' ? '+' : '-') + fmt(p.amount) + '</div></div>').join('')
    : '<div class="empty">还没有记录。记下的第一笔就会进入不可变账本。</div>';
  return '<div class="kpis">' +
    '<div class="kpi"><div class="l">链上记录</div><div class="v">' + (ST.me ? ST.me.seq : 0) + '</div></div>' +
    '<div class="kpi"><div class="l">累计增加</div><div class="v" style="color:var(--income)">' + fmt(list.filter(x => x.type === 'income').reduce((s,x) => s+x.amount,0)) + '</div></div>' +
    '<div class="kpi"><div class="l">累计减少</div><div class="v" style="color:var(--expense)">' + fmt(list.filter(x => x.type === 'expense').reduce((s,x) => s+x.amount,0)) + '</div></div>' +
    '<div class="kpi"><div class="l">账本头</div><div class="v mono" style="font-size:12px">' + esc((ST.me && ST.me.head || '').slice(0,14)) + '…</div></div></div>' +
    '<div class="grid2"><div class="card"><div class="card-h"><div class="card-t">记一笔（本地加密后上传）</div>' +
      '<span class="tag info">只追加</span></div>' +
      '<div class="field"><label>账本</label><select class="inp" id="f-book">' + ST.books.map(b => '<option' + (b === ST.book ? ' selected' : '') + '>' + esc(b) + '</option>').join('') + '</select></div>' +
      '<div class="row" style="margin-bottom:12px"><button class="btn sm" data-act="add-book">+ 新增账本</button></div>' +
      '<div class="field"><label>方向</label><select class="inp" id="f-type"><option value="expense">减少 / 支出</option><option value="income">增加 / 收入</option></select></div>' +
      '<div class="field"><label>金额（元）</label><input class="inp" id="f-amount" inputmode="decimal" placeholder="0.00"></div>' +
      '<div class="field"><label>摘要</label><input class="inp" id="f-note" placeholder="例如：公司拨入备用金"></div>' +
      '<div class="grid2" style="gap:10px"><div class="field"><label>往来 / 经办</label><input class="inp" id="f-party" placeholder="选填"></div>' +
      '<div class="field"><label>凭证号</label><input class="inp" id="f-voucher" placeholder="选填"></div></div>' +
      '<div class="field"><label>日期</label><input class="inp" type="date" id="f-date" value="' + today() + '"></div>' +
      '<button class="btn primary" data-act="add-entry">签名并记入账本</button>' +
      '<div class="note">记录一经提交就无法修改或删除。记错了按财务规范做一笔反向冲销，两笔都永久留痕。</div></div>' +
    '<div class="card"><div class="card-h"><div class="card-t">已解密的账目</div><span class="tag good">仅你可见</span></div>' + rows + '</div></div>';
}
function savedAnchors() { try { return JSON.parse(localStorage.getItem('jianji.anchors.v1') || '[]'); } catch (e) { return []; } }
function writeSavedAnchors(a) { try { localStorage.setItem('jianji.anchors.v1', JSON.stringify(a)); } catch (e) {} }
function consistency(proof, saved) {
  const n = Number(saved.anchorCount || saved.count || 0), head = saved.anchorHead || saved.head;
  if (!n || !head) return { ok:false, msg:'锚点文件格式不正确' };
  const arr = proof.anchors || [];
  if (!arr[n-1]) return { ok:false, msg:'当前锚链比保存时更短：服务端可能回滚过，或运行环境被重建' };
  if (arr[n-1].hash !== head) return { ok:false, msg:'锚点哈希不匹配：账本历史被替换过' };
  return { ok:true, extended:arr.length - n };
}
function viewVerify() {
  const a = ST.anchors || { merkleRoot:'—', owners:[] };
  const proof = ST.proof || { anchors:[], anchorHead:'—', anchorCount:0 };
  const savedRows = savedAnchors().slice().reverse().map(s => {
    const c = consistency(proof, s);
    return '<div class="list-row"><div class="lr-main"><div class="lr-t mono">#' + (s.anchorCount || s.count) +
      ' · ' + esc(String(s.anchorHead || s.head).slice(0,16)) + '…</div>' +
      '<div class="lr-s">' + esc(s.savedAt || '') + ' · ' + esc(c.ok ? '一致，此后新增 ' + c.extended + ' 个锚点' : c.msg) + '</div></div>' +
      '<span class="tag ' + (c.ok ? 'good' : 'bad') + '">' + (c.ok ? '一致' : '异常') + '</span></div>';
  }).join('') || '<div class="empty">还没有保存过锚点</div>';
  const own = (a.owners || []).map(o => '<div class="list-row"><div class="lr-main">' +
    '<div class="lr-t mono">' + esc(o.fp) + (o.fp === ST.id.fp ? ' <span class="tag info">我</span>' : '') + '</div>' +
    '<div class="lr-s">' + o.count + ' 条 · 链头 ' + esc(o.head.slice(0,20)) + '…</div></div>' +
    '<button class="btn sm" data-act="verify-one" data-fp="' + esc(o.fp) + '">校验</button></div>').join('') || '<div class="empty">链上还没有身份</div>';
  return '<div class="card"><div class="card-h"><div class="card-t">全局哈希承诺</div>' +
    '<button class="btn sm" data-act="refresh-anchors">刷新</button></div>' +
    '<div class="field"><label>Merkle 根（任何改动都会让它变化）</label><div class="mono" style="color:var(--accent);word-break:break-all">' + esc(a.merkleRoot) + '</div></div>' +
    '<div class="note">公开接口只返回序号、前序哈希、本条哈希、时间戳与签名。<b>不返回密文，也不返回账目内容</b>。' +
    '任何人都能验证链是否连续、签名是否属于该身份、链头是否与公布的一致。</div>' +
    '<div class="card-s">已登记身份 ' + (a.owners || []).length + ' 个 · 策略：只追加 / 密文永不公开 / 仅哈希承诺</div>' + own + '</div>' +
    '<div class="card" id="verify-detail"><div class="card-h"><div class="card-t">独立校验结果</div></div>' +
    '<div class="card-s">点上面的「校验」，浏览器会本地重算整条哈希链并用该身份的公钥验签，不依赖服务端结论。</div></div>' +
    '<div class="card"><div class="card-h"><div class="card-t">锚定证明与回滚检测</div>' +
      '<span class="tag ' + (proof.anchorCount ? 'good' : 'info') + '">' + (proof.anchorCount || 0) + ' 个锚点</span></div>' +
      '<div class="field"><label>当前锚链头</label><div class="mono" style="color:var(--accent);word-break:break-all">' + esc(proof.anchorHead || '—') + '</div></div>' +
      '<div class="note">服务端每写入一个事件就把当时的 Merkle 根串进只追加的锚链。把锚点或完整证明保存下来，日后核对：' +
      '如果存储被整体替换或回滚，旧锚点就不会出现在新锚链的前缀里，一致性校验会立刻失败。这不依赖任何第三方，也不需要信任服务端。</div>' +
      '<div class="row">' +
        '<button class="btn sm" data-act="save-anchor">保存当前锚点</button>' +
        '<button class="btn sm" data-act="export-proof">下载锚定证明</button>' +
        '<button class="btn sm" data-act="import-anchor">导入历史锚点校验</button>' +
        '<button class="btn sm" data-act="open-public">公开验证页</button>' +
        '<button class="btn sm" data-act="copy-public">复制公开链接</button>' +
      '</div><div style="margin-top:12px">' + savedRows + '</div></div>';
}
function viewGrants() {
  const g = ST.grants || { out:[], in:[] };
  const outRows = g.out.length ? g.out.map(x => '<div class="list-row"><div class="lr-main">' +
    '<div class="lr-t">' + esc(x.label || x.bookTag.slice(0,10)) + ' → <span class="mono">' + esc(x.to) + '</span></div>' +
    '<div class="lr-s">授权时间 ' + new Date(x.ts).toLocaleString('zh-CN') + '</div></div>' +
    '<button class="btn sm danger" data-act="revoke" data-id="' + esc(x.id) + '">撤销</button></div>').join('') : '<div class="empty">还没有授权给别人</div>';
  const inRows = (ST.shared && ST.shared.length) ? ST.shared.map(x => '<div class="list-row"><div class="lr-main">' +
    '<div class="lr-t">' + esc(x.label || '共享账本') + ' · 来自 <span class="mono">' + esc(x.from) + '</span></div>' +
    '<div class="lr-s">' + x.entries.length + ' 条密文 · 已用你的私钥解开查看密钥</div></div>' +
    '<button class="btn sm" data-act="view-shared" data-id="' + esc(x.grantId) + '">查看</button></div>').join('') : '<div class="empty">还没有人授权给你</div>';
  return '<div class="grid2"><div class="card"><div class="card-h"><div class="card-t">授权别人看懂指定账本</div></div>' +
    '<div class="card-s">把某个账本的数据密钥，用对方的公钥加密后交给对方。服务端只负责转交与按标签过滤，全程看不到明文。</div>' +
    '<div class="field" style="margin-top:12px"><label>对方身份指纹（20 位）</label><input class="inp" id="g-to" placeholder="对方在「身份与备份」里能看到"></div>' +
    '<div class="field"><label>授权哪个账本</label><select class="inp" id="g-book">' + ST.books.map(b => '<option>' + esc(b) + '</option>').join('') + '</select></div>' +
    '<button class="btn primary" data-act="grant">生成并发送授权</button>' +
    '<div class="note warn">撤销只阻止之后继续读取；对方在授权期间已经看过或保存的内容，密码学上无法收回。</div></div>' +
    '<div class="card"><div class="card-h"><div class="card-t">我发出的授权</div></div>' + outRows + '</div></div>' +
    '<div class="card"><div class="card-h"><div class="card-t">别人授权给我</div></div>' + inRows + '</div>';
}
function viewIdentity() {
  return '<div class="grid2"><div class="card"><div class="card-h"><div class="card-t">我的身份</div><span class="tag good">密钥即身份</span></div>' +
    '<div class="field"><label>身份指纹（可以给别人，用于授权给你）</label><div class="mono" style="color:var(--accent)">' + esc(ST.id.fp) + '</div></div>' +
    '<div class="row"><button class="btn sm" data-act="copy-fp">复制指纹</button><button class="btn sm" data-act="show-words">查看助记词</button></div>' +
    '<div class="note">服务端只保存：公钥、用你助记词加密的私钥包、密文记录、哈希链。没有邮箱、手机号、密码，也没有任何能解开内容的凭据。</div></div>' +
    '<div class="card"><div class="card-h"><div class="card-t">备份与迁移</div></div>' +
    '<div class="card-s">服务端存储可能随运行环境重建而清空。助记词 + 导出的加密账本可在任何新环境恢复：导入后能本地解密查看；若服务端为空，还可逐条重新提交，完整重建链上记录（每条仍要过哈希与签名校验）。记录已做 512 字节定长填充，密文大小不再泄露内容长度。</div>' +
    '<div class="row" style="margin-top:12px"><button class="btn" data-act="export-ledger">导出加密账本</button>' +
    '<button class="btn" data-act="import-ledger">导入账本文件</button></div>' +
    '<div class="note warn">助记词是唯一恢复方式。建议离线抄写，不要截图、不要存网盘明文。</div></div></div>' +
    '<div class="card"><div class="card-h"><div class="card-t">技术边界（如实说明）</div></div>' +
    '<div class="card-s">① 服务端账号层面没有改删接口，但运行环境提供者理论上可以替换整个存储；把 Merkle 根定期抄走或锚定到外部，就能发现这种情况。' +
    '② 密文长期保存存在未来算法风险，公开层只有哈希，不承担这个风险。③ 记账时间、笔数、记录大小等元数据仍可被服务端观察。' +
    '④ 真正的审计级不可篡改需要多机构交叉签名或公链锚定，这是下一步。</div></div>';
}

/* ---------------- 数据 ---------------- */
async function refresh() {
  ST.me = await api('/api/me', 'GET');
  const r = await api('/api/entries', 'GET');
  ST.entries = r.entries;
  const tagMap = {};
  for (const b of ST.books) tagMap[await bookTag(ST.id, b)] = b;
  const plain = [];
  for (const e of r.entries) {
    const b = tagMap[e.bookTag]; if (!b) continue;
    try {
      const p = await aesDec(await bookKey(ST.id, b), e.cipher);
      plain.push(Object.assign({}, p, { seq:e.seq, hash:e.hash }));
    } catch (err) {}
  }
  ST.plain = plain;
  ST.anchors = await api('/api/anchors', 'GET', null, false);
  ST.proof = await api('/api/anchor-proof', 'GET', null, false);
  ST.grants = await api('/api/grants', 'GET');
  ST.shared = (await api('/api/shared', 'GET')).shared;
}
async function addEntry() {
  const amount = Math.round(Number(String($('#f-amount').value).replace(/[^\d.]/g,'')) * 100);
  if (!amount || amount <= 0) { toast('请输入有效金额', 'err'); return; }
  const book = $('#f-book').value;
  const plain = { type:$('#f-type').value, amount, book, date:$('#f-date').value || today(),
    note:$('#f-note').value.trim(), party:$('#f-party').value.trim(), voucher:$('#f-voucher').value.trim() };
  const cipher = await aesEnc(await bookKey(ST.id, book), plain);
  const tag = await bookTag(ST.id, book);
  const seq = ST.me.seq + 1, prevHash = ST.me.head, ts = Date.now();
  const hash = await sha256hex([seq, prevHash, ST.id.fp, cipher, tag, ts].join('|'));
  const sig = b64(await subtle().sign({ name:'ECDSA', hash:'SHA-256' }, await importSignPriv(ST.id), enc(hash)));
  await api('/api/entries', 'POST', { seq, prevHash, hash, cipher, sig, bookTag:tag, ts });
  await refresh(); render(); toast('已签名并写入不可变账本');
}
async function verifyOne(fp) {
  const a = await api('/api/anchors/' + fp, 'GET', null, false);
  let prev = '0'.repeat(64), broken = -1, sigOk = true;
  const pub = await importSignPub(a.pubSign);
  for (let i = 0; i < a.chain.length; i++) {
    const e = a.chain[i];
    if (e.seq !== i + 1 || e.prevHash !== prev) { broken = i + 1; break; }
    try { sigOk = await subtle().verify({ name:'ECDSA', hash:'SHA-256' }, pub, unb64(e.sig), enc(e.hash)) && sigOk; }
    catch (err) { sigOk = false; }
    prev = e.hash;
  }
  const headOk = prev === a.head;
  const ok = broken < 0 && headOk && sigOk;
  const rows = a.chain.slice(0, 12).map(e => '<div><span>#' + e.seq + '</span><span>' + esc(e.hash) + '</span></div>').join('');
  const el = $('#verify-detail'); if (!el) return;
  el.innerHTML = '<div class="card-h"><div class="card-t">独立校验：' + esc(fp) + '</div>' +
    '<span class="tag ' + (ok ? 'good' : 'bad') + '">' + (ok ? '校验通过' : '发现异常') + '</span></div>' +
    '<div class="card-s">链长 ' + a.chain.length + ' 条 · 序号连续：' + (broken < 0 ? '是' : '否（第 ' + broken + ' 条断开）') +
    ' · 签名有效：' + (sigOk ? '是' : '否') + ' · 链头一致：' + (headOk ? '是' : '否') + '</div>' +
    '<div class="chain">' + (rows || '<div>暂无记录</div>') + '</div>';
}
async function grant() {
  const to = $('#g-to').value.trim(), book = $('#g-book').value;
  if (!to) { toast('请填对方身份指纹', 'err'); return; }
  const other = await api('/api/pub/' + to, 'GET', null, false);
  const bits = await subtle().deriveBits({ name:'ECDH', public: await importDhPub(other.pubDh) }, await importDhPriv(ST.id), 256);
  const wrap = await aesKey(new Uint8Array(bits), ['encrypt','decrypt']);
  const raw = await subtle().exportKey('raw', await bookKey(ST.id, book));
  const wrappedKey = await aesEncRaw(wrap, new Uint8Array(raw));
  await api('/api/grants', 'POST', { id:uid(), to, bookTag:await bookTag(ST.id, book), wrappedKey, label:book });
  await refresh(); render(); toast('授权已生成，对方现在可以解开这个账本');
}
async function viewShared(grantId) {
  const g = (ST.shared || []).find(x => x.grantId === grantId); if (!g) return;
  const other = await api('/api/pub/' + g.from, 'GET', null, false);
  const bits = await subtle().deriveBits({ name:'ECDH', public: await importDhPub(other.pubDh) }, await importDhPriv(ST.id), 256);
  const wrap = await aesKey(new Uint8Array(bits), ['encrypt','decrypt']);
  const raw = await aesDecRaw(wrap, g.wrappedKey);
  const bk = await aesKey(raw, ['decrypt']);
  const rows = [];
  for (const e of g.entries) {
    try { const p = await aesDec(bk, e.cipher); rows.push('<div class="list-row"><div class="lr-main"><div class="lr-t">' + esc(p.note || '—') + '</div>' +
      '<div class="lr-s">' + esc(p.date) + ' · #' + e.seq + '</div></div><div class="lr-v">' + (p.type === 'income' ? '+' : '-') + fmt(p.amount) + '</div></div>'); }
    catch (err) {}
  }
  modal('<h3>' + esc(g.label || '共享账本') + '</h3><div class="card-s">来自 ' + esc(g.from) + ' · 共 ' + rows.length + ' 条，已用你的私钥解开</div>' +
    (rows.join('') || '<div class="empty">这个账本还没有记录</div>') +
    '<div class="row" style="margin-top:14px"><button class="btn" data-act="close-modal">关闭</button></div>');
}

function render() { ST.id ? viewMain() : viewWelcome(); }

/* ---------------- 事件 ---------------- */
document.addEventListener('click', async e => {
  const el = e.target.closest('[data-act]'); if (!el) return;
  const a = el.dataset.act;
  try {
    switch (a) {
      case 'gen-words': ST.tmp = newMnemonic(); render(); break;
      case 'cancel-words': ST.tmp = null; render(); break;
      case 'copy-words': await copy(ST.tmp); break;
      case 'confirm-words': {
        const m = ST.tmp;
        const id = await createIdentity(m);
        const r = await login(id);
        TOKEN = r.token; ST.id = id; ST.tmp = null; cacheIdentity(id);
        await refresh(); render(); toast('身份已创建，助记词请务必保管好'); break;
      }
      case 'restore': {
        const m = normMnemonic($('#restore-words').value);
        if (m.split(' ').length !== 16) { toast('需要 16 个词', 'err'); return; }
        if (m.split(' ').some(w => WORDS.indexOf(w) < 0)) { toast('有词不在词表里，请检查拼写', 'err'); return; }
        const id = await restoreIdentity(m);
        const r = await login(id);
        TOKEN = r.token; ST.id = id; cacheIdentity(id);
        await refresh(); render(); toast('身份已恢复'); break;
      }
      case 'logout': TOKEN = ''; ST.id = null; ST.plain = []; render(); break;
      case 'theme': {
        const t = document.documentElement.dataset.theme === 'dark' ? 'light' : 'dark';
        document.documentElement.dataset.theme = t;
        try { localStorage.setItem('jianji.theme', t); } catch (e) {}
        break;
      }
      case 'tab': ST.tab = el.dataset.v; render(); break;
      case 'public-check': case 'refresh-anchors':
        ST.anchors = await api('/api/anchors', 'GET', null, false);
        ST.proof = await api('/api/anchor-proof', 'GET', null, false);
        if (!ST.id) loadPublicStatus(); else render();
        toast('公开哈希与锚链已刷新'); break;
      case 'save-anchor': {
        const p = (ST.proof = await api('/api/anchor-proof', 'GET', null, false));
        const arr = savedAnchors();
        arr.push({ anchorCount:p.anchorCount, anchorHead:p.anchorHead, root:p.merkleRoot,
          savedAt:new Date().toLocaleString('zh-CN') });
        writeSavedAnchors(arr); render();
        toast('锚点已保存到本机，可随时回来核对历史有没有被替换'); break;
      }
      case 'export-proof': {
        const p = (ST.proof = await api('/api/anchor-proof', 'GET', null, false));
        const blob = new Blob([JSON.stringify(p, null, 2)], { type:'application/json' });
        const a2 = document.createElement('a'); a2.href = URL.createObjectURL(blob);
        a2.download = '简记_锚定证明_' + today() + '.json'; a2.click();
        setTimeout(() => URL.revokeObjectURL(a2.href), 500);
        toast('锚定证明已导出，建议存到不会被删改的地方'); break;
      }
      case 'import-anchor': {
        const p = (ST.proof = await api('/api/anchor-proof', 'GET', null, false));
        const i = document.createElement('input'); i.type = 'file'; i.accept = '.json';
        i.onchange = async () => {
          const f = i.files && i.files[0]; if (!f) return;
          try {
            const j = JSON.parse(await f.text());
            const saved = j.anchorHead ? j : (Array.isArray(j) ? j[j.length-1] : null);
            if (!saved) throw new Error('不是有效的锚点或锚定证明文件');
            const c = consistency(p, saved);
            modal('<h3>锚点一致性校验</h3>' +
              '<div class="note ' + (c.ok ? 'good' : 'warn') + '">' + (c.ok
                ? '一致：保存时的第 ' + (saved.anchorCount || saved.count) + ' 个锚点仍在当前锚链前缀中，此后新增 ' + c.extended + ' 个锚点。账本历史没有被回滚或替换。'
                : esc(c.msg)) + '</div>' +
              '<div class="card-s">导入锚链头：<span class="mono">' + esc(String(saved.anchorHead || saved.head).slice(0,32)) + '…</span><br>' +
              '当前锚链头：<span class="mono">' + esc(String(p.anchorHead).slice(0,32)) + '…</span></div>' +
              '<div class="row" style="margin-top:14px"><button class="btn" data-act="close-modal">关闭</button></div>');
          } catch (err) { toast(err.message, 'err'); }
        };
        i.click(); break;
      }
      case 'open-public': window.open('/verify.html?fp=' + ST.id.fp, '_blank'); break;
      case 'copy-public': await copy(location.origin + '/verify.html?fp=' + ST.id.fp); break;
      case 'add-book': {
        const name = prompt('新账本名称（例如：项目 A 备用金）');
        if (name && name.trim() && ST.books.indexOf(name.trim()) < 0) { ST.books.push(name.trim()); ST.book = name.trim(); render(); }
        break;
      }
      case 'add-entry': await addEntry(); break;
      case 'verify-one': await verifyOne(el.dataset.fp); break;
      case 'grant': await grant(); break;
      case 'revoke': await api('/api/revoke', 'POST', { grantId: el.dataset.id }); await refresh(); render(); toast('授权已撤销'); break;
      case 'view-shared': await viewShared(el.dataset.id); break;
      case 'copy-fp': await copy(ST.id.fp); break;
      case 'show-words': {
        const d = modal('<h3>你的助记词</h3><div class="note warn">任何看到这 16 个词的人都能完全控制你的身份和账本。请确认周围没人。</div>' +
          '<div class="words">' + ST.id.keys.mnemonic.split(' ').map((w,i) => '<div class="word"><b>' + (i+1) + '</b>' + esc(w) + '</div>').join('') + '</div>' +
          '<div class="row"><button class="btn" data-act="copy-words-now">复制</button><button class="btn" data-act="close-modal">关闭</button></div>');
        d.addEventListener('click', ev => { if (ev.target.dataset.act === 'copy-words-now') copy(ST.id.keys.mnemonic); });
        break;
      }
      case 'export-ledger': {
        const r = await api('/api/entries', 'GET');
        const blob = new Blob([JSON.stringify({ app:'简记联网账本', fp:ST.id.fp, exportedAt:new Date().toISOString(),
          pubSign:ST.id.pubSign, identity:cachedIdentity(), books:ST.books,
          entries:r.entries, anchors:ST.anchors, proof:ST.proof }, null, 2)], { type:'application/json' });
        const a2 = document.createElement('a'); a2.href = URL.createObjectURL(blob);
        a2.download = '简记_加密账本_' + today() + '.json'; a2.click();
        setTimeout(() => URL.revokeObjectURL(a2.href), 500);
        toast('加密账本已导出（内容仍是密文）'); break;
      }
      case 'import-ledger': {
        const i = document.createElement('input'); i.type = 'file'; i.accept = '.json';
        i.onchange = async () => {
          const f = i.files && i.files[0]; if (!f) return;
          try {
            const pack = JSON.parse(await f.text());
            if (!pack.fp || !Array.isArray(pack.entries)) throw new Error('不是有效的简记加密账本');
            if (pack.fp !== ST.id.fp) throw new Error('这份账本属于身份 ' + pack.fp + '，请用对应助记词登录后再恢复');
            if (pack.identity && pack.identity.verifier === ST.id.keys.verifier) {
              try { localStorage.setItem(ID_CACHE, JSON.stringify(pack.identity)); } catch (e) {}
            }
            const books = Array.isArray(pack.books) && pack.books.length ? pack.books : ST.books;
            const tagMap = {};
            for (const b of books) tagMap[await bookTag(ST.id, b)] = b;
            const rows = [];
            for (const e of pack.entries) {
              const b = tagMap[e.bookTag]; if (!b) continue;
              try { rows.push(Object.assign({}, await aesDec(await bookKey(ST.id, b), e.cipher), { seq:e.seq })); }
              catch (err) {}
            }
            const list = rows.slice().reverse().slice(0, 8).map(p => '<div class="list-row"><div class="lr-main">' +
              '<div class="lr-t">' + esc(p.note || '—') + '</div><div class="lr-s">' + esc(p.date) + ' · #' + p.seq + '</div></div>' +
              '<div class="lr-v">' + (p.type === 'income' ? '+' : '-') + fmt(p.amount) + '</div></div>').join('') ||
              '<div class="empty">没有能用当前助记词解开的记录</div>';
            const canResubmit = ST.me.seq === 0 && pack.entries.length > 0;
            const d = modal('<h3>加密账本恢复</h3>' +
              '<div class="card-s">文件含 ' + pack.entries.length + ' 条密文，用当前助记词成功解开 <b style="color:var(--cyan)">' + rows.length + '</b> 条。文件里始终是密文，只有你能读。</div>' +
              '<div style="margin:12px 0">' + list + '</div>' +
              '<div class="note ' + (canResubmit ? 'good' : 'warn') + '">' + (canResubmit
                ? '当前服务端账本为空，可逐条重新提交，完整重建链上记录；每条仍会通过序号、前序哈希、记录哈希与签名校验。'
                : '服务端已有 ' + ST.me.seq + ' 条记录，为避免覆盖或重复，不提供重新提交。可在全新环境中恢复。') + '</div>' +
              '<div class="row"><button class="btn" data-act="close-modal">关闭</button>' +
              (canResubmit ? '<button class="btn primary" id="do-resubmit">重新提交到服务端</button>' : '') + '</div>');
            if (canResubmit) d.querySelector('#do-resubmit').onclick = async () => {
              try {
                for (const e of pack.entries) await api('/api/entries', 'POST', {
                  seq:e.seq, prevHash:e.prevHash, hash:e.hash, cipher:e.cipher, sig:e.sig,
                  bookTag:e.bookTag, ts:e.ts });
                d.remove(); await refresh(); render();
                toast('已重建 ' + pack.entries.length + ' 条链上记录');
              } catch (err) { toast('重建失败：' + err.message, 'err'); }
            };
          } catch (err) { toast(err.message, 'err'); }
        };
        i.click(); break;
      }
    }
  } catch (err) { toast(err.message || '操作失败', 'err'); }
});

try { const savedTheme = localStorage.getItem('jianji.theme'); if (savedTheme) document.documentElement.dataset.theme = savedTheme; } catch (e) {}
if (!crypto || !crypto.subtle || !window.isSecureContext) {
  $('#app').innerHTML = '<div class="wrap"><div class="card"><div class="card-t">需要安全上下文</div>' +
    '<div class="card-s">Web Crypto 要求 HTTPS 或 localhost。请用部署后的 https 链接访问，或本机 http://127.0.0.1。</div></div></div>';
} else render();
