'use strict';
/* 公开验证器：不登录、不接触密文，全部校验在浏览器本地完成 */
const $ = s => document.querySelector(s);
const enc = s => new TextEncoder().encode(String(s));
const esc = s => String(s == null ? '' : s).replace(/[&<>"']/g, c => ({ '&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;' }[c]));
const GENESIS = '0'.repeat(64);
async function sha256hex(s) { const d = await crypto.subtle.digest('SHA-256', enc(s)); return Array.from(new Uint8Array(d), x => x.toString(16).padStart(2,'0')).join(''); }
function unb64(s) { return Uint8Array.from(atob(s), c => c.charCodeAt(0)); }
async function get(p) { const r = await fetch(p, { cache:'no-store' }); if (!r.ok) throw new Error('HTTP ' + r.status); return r.json(); }
function copy(t) { navigator.clipboard.writeText(t).then(() => toast('已复制')).catch(() => toast('复制失败，请手动选中', 'err')); }
function toast(m, k) {
  let el = $('#toast');
  if (!el) { el = document.createElement('div'); el.id = 'toast'; el.className = 'toast'; document.body.appendChild(el); }
  el.textContent = m; el.className = 'toast show' + (k === 'err' ? ' err' : '');
  clearTimeout(toast._t); toast._t = setTimeout(() => el.className = 'toast', 3000);
}
const fp = new URLSearchParams(location.search).get('fp') || '';

async function verifyChain(a) {
  let prev = GENESIS, broken = -1, sigOk = true, pub = null;
  try { pub = await crypto.subtle.importKey('jwk', a.pubSign, { name:'ECDSA', namedCurve:'P-256' }, false, ['verify']); }
  catch (e) { sigOk = false; }
  for (let i = 0; i < a.chain.length; i++) {
    const e = a.chain[i];
    if (e.seq !== i + 1 || e.prevHash !== prev) { broken = i + 1; break; }
    if (pub) {
      try { sigOk = (await crypto.subtle.verify({ name:'ECDSA', hash:'SHA-256' }, pub, unb64(e.sig), enc(e.hash))) && sigOk; }
      catch (err) { sigOk = false; }
    }
    prev = e.hash;
  }
  return { broken, sigOk, headOk:prev === a.head, head:prev, count:a.chain.length };
}
async function verifyAnchors(proof) {
  let prev = GENESIS, broken = -1;
  for (let i = 0; i < proof.anchors.length; i++) {
    const a = proof.anchors[i];
    const calc = await sha256hex([a.seq, a.prevHash, a.root, a.ts].join('|'));
    if (a.seq !== i + 1 || a.prevHash !== prev || a.hash !== calc) { broken = i + 1; break; }
    prev = a.hash;
  }
  return { broken, ok:broken < 0 && prev === proof.anchorHead, head:prev };
}
function chainRows(chain) {
  return chain.slice().reverse().map(e => '<div><span>#' + e.seq + '</span><span>' + esc(e.hash) + '</span></div>').join('') || '<div><span>—</span><span>暂无记录</span></div>';
}
function ownerRows(a) {
  if (!a.owners.length) return '<div class="empty">链上还没有身份</div>';
  return a.owners.map(o => '<div class="list-row"><div class="lr-main">' +
    '<div class="lr-t mono">' + esc(o.fp) + '</div>' +
    '<div class="lr-s">' + o.count + ' 条 · 链头 ' + esc(o.head.slice(0,20)) + '…</div></div>' +
    '<button class="btn sm" data-fp="' + esc(o.fp) + '">验证</button></div>').join('');
}
async function render() {
  const box = $('#v-content');
  try {
    const [a, proof] = await Promise.all([get('/api/anchors'), get('/api/anchor-proof')]);
    const av = await verifyAnchors(proof);
    let detail = '';
    if (fp) {
      const one = await get('/api/anchors/' + encodeURIComponent(fp));
      const cv = await verifyChain(one);
      const ok = cv.broken < 0 && cv.headOk && cv.sigOk;
      detail = '<div class="card"><div class="card-h"><div class="card-t">身份 ' + esc(fp) + ' 的哈希链</div>' +
        '<span class="tag ' + (ok ? 'good' : 'bad') + '">' + (ok ? '校验通过' : '发现异常') + '</span></div>' +
        '<div class="kpis">' +
          '<div class="kpi"><div class="l">链长</div><div class="v">' + cv.count + '</div></div>' +
          '<div class="kpi"><div class="l">序号连续</div><div class="v" style="font-size:14px">' + (cv.broken < 0 ? 'PASS' : 'FAIL @' + cv.broken) + '</div></div>' +
          '<div class="kpi"><div class="l">签名有效</div><div class="v" style="font-size:14px">' + (cv.sigOk ? 'PASS' : 'FAIL') + '</div></div>' +
          '<div class="kpi"><div class="l">链头一致</div><div class="v" style="font-size:14px">' + (cv.headOk ? 'PASS' : 'FAIL') + '</div></div>' +
        '</div>' +
        '<div class="note good">以上结论由你的浏览器本地重算得出，没有采信服务端返回的「校验结果」字段。</div>' +
        '<div class="chain">' + chainRows(one.chain) + '</div>' +
        '<div class="row" style="margin-top:14px"><button class="btn sm" id="copy-link">复制此身份的公开链接</button>' +
        '<button class="btn sm" id="back-all">查看全部身份</button></div></div>';
    }
    box.innerHTML =
      '<div class="card"><div class="card-h"><div class="card-t">全局哈希承诺</div>' +
        '<span class="tag ' + (av.ok ? 'good' : 'bad') + '">' + (av.ok ? '锚链完整' : '锚链异常') + '</span></div>' +
        '<div class="field"><label>Merkle 根</label><div class="mono" style="color:var(--cyan);word-break:break-all">' + esc(a.merkleRoot) + '</div></div>' +
        '<div class="field"><label>锚链头 / 锚点数量</label><div class="mono" style="color:var(--accent);word-break:break-all">' + esc(a.anchorHead) + '</div>' +
          '<div class="card-s">已累计 ' + a.anchorCount + ' 个锚点 · 独立重算：' + (av.ok ? '全部连续且哈希一致' : '第 ' + av.broken + ' 条断开') + '</div></div>' +
        '<div class="note">公开接口只返回序号、前序哈希、本条哈希、时间戳、签名与 Merkle 根。' +
          '<b>不返回密文，也不返回账目内容</b>。你可以验证「谁在何时记过一笔、之后没被改动」，但看不到记了什么。</div>' +
        '<div class="row"><button class="btn sm" id="download-proof">下载锚定证明</button>' +
        '<button class="btn sm" id="copy-root">复制 Merkle 根</button></div></div>' +
      detail +
      '<div class="card"><div class="card-h"><div class="card-t">链上身份</div><span class="tag info">' + a.owners.length + ' 个</span></div>' + ownerRows(a) + '</div>' +
      '<div class="card"><div class="card-t">什么是锚定证明</div>' +
        '<div class="card-s" style="margin-top:8px">服务端每写入一个事件，就立刻把当时的 Merkle 根串进一条只追加的锚链。' +
        '把下载的证明文件保存下来，日后重新打开本页核对：如果服务端的存储被整体替换或回滚，旧锚点就不会出现在新锚链的前缀里，一致性校验会立刻失败。' +
        '这是不依赖任何第三方、也不需要信任服务端就能发现历史被改动的办法。</div></div>';
    $('#download-proof').onclick = () => {
      const blob = new Blob([JSON.stringify(proof, null, 2)], { type:'application/json' });
      const el = document.createElement('a'); el.href = URL.createObjectURL(blob);
      el.download = '简记_锚定证明_' + new Date().toISOString().slice(0,10) + '.json'; el.click();
      setTimeout(() => URL.revokeObjectURL(el.href), 500);
    };
    $('#copy-root').onclick = () => copy(a.merkleRoot);
    if ($('#copy-link')) $('#copy-link').onclick = () => copy(location.origin + '/verify.html?fp=' + fp);
    if ($('#back-all')) $('#back-all').onclick = () => { location.href = '/verify.html'; };
    box.querySelectorAll('[data-fp]').forEach(b => b.onclick = () => { location.href = '/verify.html?fp=' + b.dataset.fp; });
  } catch (e) {
    box.innerHTML = '<div class="card"><div class="card-t">无法读取公开账本</div><div class="note warn">' + esc(e.message) + '</div></div>';
  }
}
$('#theme-btn').onclick = () => {
  const cur = document.documentElement.dataset.theme === 'light' ? 'dark' : 'light';
  document.documentElement.dataset.theme = cur;
  try { localStorage.setItem('jianji.theme', cur); } catch (e) {}
};
try { const t = localStorage.getItem('jianji.theme'); if (t) document.documentElement.dataset.theme = t; } catch (e) {}
render();
