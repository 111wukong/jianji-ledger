'use strict';
/* 公开验证器：不登录、不接触密文，全部校验在浏览器本地完成。 */
const $ = s => document.querySelector(s);
const enc = s => new TextEncoder().encode(String(s));
const esc = s => String(s == null ? '' : s).replace(/[&<>"']/g, c => ({ '&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;' }[c]));
const GENESIS = '0'.repeat(64);
const DEFAULT_ANCHOR_URL = 'https://raw.githubusercontent.com/111wukong/jianji-ledger/main/anchoring/latest.json';
const ANCHOR_HISTORY_URL = 'https://github.com/111wukong/jianji-ledger/commits/main/anchoring/latest.json';
let currentProof = null;

function unb64(s) { return Uint8Array.from(atob(s), c => c.charCodeAt(0)); }
async function get(p) {
  const r = await fetch(p, { cache:'no-store' });
  if (!r.ok) throw new Error('HTTP ' + r.status);
  return r.json();
}
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
  catch (_) { sigOk = false; }
  for (let i = 0; i < a.chain.length; i++) {
    const e = a.chain[i];
    if (e.seq !== i + 1 || e.prevHash !== prev) { broken = i + 1; break; }
    if (pub) {
      try { sigOk = (await crypto.subtle.verify({ name:'ECDSA', hash:'SHA-256' }, pub, unb64(e.sig), enc(e.hash))) && sigOk; }
      catch (_) { sigOk = false; }
    }
    prev = e.hash;
  }
  return { broken, sigOk, headOk:prev === a.head, head:prev, count:a.chain.length };
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
function externalCard() {
  return '<div class="card verify-external"><div class="card-h"><div><div class="card-t">GitHub 外部锚定</div>' +
    '<div class="card-s">用独立仓库的提交历史约束服务端，不再只信它自己保存的锚点。</div></div>' +
    '<span class="tag info" id="external-tag">等待核验</span></div>' +
    '<div class="field"><label for="external-url">锚点 JSON 地址（Raw GitHub）</label>' +
    '<input class="inp verify-url" id="external-url" type="url" spellcheck="false" value="' + esc(DEFAULT_ANCHOR_URL) + '"></div>' +
    '<div class="row verify-actions"><button class="btn primary sm" id="verify-external">一键核验 GitHub 锚点</button>' +
    '<label class="btn sm" for="external-file">导入锚点文件</label>' +
    '<input id="external-file" type="file" accept=".json,application/json" hidden>' +
    '<a class="btn sm" id="anchor-history" href="' + ANCHOR_HISTORY_URL + '" target="_blank" rel="noopener noreferrer">查看 GitHub 提交历史</a></div>' +
    '<div class="note" id="external-result" role="status" aria-live="polite">如果尚未启用自动锚定，这里会显示空状态，不影响上方服务端锚链的独立校验。</div></div>';
}
function setExternalResult(kind, title, detail) {
  const tag = $('#external-tag'), box = $('#external-result');
  if (!tag || !box) return;
  tag.className = 'tag ' + (kind === 'good' ? 'good' : kind === 'bad' ? 'bad' : kind === 'warn' ? 'warn' : 'info');
  tag.textContent = kind === 'good' ? '外部锚定有效' : kind === 'bad' ? '核验失败' : kind === 'warn' ? '等待新锚点' : '等待核验';
  box.className = 'note ' + (kind === 'good' ? 'good' : kind === 'bad' || kind === 'warn' ? 'warn' : '');
  box.innerHTML = '<b>' + esc(title) + '</b>' + (detail ? '<br><span class="mono">' + esc(detail) + '</span>' : '');
}
async function checkAttestation(attestation, source) {
  const result = await AnchorCore.verifyExternalAnchor(currentProof, attestation, location.origin);
  if (!result.ok) {
    setExternalResult('bad', result.error || '外部锚定未通过核验', source || '');
    return result;
  }
  const anchor = result.anchor;
  const detail = '锚点 #' + anchor.seq + ' · ' + anchor.hash + ' · 观察于 ' + attestation.observedAt;
  if (result.current) setExternalResult('good', '通过：GitHub 已锚定当前最新锚链头', detail);
  else setExternalResult('warn', '旧锚点有效；之后还有 ' + result.pending + ' 个事件等待下次自动锚定', detail);
  return result;
}
async function verifyExternalFromUrl(silent) {
  const button = $('#verify-external'), url = $('#external-url').value.trim();
  if (!url) { setExternalResult('bad', '请填写锚点 JSON 地址'); return; }
  button.disabled = true; button.textContent = '正在核验…';
  if (!silent) setExternalResult('info', '正在从第三方地址读取并本地重算…');
  try {
    const attestation = await get(url);
    await checkAttestation(attestation, url);
  } catch (e) {
    if (silent) setExternalResult('info', '尚未读取到已发布的 GitHub 锚点；配置自动锚定后再来这里核验。', e.message);
    else setExternalResult('bad', '无法读取或解析外部锚点', url + ' · ' + e.message);
  } finally {
    button.disabled = false; button.textContent = '一键核验 GitHub 锚点';
  }
}
async function render() {
  const box = $('#v-content');
  try {
    const [a, proof] = await Promise.all([get('/api/anchors'), get('/api/anchor-proof')]);
    currentProof = proof;
    const av = await AnchorCore.verifyAnchorProof(proof);
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
        '<div class="note">公开接口只返回序号、前序哈希、本条哈希、时间戳、签名与 Merkle 根。<b>不返回密文，也不返回账目内容</b>。</div>' +
        '<div class="row"><button class="btn sm" id="download-proof">下载锚定证明</button>' +
        '<button class="btn sm" id="copy-root">复制 Merkle 根</button></div></div>' +
      externalCard() + detail +
      '<div class="card"><div class="card-h"><div class="card-t">链上身份</div><span class="tag info">' + a.owners.length + ' 个</span></div>' + ownerRows(a) + '</div>' +
      '<div class="card"><div class="card-t">两层证明分别说明什么</div>' +
        '<div class="card-s" style="margin-top:8px">服务端锚链证明历史记录之间没有断链；GitHub 外部锚点进一步证明「某个锚链头在第三方提交历史中确实存在过」。' +
        '若服务端日后整体替换或回滚历史，已发布锚点就无法在新锚链中找到。GitHub 定时快照可能滞后，因此“旧锚点有效、仍有待锚定事件”不是篡改告警。</div></div>';
    $('#download-proof').onclick = () => {
      const blob = new Blob([JSON.stringify(proof, null, 2)], { type:'application/json' });
      const el = document.createElement('a'); el.href = URL.createObjectURL(blob);
      el.download = '简记_锚定证明_' + new Date().toISOString().slice(0,10) + '.json';
      document.body.appendChild(el); el.click(); el.remove();
      setTimeout(() => URL.revokeObjectURL(el.href), 500);
    };
    $('#copy-root').onclick = () => copy(a.merkleRoot);
    $('#verify-external').onclick = () => verifyExternalFromUrl(false);
    $('#external-url').addEventListener('keydown', e => { if (e.key === 'Enter') verifyExternalFromUrl(false); });
    $('#external-file').onchange = async e => {
      const file = e.target.files && e.target.files[0];
      if (!file) return;
      if (file.size > 1024 * 1024) { setExternalResult('bad', '锚点文件超过 1 MB，拒绝读取'); return; }
      try { await checkAttestation(JSON.parse(await file.text()), '本地文件：' + file.name); }
      catch (err) { setExternalResult('bad', '锚点文件不是有效 JSON', err.message); }
      e.target.value = '';
    };
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
  try { localStorage.setItem('jianji.theme', cur); } catch (_) {}
};
try { const t = localStorage.getItem('jianji.theme'); if (t) document.documentElement.dataset.theme = t; } catch (_) {}
render();
