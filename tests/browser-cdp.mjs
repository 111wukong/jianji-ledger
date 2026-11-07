/* 零依赖真实浏览器回归：用系统 Chrome/Chromium 的 CDP 协议驱动，
   不需要 Playwright。覆盖离线记账、自动上传、账本目录恢复、换设备解密、
   轻量探测、辅助校验与控制台错误。会对临时服务与临时浏览器配置运行，不碰真实账本。

   用法：npm run test:browser:cdp
   指定浏览器：CHROME_PATH=/path/to/chrome npm run test:browser:cdp
*/
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import net from 'node:net';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
/* 设置 E2E_INVITE_CODE 可额外验证「服务端要求邀请码 → 欢迎页出现输入框 → 登录带上邀请码」链路。 */
const INVITE = process.env.E2E_INVITE_CODE || '';
const sleep = ms => new Promise(r => setTimeout(r, ms));

function findChrome() {
  if (process.env.CHROME_PATH) return process.env.CHROME_PATH;
  const candidates = [
    '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome',
    '/Applications/Chromium.app/Contents/MacOS/Chromium',
    '/usr/bin/google-chrome', '/usr/bin/google-chrome-stable',
    '/usr/bin/chromium', '/usr/bin/chromium-browser'
  ];
  for (const c of candidates) if (fs.existsSync(c)) return c;
  throw new Error('找不到 Chrome/Chromium，请通过 CHROME_PATH 指定可执行文件');
}
function freePort() {
  return new Promise(resolve => {
    const s = net.createServer();
    s.listen(0, '127.0.0.1', () => { const p = s.address().port; s.close(() => resolve(p)); });
  });
}

const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'jianji-cdp-data-'));
const userDir = fs.mkdtempSync(path.join(os.tmpdir(), 'jianji-cdp-chrome-'));
let BASE = '', server = null, chrome = null, ws = null;
const pending = new Map();
const problems = [];
let commandId = 0;

function cdpCommand(method, params = {}) {
  const id = ++commandId;
  return new Promise((resolve, reject) => {
    pending.set(id, m => m.error ? reject(new Error(method + ': ' + JSON.stringify(m.error))) : resolve(m.result));
    ws.send(JSON.stringify({ id, method, params }));
  });
}
async function js(expr) {
  const r = await cdpCommand('Runtime.evaluate', { expression: expr, awaitPromise: true, returnByValue: true });
  if (r.exceptionDetails)
    throw new Error('页面异常: ' + (r.exceptionDetails.exception?.description || r.exceptionDetails.text));
  return r.result.value;
}
async function until(expr, ms, label) {
  const start = Date.now();
  while (Date.now() - start < ms) {
    try { if (await js(expr)) return; } catch (e) { /* 页面尚未就绪 */ }
    await sleep(100);
  }
  throw new Error('等待超时：' + label);
}
async function waitFor(fn, ms, label) {
  const start = Date.now();
  while (Date.now() - start < ms) { if (await fn()) return; await sleep(100); }
  throw new Error('等待超时：' + label);
}
async function stop(proc) {
  if (!proc || proc.exitCode !== null) return;
  await new Promise(resolve => { proc.once('exit', resolve); proc.kill(); });
}
function check(cond, msg) { if (!cond) throw new Error(msg); }

try {
  const port = await freePort();
  BASE = 'http://127.0.0.1:' + port;
  server = spawn(process.execPath, [path.join(ROOT, 'web', 'server.mjs')], {
    cwd: ROOT,
    env: { ...process.env, PORT: String(port), HOST: '127.0.0.1', LEDGER_DATA_DIR: dataDir,
      LEDGER_INVITE_CODE: INVITE },
    stdio: ['ignore', 'pipe', 'pipe']
  });
  await waitFor(async () => {
    try { return (await fetch(BASE + '/api/health')).ok; } catch (e) { return false; }
  }, 10000, '测试服务启动');

  chrome = spawn(findChrome(), [
    '--headless=new', '--no-sandbox', '--disable-gpu', '--disable-dev-shm-usage',
    '--remote-debugging-port=0', '--user-data-dir=' + userDir,
    '--no-first-run', '--no-default-browser-check', 'about:blank'
  ], { stdio: ['ignore', 'pipe', 'pipe'] });
  const portFile = path.join(userDir, 'DevToolsActivePort');
  await waitFor(() => fs.existsSync(portFile), 12000, 'Chrome DevTools 端口');
  const debugPort = Number(fs.readFileSync(portFile, 'utf8').split('\n')[0]);
  const targets = await (await fetch('http://127.0.0.1:' + debugPort + '/json/list')).json();
  const page = targets.find(t => t.type === 'page');
  ws = new WebSocket(page.webSocketDebuggerUrl);
  await new Promise((resolve, reject) => { ws.onopen = resolve; ws.onerror = reject; });
  ws.onmessage = e => {
    const m = JSON.parse(e.data);
    if (m.id && pending.has(m.id)) { pending.get(m.id)(m); pending.delete(m.id); return; }
    if (m.method === 'Runtime.exceptionThrown')
      problems.push('exception: ' + (m.params.exceptionDetails.exception?.description || m.params.exceptionDetails.text));
    if (m.method === 'Log.entryAdded' && m.params.entry.level === 'error')
      problems.push('console: ' + m.params.entry.text);
  };
  await cdpCommand('Page.enable');
  await cdpCommand('Runtime.enable');
  await cdpCommand('Log.enable');
  await cdpCommand('Network.enable');
  await cdpCommand('Page.navigate', { url: BASE + '/' });
  await until('typeof ST !== "undefined" && document.readyState === "complete"', 15000, '页面加载');

  check(await js('ST.id === null && !!document.querySelector(".auth-shell")'), '应显示欢迎页');
  if (INVITE) {
    await until('ST.inviteRequired === true', 10000, '服务端要求邀请码');
    const shown = await js(`(() => {
      const el = document.querySelector('#invite-code');
      if (!el) throw new Error('欢迎页没有显示邀请码输入框');
      el.value = ${JSON.stringify(INVITE)};
      ST.inviteCode = el.value;
      return true;
    })()`);
    check(shown === true, '邀请码输入框未生效');
    console.log('ok 0  邀请码闸门：欢迎页出现输入框并随登录提交');
  }
  const created = await js(`(async () => {
    const words = newMnemonic();
    const id = await createIdentity(words);
    await startIdentity(id);
    return { fp:id.fp, books:ST.books.slice() };
  })()`);
  await until('ST.sync.status === "synced" && ST.outbox.length === 0', 15000, '身份登记');
  console.log('ok 1  身份创建与联网登记 ' + created.fp);

  await js(`addEntry({ type:'expense', amount:12345, book:'个人账', date:today(), note:'CDP 第一笔', party:'', voucher:'' })`);
  await until('ST.outbox.length === 0 && ST.plain.length === 1 && ST.sync.status === "synced"', 15000, '在线记账');
  console.log('ok 2  在线加密记账并同步');

  /* 断网：覆盖 navigator.onLine 并触发 offline 事件，验证记录进入待同步队列。 */
  await js(`(async () => {
    Object.defineProperty(navigator, 'onLine', { get: () => false, configurable: true });
    window.dispatchEvent(new Event('offline'));
    await addEntry({ type:'expense', amount:2222, book:'个人账', date:today(), note:'CDP 离线笔', party:'', voucher:'' });
    return true;
  })()`);
  await until('ST.outbox.length === 1 && ST.plain.length === 2', 8000, '离线入队');
  check(await js('ST.sync.status === "offline"'), '离线状态未正确标记');
  await js(`(async () => {
    Object.defineProperty(navigator, 'onLine', { get: () => true, configurable: true });
    window.dispatchEvent(new Event('online'));
    return true;
  })()`);
  await until('ST.outbox.length === 0 && ST.plain.length === 2 && ST.sync.status === "synced"', 15000, '联网自动上传');
  console.log('ok 3  断网记账 → 联网自动上传 → 去重');

  await js(`(async () => {
    ST.books.push('CDP 项目账');
    ST.id.needProfilePush = true;
    await LedgerStore.setMeta('books:' + ST.id.fp, ST.books);
    await addEntry({ type:'income', amount:9900, book:'CDP 项目账', date:today(), note:'CDP 第三笔', party:'', voucher:'' });
    return true;
  })()`);
  await until('ST.outbox.length === 0 && ST.plain.length === 3 && ST.sync.status === "synced"', 15000, '自定义账本同步');
  const profile = await js(`(async () => {
    const me = await authed('/api/me','GET');
    return { len:(me.profile||'').length, books:await decodeProfile(ST.id, me.profile) };
  })()`);
  check(profile.books.includes('CDP 项目账'), '加密账本目录没有同步到服务端');
  console.log('ok 4  新增账本写入服务端加密目录 (' + profile.len + ' 字节密文)');

  /* 模拟换设备：只清本机账本目录，保留密文记录，用助记词重新恢复身份。 */
  const recovered = await js(`(async () => {
    const fp = ST.id.fp, words = ST.id.keys.mnemonic;
    TOKEN = ''; ST.id = null;
    await LedgerStore.setMeta('books:' + fp, ['个人账','公司资金']);
    const id = await restoreIdentity(words);
    await startIdentity(id);
    return { books:ST.books.slice(), undecryptable:ST.undecryptable, plain:ST.plain.length };
  })()`);
  check(recovered.books.includes('CDP 项目账'), '恢复后账本名丢失');
  check(recovered.undecryptable === 0 && recovered.plain === 3, '恢复后存在无法解密的记录');
  console.log('ok 5  换设备恢复：3 笔全部可解密，0 笔遗漏');

  await until('ST.archive.status === "ready" && ST.archive.count >= 3', 25000, '后台静默归档完成');
  const arc = await js(`(async () => {
    const rows = await LedgerStore.archiveAll(ST.id.fp);
    const vault = await archiveVault(ST.id);
    const opened = await ArchiveCore.open(vault.key, rows[0]);
    let tamperFailed = false;
    try { await ArchiveCore.open(vault.key, Object.assign({}, rows[0], { hash:'0'.repeat(64) })); }
    catch (e) { tamperFailed = true; }
    const params = await LedgerStore.getMeta('archiveVault:' + ST.id.fp, null);
    return { count:rows.length, hasBlob:!!rows[0].blob,
      leaksCipher:JSON.stringify(rows[0]).includes(opened.cipher),
      openedHash:opened.hash, tamperFailed, iterations:params && params.iterations };
  })()`);
  check(arc.count >= 3 && arc.hasBlob && !arc.leaksCipher && arc.tamperFailed,
    '归档双层加密或 AAD 绑定异常：' + JSON.stringify(arc));
  check(arc.iterations === 600000, '归档 KDF 迭代次数不符合 OWASP 量级');
  const restored = await js('restoreFromArchive()');
  check(restored.restored >= 3, '从归档恢复失败：' + JSON.stringify(restored));
  console.log('ok 6  后台静默归档 ' + arc.count + ' 笔（PBKDF2 60 万次 / AES-256-GCM / AAD 绑定），可恢复 ' + restored.restored + ' 笔');

  /* 模拟设备全丢：只保留导出的归档文件 + 助记词，在新设备上重建归档。 */
  const portable = await js(`(async () => {
    const rows = await LedgerStore.archiveAll(ST.id.fp);
    const params = await LedgerStore.getMeta('archiveVault:' + ST.id.fp, null);
    const pack = { app:'简记加密归档', version:1, fp:ST.id.fp,
      vault:ArchiveCore.publicParams(params),
      rows:rows.map(r => r.vault ? r : Object.assign({}, r, { vault:ArchiveCore.publicParams(params) })) };
    await LedgerStore.archiveClear(ST.id.fp);
    const vault = await ArchiveCore.openVault(ST.id.keys.mnemonic, pack.vault);
    let ok = 0;
    for (const row of pack.rows) { await ArchiveCore.open(vault.key, row); ok++; }
    await LedgerStore.archiveReplace(ST.id.fp, pack.rows);
    await LedgerStore.setMeta('archiveVault:' + ST.id.fp, pack.vault);
    return { ok, count:(await LedgerStore.archiveStats(ST.id.fp)).count, hasVault:!!pack.rows[0].vault };
  })()`);
  check(portable.ok >= 3 && portable.count === portable.ok && portable.hasVault,
    '归档导出/导入无法脱离本机恢复：' + JSON.stringify(portable));
  console.log('ok 6b 归档文件可移植：设备全丢后凭助记词重建 ' + portable.ok + ' 笔');

  await until('ST.syncing === false && ST.sync.status === "synced" && !ST.archiving', 15000, '同步与归档完全空闲');
  const counts = await js(`(async () => {
    const seen = { entries:0, proof:0, status:0, me:0 };
    const orig = window.fetch;
    window.fetch = function(u) {
      const s = String(u);
      if (s.indexOf('/api/entries') === 0) seen.entries++;
      else if (s.indexOf('/api/anchor-proof') === 0) seen.proof++;
      else if (s.indexOf('/api/status') === 0) seen.status++;
      else if (s.indexOf('/api/me') === 0) seen.me++;
      return orig.apply(this, arguments);
    };
    try {
      await synchronize();
      await new Promise(r => setTimeout(r, 200));
      await synchronize();
    } finally { window.fetch = orig; }
    return seen;
  })()`);
  check(counts.status === 2, '轻量探测未执行，测量无效：' + JSON.stringify(counts));
  check(counts.entries === 0 && counts.proof === 0, '空闲同步仍拉全量数据：' + JSON.stringify(counts));
  console.log('ok 7  两轮空闲同步零全量请求 ' + JSON.stringify(counts));

  const verified = await js(`(async () => {
    const all = await authed('/api/entries','GET');
    return api('/api/verify','POST', { fp:ST.id.fp, chain:all.entries }, true);
  })()`);
  check(verified.ok === true, '辅助校验未通过：' + JSON.stringify(verified));
  console.log('ok 8  /api/verify 对完整链校验通过');

  /* 首页随手记：一行输入、一步提交，验证「打开到记下」的最短路径。 */
  const beforeQuick = await js('ST.plain.length');
  const quickReady = await js(`(() => {
    const f = document.querySelector('#quick-form');
    if (!f || !document.querySelector('#q-amount')) return false;
    document.querySelector('#q-amount').value = '12.34';
    document.querySelector('#q-note').value = 'CDP 随手记';
    f.dispatchEvent(new Event('submit', { cancelable:true, bubbles:true }));
    return true;
  })()`);
  check(quickReady === true, '首页缺少随手记表单');
  await until('ST.plain.length === ' + (beforeQuick + 1), 15000, '首页一步记账');
  console.log('ok 9  首页随手记：一行输入、一步完成');

  const replicas = await js(`(async () => { await refreshReplicas(); return ST.replicas; })()`);
  check(replicas.ok === true && Array.isArray(replicas.targets), '副本状态接口不可用');
  check(await js(`!!document.querySelector('.replica-grid')`), '总览未显示副本状态');
  console.log('ok 9b 副本状态可见：本机/服务端/加密备份 ' + (replicas.totalBackups || 0) + ' 份，' + replicas.configured + ' 个目标');

  /* PIN 快捷解锁：锁定后不再需要输入 16 个助记词。 */
  await js(`(async () => {
    const pack = await UnlockCore.seal('628314', credentialFromId(ST.id));
    localStorage.setItem('jianji.quickunlock.v1', JSON.stringify(pack));
    ST.quick = { available:true, fp:ST.id.fp, attempts:0 };
    return true;
  })()`);
  const welcome = await js(`(() => {
    TOKEN = ''; ST.id = null; ST.mode = 'create'; render();
    return { pin:!!document.querySelector('#quick-pin'), unlock:!!document.querySelector('[data-act=unlock]') };
  })()`);
  check(welcome.pin && welcome.unlock, '锁定后未显示 PIN 解锁入口');
  await js(`(() => {
    document.querySelector('#quick-pin').value = '628314';
    document.querySelector('[data-act=unlock]').click();
    return true;
  })()`);
  await until('ST.id !== null && ST.plain.length >= ' + (beforeQuick + 1), 25000, 'PIN 快捷解锁');
  console.log('ok 10 PIN 快捷解锁：无需 16 个助记词即恢复身份与全部账目');

  check(problems.length === 0, '浏览器控制台存在错误：' + JSON.stringify(problems.slice(0, 5)));
  console.log('ok 11 无页面异常与控制台错误');
  console.log('\n浏览器回归全部通过');
} catch (e) {
  console.error('\n浏览器回归失败：' + (e.stack || e.message));
  process.exitCode = 1;
} finally {
  if (ws) ws.close();
  await stop(chrome);
  await stop(server);
  await sleep(200);
  fs.rmSync(dataDir, { recursive: true, force: true });
  fs.rmSync(userDir, { recursive: true, force: true });
}
