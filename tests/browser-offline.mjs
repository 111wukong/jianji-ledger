/* 可选真实浏览器回归：PLAYWRIGHT_PATH 可指向全局 Playwright。
   运行前启动空账本服务：BASE_URL=http://127.0.0.1:3000 node tests/browser-offline.mjs */
import { createRequire } from 'node:module';
import assert from 'node:assert/strict';
import fs from 'node:fs';
const require = createRequire(import.meta.url);
const { chromium } = require(process.env.PLAYWRIGHT_PATH || 'playwright');
const BASE = process.env.BASE_URL || 'http://127.0.0.1:3000';
const OUT = process.env.QA_DIR || '/tmp';
const browser = await chromium.launch({ executablePath:process.env.CHROMIUM_PATH || '/usr/bin/chromium', headless:true, args:['--no-sandbox'] });
const context = await browser.newContext({ viewport:{ width:1440, height:1050 }, serviceWorkers:'allow' });
const page = await context.newPage();
const errors = [];
page.on('pageerror', e => errors.push(e.message));
page.on('console', m => { if (m.type() === 'error' && !m.text().includes('ERR_INTERNET_DISCONNECTED')) errors.push(m.text()); });
page.on('response', async r => { if (r.status() >= 400) console.log('HTTP', r.status(), r.url(), await r.text().catch(() => '')); });
const waitSync = (after = 0) => page.waitForFunction(t => {
  return typeof ST !== 'undefined' && !ST.syncing && ST.outbox.length === 0 && ST.sync.status === 'synced' && ST.sync.lastSync > t;
}, after, { timeout:30000 });
const syncMark = () => page.evaluate(() => ST.sync.lastSync || 0);
async function add(amount, note) {
  await page.locator('#f-amount').fill(amount);
  await page.locator('#f-note').fill(note);
  await page.locator('#entry-form button[type=submit]').click();
  await page.waitForFunction(n => document.querySelector('.transaction-list')?.textContent.includes(n), note);
}
try {
  await page.goto(BASE, { waitUntil:'networkidle' });
  await page.screenshot({ path:OUT + '/jianji-welcome.png', fullPage:true });
  await page.locator('[data-act=gen-words]').click();
  const words = (await page.locator('.word span').allTextContents()).join(' ');
  assert.equal(words.split(' ').length, 16);
  await page.locator('#words-ack').check();
  await page.locator('[data-act=confirm-words]').click();
  await page.locator('.app-shell').waitFor();
  await waitSync();
  await page.evaluate(() => navigator.serviceWorker.ready);

  await context.setOffline(true);
  await page.evaluate(() => window.dispatchEvent(new Event('offline')));
  await add('123.45', '离线采购测试');
  await add('10', '离线收入测试');
  await page.waitForFunction(() => document.querySelector('[data-pending-count]')?.textContent === '2');
  let health = await (await fetch(BASE + '/api/health')).json();
  assert.equal(health.entries, 0, '离线时服务端不应有记录');
  await page.screenshot({ path:OUT + '/jianji-offline.png', fullPage:true });

  /* 断网刷新：应用外壳由 Service Worker 提供，密文由 IndexedDB 恢复。 */
  await page.reload({ waitUntil:'domcontentloaded' });
  await page.locator('[data-act=mode][data-v=restore]').click();
  await page.locator('#restore-words').fill(words);
  await page.locator('[data-act=restore]').click();
  await page.locator('.app-shell').waitFor();
  await page.waitForFunction(() => document.querySelector('[data-pending-count]')?.textContent === '2');
  assert.match(await page.locator('.transaction-list').innerText(), /离线采购测试/);

  const onlineMark = await syncMark();
  await context.setOffline(false);
  await page.evaluate(() => window.dispatchEvent(new Event('online')));
  await waitSync(onlineMark);
  health = await (await fetch(BASE + '/api/health')).json();
  assert.equal(health.entries, 2, '联网后应自动上传两笔且仅两笔');
  const manualMark = await syncMark();
  await page.locator('[data-act=sync-now]').click();
  await waitSync(manualMark);
  health = await (await fetch(BASE + '/api/health')).json();
  assert.equal(health.entries, 2, '手动重复同步不得产生重复记录');
  await page.screenshot({ path:OUT + '/jianji-desktop.png', fullPage:true });

  await page.locator('.side-nav [data-v=records]').click();
  await page.locator('[data-act=reverse-entry]').first().click();
  const reversalMark = await syncMark();
  await page.locator('[data-act=confirm-reversal]').click();
  await page.waitForFunction(() => document.querySelector('.records-panel')?.textContent.includes('冲销：'), null, { timeout:15000 });
  await waitSync(reversalMark);
  health = await (await fetch(BASE + '/api/health')).json();
  assert.equal(health.entries, 3, '红字冲销应追加第三条记录');
  assert.match(await page.locator('.records-panel').innerText(), /冲销：/);

  await page.setViewportSize({ width:375, height:812 });
  await page.locator('.mobile-nav [data-v=overview]').click();
  await page.waitForTimeout(250);
  await page.screenshot({ path:OUT + '/jianji-mobile.png', fullPage:true });
  assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= 375), true, '手机端不得横向溢出');
  await page.locator('.mobile-nav [data-v=entry]').click();
  await page.locator('#f-amount').waitFor();

  await page.goto(BASE + '/verify.html', { waitUntil:'networkidle' });
  await page.locator('.wrap').waitFor();
  assert.equal(errors.length, 0, '浏览器控制台不应有错误：' + errors.join('\n'));
  console.log(JSON.stringify({ ok:true, entries:health.entries, offlineReload:true, autoSync:true, idempotent:true, reversal:true, mobile:true, consoleErrors:errors }, null, 2));
} finally {
  fs.writeFileSync(OUT + '/jianji-browser-errors.json', JSON.stringify(errors, null, 2));
  await browser.close();
}
