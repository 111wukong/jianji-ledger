/* 加密备份守护进程：定时把事件日志备份到多个目标，并定期自动做一次恢复校验。
   零第三方依赖，可与账本服务同机或分机运行；不需要修改服务端代码。

   用法：
     LEDGER_BACKUP_PASSPHRASE='...' LEDGER_BACKUP_DIRS='/mnt/disk2/jianji,/mnt/nas/jianji' npm run backup:daemon
   可选：
     LEDGER_BACKUP_INTERVAL_HOURS  备份间隔，默认 6 小时
     LEDGER_BACKUP_DRILL_DAYS      自动演练间隔，默认 30 天
     LEDGER_BACKUP_KEEP            每个目标保留份数
     LEDGER_DATA_DIR               事件日志源目录

   每次执行输出一行 JSON 日志，便于接入监控。失败不会退出进程，下一轮自动重试。 */
import fs from 'node:fs';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const BACKUP = path.join(ROOT, 'scripts', 'backup-log.mjs');
const VERIFY = path.join(ROOT, 'scripts', 'verify-backup.mjs');
const INTERVAL_H = Math.max(1, Number(process.env.LEDGER_BACKUP_INTERVAL_HOURS) || 6);
const DRILL_D = Math.max(1, Number(process.env.LEDGER_BACKUP_DRILL_DAYS) || 30);
const FIRST_DIR = (process.env.LEDGER_BACKUP_DIRS || process.env.LEDGER_BACKUP_DIR ||
  path.join(ROOT, 'backups')).split(',')[0].trim();

if (!process.env.LEDGER_BACKUP_PASSPHRASE) {
  console.error('缺少 LEDGER_BACKUP_PASSPHRASE，备份守护进程拒绝启动。');
  process.exit(1);
}
function log(kind, extra) {
  console.log(JSON.stringify(Object.assign({ at: new Date().toISOString(), kind }, extra || {})));
}
function runBackup() {
  try {
    const out = execFileSync(process.execPath, [BACKUP], { env: process.env, encoding: 'utf8' });
    const report = JSON.parse(out);
    log('backup', { ok: true, files: report.files.length, lines: report.lines,
      anchors: report.anchors, targets: report.targets.map(t => t.count) });
    return report;
  } catch (e) {
    log('backup', { ok: false, error: String(e.stderr || e.message || e).slice(0, 400) });
    return null;
  }
}
function latestBackup() {
  try {
    const dir = path.resolve(FIRST_DIR);
    const files = fs.readdirSync(dir)
      .filter(f => f.startsWith('jianji-') && f.endsWith('.jsonl.enc'))
      .map(f => path.join(dir, f))
      .sort();
    return files.length ? files[files.length - 1] : null;
  } catch (e) { return null; }
}
function runDrill() {
  const file = latestBackup();
  if (!file) { log('drill', { ok: false, error: '没有可校验的加密备份' }); return; }
  try {
    const out = execFileSync(process.execPath, [VERIFY, file], { env: process.env, encoding: 'utf8' });
    const report = JSON.parse(out);
    log('drill', { ok: true, file: path.basename(file), lines: report.lines,
      anchors: report.anchors, anchorHead: report.anchorHead });
  } catch (e) {
    log('drill', { ok: false, file: path.basename(file),
      error: String(e.stderr || e.message || e).slice(0, 400) });
  }
}

/* 30 天的毫秒数超过 32 位有符号整数上限，直接 setInterval 会被 Node 截断成 1ms
   并疯狂重复执行。这里改用固定心跳 + 时间戳判断，长周期也安全。 */
const TICK_MS = 10 * 60 * 1000;
const BACKUP_MS = INTERVAL_H * 3600 * 1000;
const DRILL_MS = DRILL_D * 24 * 3600 * 1000;
let lastBackup = Date.now(), lastDrill = Date.now();

log('start', { intervalHours: INTERVAL_H, drillDays: DRILL_D, tickMinutes: 10, targets: FIRST_DIR });
runBackup();
runDrill();
const timer = setInterval(() => {
  const now = Date.now();
  if (now - lastBackup >= BACKUP_MS) { lastBackup = now; runBackup(); }
  if (now - lastDrill >= DRILL_MS) { lastDrill = now; runDrill(); }
}, TICK_MS);
function shutdown() {
  clearInterval(timer);
  log('stop', {});
  process.exit(0);
}
process.on('SIGTERM', shutdown);
process.on('SIGINT', shutdown);
