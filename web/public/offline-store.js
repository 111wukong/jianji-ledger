/* 本机加密账本库。只写入密文记录与签名，不保存解密后的账目。
   entries   = 正常读写用的账本记录（含待同步队列）
   archive   = 后台静默保存的全量加密归档（双层加密，仅灾备与迁移用）
   meta      = 账本目录、同步时间、归档参数等非敏感元数据 */
(function (root) {
  'use strict';
  const DB_NAME = 'jianji.unified.v1';
  const DB_VERSION = 2;
  let dbPromise = null;

  function open() {
    if (dbPromise) return dbPromise;
    dbPromise = new Promise((resolve, reject) => {
      if (!root.indexedDB) return reject(new Error('当前浏览器不支持本机账本数据库'));
      const req = root.indexedDB.open(DB_NAME, DB_VERSION);
      req.onupgradeneeded = () => {
        const db = req.result;
        if (!db.objectStoreNames.contains('entries')) {
          const store = db.createObjectStore('entries', { keyPath: 'key' });
          store.createIndex('fp', 'fp', { unique: false });
        }
        if (!db.objectStoreNames.contains('archive')) {
          const store = db.createObjectStore('archive', { keyPath: 'key' });
          store.createIndex('fp', 'fp', { unique: false });
        }
        if (!db.objectStoreNames.contains('meta')) db.createObjectStore('meta', { keyPath: 'key' });
      };
      req.onsuccess = () => {
        req.result.onversionchange = () => req.result.close();
        resolve(req.result);
      };
      req.onerror = () => reject(req.error || new Error('无法打开本机账本数据库'));
      req.onblocked = () => reject(new Error('本机账本数据库被其他页面占用，请关闭旧页面后重试'));
    });
    return dbPromise;
  }

  function tx(storeName, mode, work) {
    return open().then(db => new Promise((resolve, reject) => {
      const transaction = db.transaction(storeName, mode);
      const store = transaction.objectStore(storeName);
      let result;
      try { result = work(store); } catch (err) { reject(err); return; }
      transaction.oncomplete = () => resolve(result && result.result !== undefined ? result.result : result);
      transaction.onerror = () => reject(transaction.error || new Error('本机账本写入失败'));
      transaction.onabort = () => reject(transaction.error || new Error('本机账本事务已中止'));
    }));
  }

  function request(storeName, mode, work) {
    return open().then(db => new Promise((resolve, reject) => {
      const transaction = db.transaction(storeName, mode);
      const req = work(transaction.objectStore(storeName));
      req.onsuccess = () => resolve(req.result);
      req.onerror = () => reject(req.error || new Error('本机账本读取失败'));
    }));
  }

  const key = (fp, hash) => fp + ':' + hash;
  const normalize = (fp, entry, pending) => ({
    key: key(fp, entry.hash), fp, hash: entry.hash, seq: Number(entry.seq),
    pending: !!pending, savedAt: Date.now(), entry
  });

  async function all(fp) {
    const rows = await request('entries', 'readonly', store => store.index('fp').getAll(fp));
    return rows.sort((a, b) => a.seq - b.seq || Number(a.pending) - Number(b.pending));
  }
  async function put(fp, entry, pending) {
    await tx('entries', 'readwrite', store => store.put(normalize(fp, entry, pending)));
    return entry;
  }
  async function putMany(fp, entries, pending) {
    await tx('entries', 'readwrite', store => {
      for (const entry of entries) store.put(normalize(fp, entry, pending));
    });
  }
  /* 增量写入服务端新增的后缀，避免每次轮询删光并重写整本账。 */
  async function putSynced(fp, entries) {
    if (!entries || !entries.length) return;
    await putMany(fp, entries, false);
  }
  async function markSynced(fp, entry) { return put(fp, entry, false); }
  async function remove(fp, hash) { await tx('entries', 'readwrite', store => store.delete(key(fp, hash))); }

  /* 只替换已同步部分，绝不在刷新服务端时清掉待上传记录。 */
  async function replaceSynced(fp, entries) {
    const rows = await all(fp);
    await tx('entries', 'readwrite', store => {
      for (const row of rows) if (!row.pending) store.delete(row.key);
      for (const entry of entries) store.put(normalize(fp, entry, false));
    });
  }
  async function setMeta(keyName, value) {
    await tx('meta', 'readwrite', store => store.put({ key: keyName, value }));
  }
  async function getMeta(keyName, fallback) {
    const row = await request('meta', 'readonly', store => store.get(keyName));
    return row ? row.value : fallback;
  }
  async function clear(fp) {
    const rows = await all(fp);
    await tx('entries', 'readwrite', store => { for (const row of rows) store.delete(row.key); });
  }

  async function archiveAll(fp) {
    const rows = await request('archive', 'readonly', store => store.index('fp').getAll(fp));
    return rows.sort((a, b) => a.seq - b.seq);
  }
  async function archiveReplace(fp, rows) {
    const old = await archiveAll(fp);
    await tx('archive', 'readwrite', store => {
      for (const row of old) store.delete(row.key);
      for (const row of rows) store.put(row);
    });
  }
  async function archiveStats(fp) {
    const rows = await archiveAll(fp);
    let bytes = 0;
    for (const r of rows) bytes += (r.blob ? r.blob.length : 0) + (r.iv ? r.iv.length : 0);
    return { count: rows.length, bytes };
  }
  async function archiveClear(fp) {
    const rows = await archiveAll(fp);
    await tx('archive', 'readwrite', store => { for (const row of rows) store.delete(row.key); });
  }

  root.LedgerStore = { all, put, putMany, putSynced, markSynced, remove, replaceSynced,
    setMeta, getMeta, clear, archiveAll, archiveReplace, archiveStats, archiveClear };
})(typeof globalThis !== 'undefined' ? globalThis : window);
