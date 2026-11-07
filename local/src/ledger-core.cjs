/* 简记本地账本核心：纯数据逻辑，可在浏览器与 Node.js 中运行。 */
(function (root, factory) {
  const api = factory();
  if (typeof module === 'object' && module.exports) module.exports = api;
  root.LedgerCore = api;
})(typeof globalThis !== 'undefined' ? globalThis : this, function () {
  'use strict';

  const GENESIS = '0'.repeat(64);
  const SHA_K = new Uint32Array([
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
  ]);

  function sha256Sync(str) {
    const bytes = new TextEncoder().encode(String(str));
    const bitLen = bytes.length * 8;
    const total = Math.ceil((bytes.length + 9) / 64) * 64;
    const buf = new Uint8Array(total);
    buf.set(bytes); buf[bytes.length] = 0x80;
    const dv = new DataView(buf.buffer);
    dv.setUint32(total - 8, Math.floor(bitLen / 0x100000000), false);
    dv.setUint32(total - 4, bitLen >>> 0, false);
    const H = new Uint32Array([0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19]);
    const w = new Uint32Array(64);
    const rotr = (x, n) => (x >>> n) | (x << (32 - n));
    for (let off = 0; off < total; off += 64) {
      for (let i = 0; i < 16; i++) w[i] = dv.getUint32(off + i * 4, false);
      for (let i = 16; i < 64; i++) {
        const s0 = rotr(w[i-15],7) ^ rotr(w[i-15],18) ^ (w[i-15] >>> 3);
        const s1 = rotr(w[i-2],17) ^ rotr(w[i-2],19) ^ (w[i-2] >>> 10);
        w[i] = (w[i-16] + s0 + w[i-7] + s1) >>> 0;
      }
      let a=H[0],b=H[1],c=H[2],d=H[3],e=H[4],f=H[5],g=H[6],h=H[7];
      for (let i = 0; i < 64; i++) {
        const S1 = rotr(e,6)^rotr(e,11)^rotr(e,25), ch = (e&f)^((~e)&g);
        const t1 = (h+S1+ch+SHA_K[i]+w[i]) >>> 0;
        const S0 = rotr(a,2)^rotr(a,13)^rotr(a,22), maj = (a&b)^(a&c)^(b&c);
        const t2 = (S0+maj) >>> 0;
        h=g; g=f; f=e; e=(d+t1)>>>0; d=c; c=b; b=a; a=(t1+t2)>>>0;
      }
      H[0]=(H[0]+a)>>>0; H[1]=(H[1]+b)>>>0; H[2]=(H[2]+c)>>>0; H[3]=(H[3]+d)>>>0;
      H[4]=(H[4]+e)>>>0; H[5]=(H[5]+f)>>>0; H[6]=(H[6]+g)>>>0; H[7]=(H[7]+h)>>>0;
    }
    return Array.from(H, x => x.toString(16).padStart(8, '0')).join('');
  }

  async function digest(str) {
    if (globalThis.crypto && globalThis.crypto.subtle) {
      try {
        const d = await globalThis.crypto.subtle.digest('SHA-256', new TextEncoder().encode(String(str)));
        return Array.from(new Uint8Array(d), b => b.toString(16).padStart(2, '0')).join('');
      } catch (_) { /* file:// 等环境回退到同步实现 */ }
    }
    return sha256Sync(str);
  }

  function canonicalTx(t) {
    return JSON.stringify({ id:t.id, type:t.type, amount:t.amount,
      categoryId:t.categoryId || null, accountId:t.accountId, toAccountId:t.toAccountId || null,
      date:t.date, note:t.note || '', party:t.party || '', voucher:t.voucher || '',
      reversalOf:t.reversalOf || null, createdAt:t.createdAt || 0 });
  }
  const chainPayload = t => t.seq + '|' + t.prevHash + '|' + canonicalTx(t);
  const lockedRecords = tx => (Array.isArray(tx) ? tx : []).filter(t => t && t.hash).sort((a,b) => a.seq - b.seq);

  async function sealRecord(t, chain) {
    if (!t || typeof t !== 'object') throw new Error('记录格式无效');
    if (t.hash) throw new Error('已封存记录不能重复写入');
    chain.seq += 1;
    t.seq = chain.seq; t.prevHash = chain.head;
    t.hash = await digest(chainPayload(t));
    chain.head = t.hash; chain.count += 1;
    return t;
  }

  async function verifyRecords(records, declaredHead) {
    const list = Array.isArray(records) ? records : [];
    let prev = GENESIS, broken = -1, count = 0;
    for (let i = 0; i < list.length; i++) {
      const t = list[i];
      if (t.seq !== i + 1 || t.prevHash !== prev) { broken = i + 1; break; }
      if (await digest(chainPayload(t)) !== t.hash) { broken = i + 1; break; }
      prev = t.hash; count++;
    }
    const declared = declaredHead || GENESIS;
    const headOk = prev === declared;
    return { ok:broken < 0 && headOk && count === list.length,
      count, total:list.length, broken, head:prev, declared, headOk };
  }

  async function verifyBook(book) {
    const list = lockedRecords(book && book.tx);
    const result = await verifyRecords(list, book && book.chain && book.chain.head);
    result.unlocked = ((book && book.tx) || []).length - list.length;
    return result;
  }

  function reversedIds(tx) {
    const ids = new Set();
    for (const t of (Array.isArray(tx) ? tx : [])) if (t.reversalOf) ids.add(t.reversalOf);
    return ids;
  }

  function createReversal(original, options) {
    if (!original || !original.hash) throw new Error('只能冲销已封存的记录');
    const opts = options || {};
    if (reversedIds(opts.allTx).has(original.id)) throw new Error('这笔已经冲销过了');
    if (!opts.id || !opts.date) throw new Error('冲销记录缺少 id 或日期');
    const revType = original.type === 'expense' ? 'income' : original.type === 'income' ? 'expense' : 'transfer';
    return {
      id:opts.id, type:revType, amount:original.amount,
      categoryId:original.type === 'transfer' ? null : (opts.categoryId || original.categoryId),
      accountId:original.type === 'transfer' ? original.toAccountId : original.accountId,
      toAccountId:original.type === 'transfer' ? original.accountId : null,
      date:opts.date, note:opts.note || ('冲销 ' + original.id),
      party:original.party || '', voucher:(original.voucher || 'R') + '-R',
      reversalOf:original.id, createdAt:opts.createdAt || 0
    };
  }

  function signedTotals(tx) {
    let net = 0;
    for (const t of tx) {
      if (t.type === 'income') net += t.amount;
      else if (t.type === 'expense') net -= t.amount;
    }
    return net;
  }

  function assertPrefix(currentTx, restoredTx) {
    const cur = lockedRecords(currentTx), next = lockedRecords(restoredTx);
    if (next.length < cur.length) throw new Error('恢复的数据比当前账本短，拒绝回退或删除历史');
    for (let i = 0; i < cur.length; i++) {
      if (next[i].hash !== cur[i].hash) throw new Error('恢复的数据与已封存历史不一致（第 ' + (i+1) + ' 条），拒绝覆盖');
    }
    return true;
  }

  function serializeBook(book, exportedAt) {
    const c = book.chain || { head:GENESIS, count:0 };
    const lines = ['# 简记不可变账本 v3 | book=' + book.id + ' | name=' + book.name +
      ' | head=' + c.head + ' | count=' + c.count + ' | exported=' + (exportedAt || new Date().toISOString()),
      '#META ' + JSON.stringify({ name:book.name, type:book.type,
        accounts:book.accounts, categories:book.categories, budgets:book.budgets })];
    for (const t of lockedRecords(book.tx)) lines.push(JSON.stringify(t));
    return lines.join('\n') + '\n';
  }

  function parseBook(text) {
    const raw = String(text).split(/\r?\n/);
    const header = raw[0] || '';
    let meta = null;
    const metaLine = raw.find(l => l.indexOf('#META ') === 0);
    if (metaLine) { try { meta = JSON.parse(metaLine.slice(6)); } catch (_) {} }
    const match = header.match(/book=([^\s|]+)/);
    const lines = raw.filter(l => l.trim().charAt(0) === '{');
    if (!lines.length) throw new Error('文件里没有账本记录');
    const records = lines.map((line, i) => {
      try { return JSON.parse(line); } catch (_) { throw new Error('第 ' + (i+1) + ' 行格式错误'); }
    });
    return { bookId:match && match[1], meta, records };
  }

  return { GENESIS, sha256Sync, digest, canonicalTx, chainPayload, lockedRecords,
    sealRecord, verifyRecords, verifyBook, reversedIds, createReversal, signedTotals,
    assertPrefix, serializeBook, parseBook };
});
