/* 简记本机加密归档核心：浏览器 / Node.js 共用的纯密码学逻辑。
   借鉴 Evolu / Cryptomator 的实践：
   - 口令不直接当数据密钥：PBKDF2-SHA256 600,000 次 + 随机 salt 派生独立的归档密钥；
   - 分域派生：归档密钥与身份密钥、账本密钥互不相干，泄露一层不牵连其它；
   - AEAD 的 AAD 绑定 版本/fp/seq/hash，密文被搬移或替换即解密失败；
   - 格式版本 MAC 防降级（攻击者不能把迭代次数改小后让客户端用弱参数重放）；
   - 明文按 512 字节分块填充，只暴露粗粒度长度。

   注意：这里加密的是「服务端/账本里已经是密文的 cipher」，即双层加密。
   归档层永远不接触账目明文，明文只在当前页面内存中存在。 */
(function (root, factory) {
  const api = factory();
  if (typeof module === 'object' && module.exports) module.exports = api;
  root.ArchiveCore = api;
})(typeof globalThis !== 'undefined' ? globalThis : this, function () {
  'use strict';
  const VERSION = 'jianji-archive/v1';
  const ITERATIONS = 600000;
  const SALT_BYTES = 16;
  const IV_BYTES = 12;
  const BLOCK = 512;
  const enc = s => new TextEncoder().encode(String(s));
  const dec = b => new TextDecoder().decode(b);
  const s = () => globalThis.crypto.subtle;

  function b64(bytes) {
    const a = new Uint8Array(bytes);
    let out = '';
    for (let i = 0; i < a.length; i++) out += String.fromCharCode(a[i]);
    return btoa(out);
  }
  function unb64(str) { return Uint8Array.from(atob(str), c => c.charCodeAt(0)); }
  function hex(bytes) { return Array.from(new Uint8Array(bytes), x => x.toString(16).padStart(2, '0')).join(''); }

  /* 独立的 MAC 域：从助记词用 HKDF 派生，仅用于校验归档参数没有被降级篡改。 */
  async function macKey(mnemonic) {
    const base = await s().importKey('raw', enc(mnemonic), 'HKDF', false, ['deriveKey']);
    return s().deriveKey({ name:'HKDF', hash:'SHA-256', salt:enc('jianji-archive-param-mac'),
      info:enc(VERSION + '|mac') }, base, { name:'HMAC', hash:'SHA-256', length:256 }, false, ['sign']);
  }
  function paramPayload(p) { return VERSION + '|' + p.iterations + '|' + p.salt; }

  /* 首次使用创建归档参数。salt 与迭代次数可以明文保存（Cryptomator 的做法），
     秘密只有助记词；mac 用来防止有人把 iterations 改小。 */
  async function createVault(mnemonic) {
    const salt = b64(globalThis.crypto.getRandomValues(new Uint8Array(SALT_BYTES)));
    const p = { version:VERSION, salt, iterations:ITERATIONS };
    const mk = await macKey(mnemonic);
    p.mac = hex(await s().sign('HMAC', mk, enc(paramPayload(p))));
    return p;
  }
  async function openVault(mnemonic, p) {
    if (!p || p.version !== VERSION) throw new Error('归档格式版本不支持，拒绝降级读取');
    if (!Number.isInteger(p.iterations) || p.iterations < ITERATIONS)
      throw new Error('归档密钥参数被降级或无效，拒绝读取');
    const mk = await macKey(mnemonic);
    const want = hex(await s().sign('HMAC', mk, enc(paramPayload(p))));
    if (want !== p.mac) throw new Error('归档参数校验失败，可能已被篡改');
    const base = await s().importKey('raw', enc(mnemonic), 'PBKDF2', false, ['deriveKey']);
    const key = await s().deriveKey({ name:'PBKDF2', hash:'SHA-256', salt:unb64(p.salt),
      iterations:p.iterations }, base, { name:'AES-GCM', length:256 }, false, ['encrypt','decrypt']);
    return { key, params:p };
  }
  function aadOf(r) { return VERSION + '|' + r.fp + '|' + r.seq + '|' + r.hash; }
  function keyOf(r) { return r.fp + ':' + r.source + ':' + r.seq + ':' + r.hash; }

  /* 把非秘密的归档参数冗余进每一行：设备坏了只剩归档文件时，
     只要还持有助记词就能重建密钥，不必依赖原设备 IndexedDB 里的 meta。 */
  function publicParams(p) {
    return { version:p.version, salt:p.salt, iterations:p.iterations, mac:p.mac };
  }
  async function vaultFromRow(mnemonic, row) {
    if (!row || !row.vault) throw new Error('归档行缺少密钥参数，请使用完整导出文件恢复');
    return openVault(mnemonic, row.vault);
  }
  /* 每条记录单独随机 IV + AAD 绑定；填充后长度只暴露 512 字节粒度。 */
  async function seal(key, record, vaultParams) {
    if (!record || !record.fp || !record.hash || !record.cipher)
      throw new Error('归档记录缺少必要字段');
    const r = { version:VERSION, fp:record.fp, source:record.source || 'own',
      grantId:record.grantId || '', label:record.label || '', seq:record.seq,
      prevHash:record.prevHash, hash:record.hash, ts:record.ts, sig:record.sig,
      cipher:record.cipher, bookTag:record.bookTag };
    const raw = enc(JSON.stringify(r));
    const pad = BLOCK - (raw.length % BLOCK);
    const buf = new Uint8Array(raw.length + pad);
    buf.set(raw); buf.fill(32, raw.length);
    const iv = globalThis.crypto.getRandomValues(new Uint8Array(IV_BYTES));
    const ct = await s().encrypt({ name:'AES-GCM', iv, additionalData:enc(aadOf(r)) }, key, buf);
    const row = { key:keyOf(r), fp:r.fp, source:r.source, seq:Number(r.seq), hash:r.hash,
      blob:b64(new Uint8Array(ct)), iv:b64(iv), version:VERSION, savedAt:Date.now() };
    if (vaultParams) row.vault = publicParams(vaultParams);
    return row;
  }
  async function open(key, row) {
    if (!row || row.version !== VERSION) throw new Error('归档记录版本不支持');
    const pt = await s().decrypt({ name:'AES-GCM', iv:unb64(row.iv),
      additionalData:enc(VERSION + '|' + row.fp + '|' + row.seq + '|' + row.hash) }, key, unb64(row.blob));
    const r = JSON.parse(dec(pt).trim());
    if (r.hash !== row.hash || r.fp !== row.fp || Number(r.seq) !== Number(row.seq))
      throw new Error('归档记录与索引不一致');
    return r;
  }
  return { VERSION, ITERATIONS, BLOCK, createVault, openVault, publicParams, vaultFromRow,
    seal, open, aadOf, keyOf, b64, unb64 };
});
