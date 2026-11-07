/* 本机快捷解锁：信封加密，浏览器 / Node.js 共用。
   借鉴 Bitwarden / 1Password / KeePassXC 的密钥层级：
   PIN → PBKDF2(60 万次) → KEK → AES-256-GCM 包住「助记词 + 私钥」这枚凭据。

   重要边界：KEK 由用户 PIN 派生，浏览器 localStorage 没有 Secure Enclave 保护，
   因此能拿到本机存储的人可以离线尝试 PIN。它的定位是「本机便利」，
   跨设备恢复与最高安全级别仍然只有助记词。生产升级路径是 WebAuthn PRF
   （认证器给出 32 字节确定性输出，不经服务端，也不存本地），pack.method 已预留。 */
(function (root, factory) {
  const api = factory();
  if (typeof module === 'object' && module.exports) module.exports = api;
  root.UnlockCore = api;
})(typeof globalThis !== 'undefined' ? globalThis : this, function () {
  'use strict';
  const VERSION = 'jianji-quickunlock/v1';
  const ITERATIONS = 600000;
  const SALT_BYTES = 16;
  const IV_BYTES = 12;
  const MAX_ATTEMPTS = 5;
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

  async function pinKey(pin, salt, iterations) {
    const base = await s().importKey('raw', enc(pin), 'PBKDF2', false, ['deriveKey']);
    return s().deriveKey({ name:'PBKDF2', hash:'SHA-256', salt:unb64(salt), iterations },
      base, { name:'AES-GCM', length:256 }, false, ['encrypt','decrypt']);
  }
  /* credential = { mnemonic, priv, pubSign, pubDh, bundle, fp, verifier } */
  async function seal(pin, credential, method) {
    if (typeof pin !== 'string' || pin.length < 6) throw new Error('快捷解锁 PIN 至少 6 位');
    if (!credential || !credential.mnemonic || !credential.priv || !credential.fp)
      throw new Error('凭据缺少必要字段');
    const salt = b64(globalThis.crypto.getRandomValues(new Uint8Array(SALT_BYTES)));
    const iterations = ITERATIONS;
    const key = await pinKey(pin, salt, iterations);
    const iv = globalThis.crypto.getRandomValues(new Uint8Array(IV_BYTES));
    const ct = await s().encrypt({ name:'AES-GCM', iv, additionalData:enc(VERSION) },
      key, enc(JSON.stringify(credential)));
    return { version:VERSION, method:method || 'pin', salt, iterations,
      iv:b64(iv), blob:b64(new Uint8Array(ct)), fp:credential.fp,
      savedAt:Date.now(), attempts:0 };
  }
  async function open(pin, pack) {
    if (!pack || pack.version !== VERSION) throw new Error('快捷解锁数据版本不支持');
    if (!Number.isInteger(pack.iterations) || pack.iterations < ITERATIONS)
      throw new Error('快捷解锁参数被降级，拒绝读取');
    const key = await pinKey(pin, pack.salt, pack.iterations);
    const pt = await s().decrypt({ name:'AES-GCM', iv:unb64(pack.iv),
      additionalData:enc(VERSION) }, key, unb64(pack.blob));
    const c = JSON.parse(dec(pt));
    if (c.fp !== pack.fp) throw new Error('凭据与索引不一致');
    return c;
  }
  function validateCredential(c) {
    return !!(c && typeof c.mnemonic === 'string' && c.mnemonic.trim().split(/\s+/).length === 16 &&
      c.priv && c.priv.sign && c.priv.dh && c.pubSign && c.pubDh && c.fp && c.bundle);
  }
  return { VERSION, ITERATIONS, MAX_ATTEMPTS, seal, open, validateCredential, b64, unb64 };
});
