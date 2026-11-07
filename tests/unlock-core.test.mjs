/* 本机快捷解锁（PIN 信封加密）测试：浏览器与 Node.js 共用同一份实现。 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
const require = createRequire(import.meta.url);
const UnlockCore = require('../web/public/unlock-core.cjs');

const credential = () => ({
  mnemonic:'abandon ability able about above absent absorb abstract absurd abuse access accident account accuse achieve acid',
  priv:{ sign:{ kty:'EC', crv:'P-256', d:'sign-private' }, dh:{ kty:'EC', crv:'P-256', d:'dh-private' } },
  pubSign:{ kty:'EC', crv:'P-256', x:'a', y:'b' },
  pubDh:{ kty:'EC', crv:'P-256', x:'c', y:'d' },
  bundle:'encrypted-key-bundle', fp:'finger-print-001', verifier:'verifier-hash'
});

test('凭据结构校验：必须同时有 16 词助记词与两把私钥', () => {
  assert.equal(UnlockCore.validateCredential(credential()), true);
  assert.equal(UnlockCore.validateCredential({ ...credential(), priv:null }), false);
  assert.equal(UnlockCore.validateCredential({ ...credential(), mnemonic:'too short' }), false);
  assert.equal(UnlockCore.validateCredential({ ...credential(), fp:'' }), false);
});

test('封存后不含明文，且 PIN 可完整解出凭据', async () => {
  const c = credential();
  const pack = await UnlockCore.seal('628314', c);
  assert.equal(pack.version, UnlockCore.VERSION);
  assert.equal(pack.method, 'pin');
  assert.equal(pack.iterations, 600000);
  assert.equal(pack.fp, c.fp);
  assert.equal(pack.attempts, 0);
  assert.equal(JSON.stringify(pack).includes(c.mnemonic), false);
  const opened = await UnlockCore.open('628314', pack);
  assert.equal(opened.mnemonic, c.mnemonic);
  assert.equal(opened.priv.sign.d, 'sign-private');
  assert.equal(opened.fp, c.fp);
  assert.equal(UnlockCore.validateCredential(opened), true);
});

test('相同 PIN 每次封存使用不同 salt 与 IV', async () => {
  const a = await UnlockCore.seal('628314', credential());
  const b = await UnlockCore.seal('628314', credential());
  assert.notEqual(a.salt, b.salt);
  assert.notEqual(a.blob, b.blob);
});

test('错误 PIN、降级迭代次数、错误版本都拒绝读取', async () => {
  const pack = await UnlockCore.seal('628314', credential());
  await assert.rejects(() => UnlockCore.open('000000', pack), /.*/);
  await assert.rejects(() => UnlockCore.open('628314', { ...pack, iterations:1000 }), /降级/);
  await assert.rejects(() => UnlockCore.open('628314', { ...pack, version:'other' }), /版本/);
  await assert.rejects(() => UnlockCore.open('628314', { ...pack, iv:pack.iv.slice(0, -4) + 'AAAA' }), /.*/);
});

test('PIN 强度与凭据完整性在封存前校验', async () => {
  await assert.rejects(() => UnlockCore.seal('123', credential()), /至少 6 位/);
  await assert.rejects(() => UnlockCore.seal('628314', { fp:'x' }), /缺少必要字段/);
  assert.ok(UnlockCore.MAX_ATTEMPTS >= 3);
});
