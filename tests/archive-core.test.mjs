/* 本机加密归档的密码学属性测试：浏览器与 Node.js 共用同一份实现。 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
const require = createRequire(import.meta.url);
const ArchiveCore = require('../web/public/archive-core.cjs');

const MNEMONIC = 'abandon ability able about above absent absorb abstract absurd abuse access accident account accuse achieve acid';
const OTHER = 'zoo zone zero youth wrong world wood wife whole white water voice unit tree';
function record(overrides) {
  return Object.assign({
    fp:'finger-print-0001', source:'own', grantId:'', label:'',
    seq:1, prevHash:'0'.repeat(64), hash:'a'.repeat(64), ts:1700000000000,
    sig:'c2lnbmF0dXJl', cipher:'Y2lwaGVyLXRleHQ=', bookTag:'tag-abc'
  }, overrides || {});
}

test('归档参数：版本、随机 salt 与 OWASP 量级的迭代次数', async () => {
  const a = await ArchiveCore.createVault(MNEMONIC);
  const b = await ArchiveCore.createVault(MNEMONIC);
  assert.equal(a.version, ArchiveCore.VERSION);
  assert.equal(a.iterations, 600000);
  assert.notEqual(a.salt, b.salt);
  assert.match(a.mac, /^[0-9a-f]{64}$/);
});

test('相同助记词可重新解出归档密钥，错误助记词不能', async () => {
  const p = await ArchiveCore.createVault(MNEMONIC);
  const v = await ArchiveCore.openVault(MNEMONIC, p);
  assert.ok(v.key && v.key.type === 'secret');
  await assert.rejects(() => ArchiveCore.openVault(OTHER, p), /参数校验失败/);
});

test('格式版本、迭代次数或 MAC 被降级 / 篡改时拒绝读取', async () => {
  const p = await ArchiveCore.createVault(MNEMONIC);
  await assert.rejects(() => ArchiveCore.openVault(MNEMONIC, { ...p, iterations:1000 }), /降级|无效/);
  await assert.rejects(() => ArchiveCore.openVault(MNEMONIC, { ...p, version:'jianji-archive/v0' }), /版本/);
  await assert.rejects(() => ArchiveCore.openVault(MNEMONIC, { ...p, mac:'0'.repeat(64) }), /参数校验失败/);
  await assert.rejects(() => ArchiveCore.openVault(MNEMONIC, { ...p, iterations:600000, salt:p.salt, mac:'f'.repeat(64) }), /参数校验失败/);
});

test('归档往返：字段完整，且密文里不出现原始 cipher', async () => {
  const v = await ArchiveCore.openVault(MNEMONIC, await ArchiveCore.createVault(MNEMONIC));
  const r = record();
  const row = await ArchiveCore.seal(v.key, r);
  assert.ok(row.blob && row.iv);
  assert.equal(JSON.stringify(row).includes(r.cipher), false);
  assert.equal(row.key, ArchiveCore.keyOf(r));
  assert.notEqual(row.blob, (await ArchiveCore.seal(v.key, r)).blob, '每条记录必须使用不同随机 IV');
  const opened = await ArchiveCore.open(v.key, row);
  assert.equal(opened.cipher, r.cipher);
  assert.equal(opened.hash, r.hash);
  assert.equal(opened.seq, 1);
  assert.equal(opened.fp, r.fp);
});

test('AAD 绑定：索引里的 fp / seq / hash 被改动即解密失败', async () => {
  const v = await ArchiveCore.openVault(MNEMONIC, await ArchiveCore.createVault(MNEMONIC));
  const row = await ArchiveCore.seal(v.key, record());
  await assert.rejects(() => ArchiveCore.open(v.key, { ...row, hash:'b'.repeat(64) }), /.*/);
  await assert.rejects(() => ArchiveCore.open(v.key, { ...row, seq:2 }), /.*/);
  await assert.rejects(() => ArchiveCore.open(v.key, { ...row, fp:'someone-else' }), /.*/);
  await assert.rejects(() => ArchiveCore.open(v.key, { ...row, blob:row.blob.slice(0, -8) + 'AAAAAAAA' }), /.*/);
});

test('512 字节分块填充：同档位长度一致，只有跨档位才增长', async () => {
  const v = await ArchiveCore.openVault(MNEMONIC, await ArchiveCore.createVault(MNEMONIC));
  const short = await ArchiveCore.seal(v.key, record({ cipher:'YQ==' }));
  const medium = await ArchiveCore.seal(v.key, record({ cipher:Buffer.from('x'.repeat(120)).toString('base64') }));
  const long = await ArchiveCore.seal(v.key, record({ cipher:Buffer.from('x'.repeat(600)).toString('base64') }));
  assert.equal(short.blob.length, medium.blob.length, '同一 512B 档位内长度不可区分');
  assert.ok(long.blob.length > short.blob.length, '跨档位才会暴露更大粒度');
  const ctLen = ArchiveCore.unb64(short.blob).length - 16;
  assert.equal(ctLen % 512, 0, '密文长度应对齐到 512B（16 字节为 GCM 标签）');
});

test('归档行自包含非秘密参数：设备丢失后仅凭助记词 + 归档文件即可解开', async () => {
  const p = await ArchiveCore.createVault(MNEMONIC);
  const v = await ArchiveCore.openVault(MNEMONIC, p);
  const r = record();
  const row = await ArchiveCore.seal(v.key, r, p);
  assert.deepEqual(row.vault, ArchiveCore.publicParams(p));
  assert.equal(row.vault.mac, p.mac);
  /* 模拟换设备：本机 meta 全丢，手上只有导出的归档行与助记词。 */
  const rebuilt = await ArchiveCore.vaultFromRow(MNEMONIC, row);
  const opened = await ArchiveCore.open(rebuilt.key, row);
  assert.equal(opened.cipher, r.cipher);
  assert.equal(opened.hash, r.hash);
  await assert.rejects(() => ArchiveCore.vaultFromRow(OTHER, row), /参数校验失败/);
  await assert.rejects(() => ArchiveCore.vaultFromRow(MNEMONIC, { ...row, vault:undefined }), /缺少密钥参数/);
  const legacy = await ArchiveCore.seal(v.key, r);
  assert.equal(legacy.vault, undefined, '未传参数的旧调用仍可正常封存');
});

test('缺少必要字段或版本不符时拒绝封存', async () => {
  const v = await ArchiveCore.openVault(MNEMONIC, await ArchiveCore.createVault(MNEMONIC));
  await assert.rejects(() => ArchiveCore.seal(v.key, { fp:'x', hash:'y' }), /缺少必要字段/);
  await assert.rejects(() => ArchiveCore.open(v.key, { version:'other' }), /版本/);
});
