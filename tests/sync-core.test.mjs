import test from 'node:test';
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
const require = createRequire(import.meta.url);
const Sync = require('../web/public/sync-core.cjs');
const G = Sync.GENESIS;
const e = (seq, prevHash, hash) => ({ seq, prevHash, hash, cipher: 'encrypted', sig: 'signed' });

test('空服务端接受完整离线链', () => {
  const queue = [e(1, G, 'a'), e(2, 'a', 'b'), e(3, 'b', 'c')];
  const plan = Sync.uploadBatch([], queue, 2);
  assert.equal(plan.conflict, null);
  assert.deepEqual(plan.batch.map(x => x.hash), ['a', 'b']);
  assert.equal(plan.pending.length, 3);
});

test('响应丢失后重试：服务端已有记录被识别为 existing', () => {
  const queue = [e(1, G, 'a'), e(2, 'a', 'b')];
  const server = [e(1, G, 'a')];
  const plan = Sync.assessOutbox(server, queue);
  assert.deepEqual(plan.existing.map(x => x.hash), ['a']);
  assert.deepEqual(plan.pending.map(x => x.hash), ['b']);
  assert.equal(plan.conflict, null);
});

test('全部已上传时不产生重复批次', () => {
  const chain = [e(1, G, 'a'), e(2, 'a', 'b')];
  const plan = Sync.uploadBatch(chain, chain);
  assert.equal(plan.existing.length, 2);
  assert.equal(plan.batch.length, 0);
  assert.equal(plan.conflict, null);
});

test('另一设备推进相同序号时报告分叉，禁止自动覆盖', () => {
  const server = [e(1, G, 'remote')];
  const queue = [e(1, G, 'local')];
  const plan = Sync.assessOutbox(server, queue);
  assert.equal(plan.conflict.reason, 'divergent-history');
  assert.equal(plan.pending.length, 0);
});

test('离线队列前序不匹配时停止上传', () => {
  const plan = Sync.assessOutbox([], [e(1, G, 'a'), e(2, 'wrong', 'b')]);
  assert.equal(plan.conflict.reason, 'non-contiguous-outbox');
  assert.equal(plan.batch, undefined);
});

test('服务端缩短或替换缓存前缀会被拒绝', () => {
  const cached = [e(1, G, 'a'), e(2, 'a', 'b')];
  assert.equal(Sync.prefixProblem(cached, [e(1, G, 'a')]).reason, 'server-shrunk');
  assert.equal(Sync.prefixProblem(cached, [e(1, G, 'x'), e(2, 'x', 'b')]).reason, 'server-prefix-changed');
  assert.equal(Sync.prefixProblem(cached, cached.concat(e(3, 'b', 'c'))), null);
});

test('上传批次最多 50 条且保持原顺序', () => {
  let prev = G;
  const queue = Array.from({ length: 70 }, (_, i) => {
    const row = e(i + 1, prev, 'h' + (i + 1)); prev = row.hash; return row;
  });
  const plan = Sync.uploadBatch([], queue, 500);
  assert.equal(plan.batch.length, 50);
  assert.equal(plan.batch[49].seq, 50);
  assert.equal(plan.pending.length, 70);
});
