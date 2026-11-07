import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import core from '../local/src/ledger-core.cjs';

const tx = (id, amount = 1000, extra = {}) => ({
  id, type:'expense', amount, categoryId:'e_food', accountId:'a_cash',
  toAccountId:null, date:'2026-11-06', note:'午餐', party:'', voucher:'P001',
  createdAt:1793928000000, ...extra
});
async function bookOf(records) {
  const book = { id:'personal', name:'个人账', type:'personal', tx:[], accounts:[], categories:[], budgets:{},
    chain:{ head:core.GENESIS, seq:0, count:0 } };
  for (const record of records) {
    await core.sealRecord(record, book.chain);
    book.tx.push(record);
  }
  return book;
}

test('SHA-256 与 Node 标准实现一致（含空串与中文）', async () => {
  for (const value of ['', 'abc', '简记·不可篡改账本🧾', 'x'.repeat(10000)]) {
    const expected = crypto.createHash('sha256').update(value).digest('hex');
    assert.equal(core.sha256Sync(value), expected);
    assert.equal(await core.digest(value), expected);
  }
});

test('追加封存后序号、前序哈希和链头均可独立重算', async () => {
  const book = await bookOf([tx('a'), tx('b', 2000), tx('c', 3000)]);
  const result = await core.verifyBook(book);
  assert.equal(result.ok, true);
  assert.equal(result.count, 3);
  assert.equal(book.tx[0].prevHash, core.GENESIS);
  assert.equal(book.tx[1].prevHash, book.tx[0].hash);
  assert.equal(book.chain.head, book.tx[2].hash);
});

test('修改金额、备注、序号或删除历史都会被发现', async () => {
  const original = await bookOf([tx('a'), tx('b'), tx('c')]);
  for (const mutate of [
    b => { b.tx[1].amount += 1; },
    b => { b.tx[0].note = '被篡改'; },
    b => { b.tx[2].seq = 9; },
    b => { b.tx.splice(1, 1); },
    b => { b.chain.head = core.GENESIS; }
  ]) {
    const copy = structuredClone(original);
    mutate(copy);
    assert.equal((await core.verifyBook(copy)).ok, false);
  }
});

test('红字冲销只追加反向分录，原记录不变且净额归零', async () => {
  const book = await bookOf([tx('original', 12800)]);
  const before = JSON.stringify(book.tx[0]);
  const reversal = core.createReversal(book.tx[0], {
    id:'reverse-1', date:'2026-11-07', allTx:book.tx, categoryId:'i_other', createdAt:1794000000000
  });
  await core.sealRecord(reversal, book.chain);
  book.tx.push(reversal);
  assert.equal(JSON.stringify(book.tx[0]), before);
  assert.equal(reversal.type, 'income');
  assert.equal(reversal.reversalOf, 'original');
  assert.equal(core.signedTotals(book.tx), 0);
  assert.equal((await core.verifyBook(book)).ok, true);
  assert.throws(() => core.createReversal(book.tx[0], { id:'x', date:'2026-11-08', allTx:book.tx }), /已经冲销/);
});

test('转账冲销会交换转出与转入账户', async () => {
  const transfer = tx('transfer', 5000, { type:'transfer', categoryId:null, accountId:'a_bank', toAccountId:'a_wx' });
  const book = await bookOf([transfer]);
  const reversal = core.createReversal(transfer, { id:'r', date:'2026-11-07', allTx:book.tx });
  assert.equal(reversal.accountId, 'a_wx');
  assert.equal(reversal.toAccountId, 'a_bank');
});

test('恢复只能向前：拒绝缩短历史或替换前缀', async () => {
  const book = await bookOf([tx('a'), tx('b'), tx('c')]);
  assert.equal(core.assertPrefix(book.tx, book.tx), true);
  assert.throws(() => core.assertPrefix(book.tx, book.tx.slice(0, 2)), /拒绝回退/);
  const changed = structuredClone(book.tx);
  changed[0].hash = 'f'.repeat(64);
  assert.throws(() => core.assertPrefix(book.tx, changed), /拒绝覆盖/);
});

test('JSONL 导出与解析保留元数据、顺序和哈希链', async () => {
  const book = await bookOf([tx('a'), tx('b')]);
  const text = core.serializeBook(book, '2026-11-06T00:00:00.000Z');
  const parsed = core.parseBook(text);
  assert.equal(parsed.bookId, 'personal');
  assert.equal(parsed.meta.name, '个人账');
  assert.deepEqual(parsed.records.map(t => t.id), ['a', 'b']);
  assert.equal((await core.verifyRecords(parsed.records, book.chain.head)).ok, true);
  assert.throws(() => core.parseBook('# empty'), /没有账本记录/);
});
