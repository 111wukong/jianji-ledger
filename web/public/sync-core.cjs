/* 简记统一同步核心：纯函数，浏览器 / Node.js 共用。
   不合并分叉、不改写历史；只识别可安全上传的连续后缀。 */
(function (root, factory) {
  const api = factory();
  if (typeof module === 'object' && module.exports) module.exports = api;
  root.SyncCore = api;
})(typeof globalThis !== 'undefined' ? globalThis : this, function () {
  'use strict';
  const GENESIS = '0'.repeat(64);

  function bySeq(entries) {
    return (entries || []).slice().sort((a, b) => Number(a.seq) - Number(b.seq));
  }

  function chainProblem(chain) {
    let prev = GENESIS;
    const list = bySeq(chain);
    for (let i = 0; i < list.length; i++) {
      const e = list[i];
      if (Number(e.seq) !== i + 1) return { index: i, reason: 'gap' };
      if (e.prevHash !== prev) return { index: i, reason: 'prefix' };
      prev = e.hash;
    }
    return null;
  }

  /* 已缓存的服务端记录必须仍是新响应的严格前缀。
     否则说明服务端回滚、替换，或本机缓存属于另一条历史。 */
  function prefixProblem(cached, incoming) {
    const oldList = bySeq(cached), newList = bySeq(incoming);
    if (chainProblem(newList)) return { reason: 'invalid-server-chain' };
    if (oldList.length > newList.length) return { reason: 'server-shrunk', at: newList.length + 1 };
    for (let i = 0; i < oldList.length; i++) {
      if (oldList[i].hash !== newList[i].hash || Number(oldList[i].seq) !== Number(newList[i].seq))
        return { reason: 'server-prefix-changed', at: i + 1 };
    }
    return null;
  }

  /* 返回：已存在（可安全确认）、待上传（连续后缀）、分叉（必须人工处理）。 */
  function assessOutbox(serverChain, outbox) {
    const server = bySeq(serverChain), queue = bySeq(outbox);
    const serverProblem = chainProblem(server);
    if (serverProblem) return { existing: [], pending: [], conflict: { reason: 'invalid-server-chain', at: serverProblem.index + 1 } };
    const byHash = new Map(server.map(e => [e.hash, e]));
    const existing = [], remaining = [];
    for (const e of queue) (byHash.has(e.hash) ? existing : remaining).push(e);
    if (!remaining.length) return { existing, pending: [], conflict: null };

    let head = server.length ? server[server.length - 1].hash : GENESIS;
    let seq = server.length;
    const pending = [];
    for (const e of remaining) {
      if (Number(e.seq) <= seq) {
        return { existing, pending: [], conflict: {
          reason: 'divergent-history', at: Number(e.seq), hash: e.hash,
          serverHash: server[Number(e.seq) - 1] && server[Number(e.seq) - 1].hash
        } };
      }
      if (Number(e.seq) !== seq + 1 || e.prevHash !== head) {
        return { existing, pending: [], conflict: {
          reason: 'non-contiguous-outbox', at: Number(e.seq), hash: e.hash, expectedSeq: seq + 1, expectedPrevHash: head
        } };
      }
      pending.push(e); seq = Number(e.seq); head = e.hash;
    }
    return { existing, pending, conflict: null };
  }

  function uploadBatch(serverChain, outbox, limit) {
    const plan = assessOutbox(serverChain, outbox);
    return Object.assign(plan, { batch: plan.pending.slice(0, Math.max(1, Math.min(50, Number(limit) || 50))) });
  }

  return { GENESIS, bySeq, chainProblem, prefixProblem, assessOutbox, uploadBatch };
});
