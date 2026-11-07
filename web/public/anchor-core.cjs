/* 外部锚定核验：浏览器与 Node.js 共用，不读取密文、身份密钥或账目明文。 */
(function (root, factory) {
  const api = factory();
  if (typeof module === 'object' && module.exports) module.exports = api;
  root.AnchorCore = api;
})(typeof globalThis !== 'undefined' ? globalThis : this, function () {
  'use strict';
  const GENESIS = '0'.repeat(64);
  const SCHEMA = 'jianji.github-anchor/v1';
  const enc = s => new TextEncoder().encode(String(s));
  async function sha256hex(s) {
    const d = await crypto.subtle.digest('SHA-256', enc(s));
    return Array.from(new Uint8Array(d), x => x.toString(16).padStart(2, '0')).join('');
  }
  function ownersRoot(owners) {
    return (Array.isArray(owners) ? owners : []).map(o => String(o.fp) + ':' + String(o.head)).sort().join('|');
  }
  function sameAnchor(a, b) {
    return !!a && !!b && ['seq','prevHash','root','ts','hash'].every(k => a[k] === b[k]);
  }
  async function verifyAnchorProof(proof) {
    if (!proof || !Array.isArray(proof.anchors)) return { ok:false, broken:0, error:'证明格式无效' };
    let prev = GENESIS, broken = -1;
    for (let i = 0; i < proof.anchors.length; i++) {
      const a = proof.anchors[i];
      if (!a || a.seq !== i + 1 || a.prevHash !== prev) { broken = i + 1; break; }
      const calc = await sha256hex([a.seq, a.prevHash, a.root, a.ts].join('|'));
      if (a.hash !== calc) { broken = i + 1; break; }
      prev = a.hash;
    }
    const countOk = proof.anchorCount === proof.anchors.length;
    const headOk = prev === proof.anchorHead;
    const lastRoot = proof.anchors.length ? proof.anchors[proof.anchors.length - 1].root : await sha256hex(ownersRoot(proof.owners));
    const rootOk = lastRoot === proof.merkleRoot;
    let ownersOk = true;
    if (proof.anchors.length) {
      const currentRoot = await sha256hex(ownersRoot(proof.owners));
      ownersOk = currentRoot === proof.merkleRoot;
    }
    return { ok:broken < 0 && countOk && headOk && rootOk && ownersOk,
      broken, countOk, headOk, rootOk, ownersOk, head:prev, count:proof.anchors.length };
  }
  function validateAttestation(attestation, expectedOrigin) {
    if (!attestation || attestation.schema !== SCHEMA) return '不是简记 GitHub 锚点文件';
    const a = attestation.anchor;
    if (!a || !Number.isInteger(a.seq) || a.seq < 1) return '锚点序号无效';
    if (attestation.anchorCount !== a.seq || attestation.anchorHead !== a.hash || attestation.merkleRoot !== a.root)
      return '锚点文件内的摘要字段不一致';
    if (!attestation.observedAt || Number.isNaN(Date.parse(attestation.observedAt))) return '锚点观察时间无效';
    if (expectedOrigin) {
      try { if (new URL(attestation.ledgerUrl).origin !== new URL(expectedOrigin).origin) return '锚点属于另一个账本服务'; }
      catch (_) { return '锚点账本地址无效'; }
    }
    return '';
  }
  async function verifyExternalAnchor(proof, attestation, expectedOrigin) {
    const internal = await verifyAnchorProof(proof);
    const validationError = validateAttestation(attestation, expectedOrigin);
    if (validationError) return { ok:false, internal, error:validationError };
    const external = attestation.anchor;
    const match = proof.anchors.find(a => a.seq === external.seq);
    if (!sameAnchor(match, external)) {
      return { ok:false, internal, error:'GitHub 锚点不在当前锚链中：服务端可能替换或回滚了历史' };
    }
    const pending = proof.anchorCount - attestation.anchorCount;
    if (pending < 0) return { ok:false, internal, error:'当前锚链短于 GitHub 已发布锚点：检测到历史回滚' };
    return { ok:internal.ok, internal, pending, current:pending === 0,
      error:internal.ok ? '' : '服务端当前锚链自身未通过校验', anchor:external, attestation };
  }
  return { GENESIS, SCHEMA, sha256hex, verifyAnchorProof, validateAttestation, verifyExternalAnchor, sameAnchor };
});
