import test from 'node:test';
import assert from 'node:assert/strict';
import AnchorCore from '../web/public/anchor-core.cjs';

async function proofOf(count = 3) {
  const proof = { version:2, generatedAt:'2026-11-06T00:00:00.000Z', anchors:[], owners:[{ fp:'abc', head:'def', seq:1, count:1 }] };
  proof.merkleRoot = await AnchorCore.sha256hex('abc:def');
  let prev = AnchorCore.GENESIS;
  for (let i = 1; i <= count; i++) {
    const a = { t:'anchor', seq:i, prevHash:prev, root:proof.merkleRoot, ts:1793928000000 + i, hash:'' };
    a.hash = await AnchorCore.sha256hex([a.seq, a.prevHash, a.root, a.ts].join('|'));
    proof.anchors.push(a); prev = a.hash;
  }
  proof.anchorCount = count; proof.anchorHead = prev;
  return proof;
}
function attestationOf(proof, seq = proof.anchorCount) {
  const anchor = proof.anchors[seq - 1];
  return { schema:AnchorCore.SCHEMA, ledgerUrl:'https://ledger.example', observedAt:'2026-11-06T00:00:00.000Z',
    merkleRoot:anchor.root, anchorHead:anchor.hash, anchorCount:anchor.seq, anchor:structuredClone(anchor) };
}

test('完整锚链可独立重算，空锚链也支持', async () => {
  const proof = await proofOf();
  assert.equal((await AnchorCore.verifyAnchorProof(proof)).ok, true);
  const empty = await proofOf(0);
  assert.equal((await AnchorCore.verifyAnchorProof(empty)).ok, true);
});

test('锚点内容、链头或当前 Merkle 根被改动都会失败', async () => {
  for (const mutate of [
    p => { p.anchors[1].root = '0'.repeat(64); },
    p => { p.anchorHead = 'f'.repeat(64); },
    p => { p.merkleRoot = 'e'.repeat(64); },
    p => { p.anchorCount++; }
  ]) {
    const proof = await proofOf(); mutate(proof);
    assert.equal((await AnchorCore.verifyAnchorProof(proof)).ok, false);
  }
});

test('GitHub 最新锚点与服务端一致时判定 current', async () => {
  const proof = await proofOf();
  const result = await AnchorCore.verifyExternalAnchor(proof, attestationOf(proof), 'https://ledger.example');
  assert.equal(result.ok, true);
  assert.equal(result.current, true);
  assert.equal(result.pending, 0);
});

test('服务端继续前进时旧锚点仍有效，但明确报告待锚定事件', async () => {
  const proof = await proofOf(5);
  const result = await AnchorCore.verifyExternalAnchor(proof, attestationOf(proof, 3), 'https://ledger.example');
  assert.equal(result.ok, true);
  assert.equal(result.current, false);
  assert.equal(result.pending, 2);
});

test('锚点被替换、历史回滚或跨账本引用都会失败', async () => {
  const proof = await proofOf();
  const wrong = attestationOf(proof); wrong.anchor.hash = 'f'.repeat(64); wrong.anchorHead = wrong.anchor.hash;
  assert.equal((await AnchorCore.verifyExternalAnchor(proof, wrong, 'https://ledger.example')).ok, false);
  const shortProof = await proofOf(2);
  assert.equal((await AnchorCore.verifyExternalAnchor(shortProof, attestationOf(proof), 'https://ledger.example')).ok, false);
  assert.match(AnchorCore.validateAttestation(attestationOf(proof), 'https://other.example'), /另一个账本/);
});
