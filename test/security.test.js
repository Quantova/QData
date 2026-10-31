// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

'use strict';

const test = require('node:test');
const assert = require('node:assert');
const Q = require('..');

const OPTS = { network: 'testnet', requireAnchor: false, strict: false };

function records() {
  const key = Q.generateKey();
  const register = Q.register({ key, system: 'customer-records', classification: 'confidential' });
  const commit = Q.commit({ key, store: register, recordId: 'export-batch-01', digestAlg: 'sha-256', digest: 'a'.repeat(64), scope: 'the nightly export of the customer table' });
  return { key, register, commit };
}

test('replay as another record type is refused', async () => {
  const { register } = records();
  const forged = JSON.parse(JSON.stringify(register));
  forged.type = 'commit';
  const r = await Q.verify(forged, Object.assign({ type: 'commit' }, OPTS));
  assert.strictEqual(r.status, 'invalid');
});

test('replay onto another store id is refused', async () => {
  const { register } = records();
  const forged = JSON.parse(JSON.stringify(register));
  forged.statement.storeId = 'f'.repeat(32);
  const r = await Q.verify(forged, Object.assign({ type: 'register' }, OPTS));
  assert.strictEqual(r.status, 'invalid');
  assert.ok(r.checks.some((c) => c.name === 'signature' && !c.ok));
});

test('every signed field is bound, a change to any of them breaks the signature', async () => {
  const { commit } = records();
  const flipHex = (h) => (h[0] === '0' ? '1' : '0') + h.slice(1);
  const mutations = [
    (s) => { s.storeId = flipHex(s.storeId); },
    (s) => { s.storeRef = flipHex(s.storeRef); },
    (s) => { s.recordId = 'export-batch-02'; },
    (s) => { s.digestAlg = 'sha3-256'; },
    (s) => { s.digest = 'b'.repeat(64); },
    (s) => { s.scope = 'another scope'; },
    (s) => { s.authorityKeyId = flipHex(s.authorityKeyId); },
    (s) => { s.sealedAt = '2000-01-01T00:00:00.000Z'; },
    (s) => { s.note = 'added'; },
  ];
  for (const mutate of mutations) {
    const forged = JSON.parse(JSON.stringify(commit));
    mutate(forged.statement);
    const r = await Q.verify(forged, Object.assign({ type: 'commit' }, OPTS));
    assert.strictEqual(r.status, 'invalid', JSON.stringify(forged.statement));
  }
});

test('a signature from a key other than the named signer does not verify', async () => {
  const a = records();
  const b = records();
  const forged = JSON.parse(JSON.stringify(a.register));
  forged.signer = b.register.signer;
  const r = await Q.verify(forged, Object.assign({ type: 'register' }, OPTS));
  assert.strictEqual(r.status, 'invalid');
});

test('a non canonical base64 public key or signature is rejected at parse', async () => {
  const { register } = records();
  const forged = JSON.parse(JSON.stringify(register));
  forged.signer.publicKey = forged.signer.publicKey.slice(0, -2) + '==';
  const r = await Q.verify(forged, Object.assign({ type: 'register' }, OPTS));
  assert.strictEqual(r.status, 'invalid');
  const bad = JSON.parse(JSON.stringify(register));
  bad.signature = bad.signature.slice(0, -4) + 'AAAA';
  const r2 = await Q.verify(bad, Object.assign({ type: 'register' }, OPTS));
  assert.strictEqual(r2.status, 'invalid');
});

test('an envelope with an unexpected field is refused', async () => {
  const { register } = records();
  const forged = JSON.parse(JSON.stringify(register));
  forged.extra = 1;
  const r = await Q.verify(forged, Object.assign({ type: 'register' }, OPTS));
  assert.strictEqual(r.status, 'invalid');
  const withStatementExtra = JSON.parse(JSON.stringify(register));
  withStatementExtra.statement.extra = 1;
  const r2 = await Q.verify(withStatementExtra, Object.assign({ type: 'register' }, OPTS));
  assert.strictEqual(r2.status, 'invalid');
});

test('a statement carrying a prototype polluting key is refused', async () => {
  const { register } = records();
  const forged = JSON.parse(JSON.stringify(register));
  forged.statement = JSON.parse('{"__proto__":{"polluted":true},"storeId":"' + register.statement.storeId + '"}');
  const r = await Q.verify(forged, Object.assign({ type: 'register' }, OPTS));
  assert.strictEqual(r.status, 'invalid');
  assert.strictEqual({}.polluted, undefined);
});

test('a signing key is never serialised by the SDK', () => {
  const key = Q.generateKey();
  assert.strictEqual(JSON.stringify({ key }), '{"key":"SecretKey [hidden]"}');
  assert.strictEqual(String(key), 'SecretKey [hidden]');
  assert.strictEqual(require('util').inspect(key), 'SecretKey [hidden]');
});

test('an anchor recorded under another record kind is not accepted', async () => {
  const { register } = records();
  const anchored = JSON.parse(JSON.stringify(register));
  anchored.anchor = { kind: '1301', chain: { id: 'x', genesis: 'y' }, anchor: { time: 1, height: 1, tx: 't' }, proof: { index: 0 } };
  const r = await Q.verify(anchored, Object.assign({ type: 'register', requireAnchor: true }, { network: 'testnet', strict: false }));
  assert.strictEqual(r.status, 'invalid');
  assert.ok(r.checks.some((c) => /anchor/.test(c.name) && !c.ok));
});
