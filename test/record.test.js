// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

'use strict';

const test = require('node:test');
const assert = require('node:assert');
const Q = require('..');

function freshKey() {
  return Q.generateKey();
}

function registerStore(key) {
  return Q.register({ key, system: 'customer-records', classification: 'confidential', authorityLabel: 'Data Protection Office' });
}

function commitOf(key, store) {
  return Q.commit({ key, store, recordId: 'export-batch-01', digestAlg: 'sha-256', digest: 'a'.repeat(64), scope: 'the nightly export of the customer table' });
}

test('a registered store is a well formed signed record of the authority', () => {
  const authority = freshKey();
  const env = registerStore(authority);
  assert.strictEqual(env.format, 'qdata/1');
  assert.strictEqual(env.type, 'register');
  assert.strictEqual(env.algorithm, 'ML-DSA-65');
  assert.strictEqual(env.signer.id, Q.keyId(authority));
  assert.strictEqual(env.statement.authorityKeyId, Q.keyId(authority));
  assert.match(env.statement.storeId, /^[0-9a-f]{32}$/);
  assert.strictEqual(Buffer.from(env.signer.publicKey, 'base64').length, Q.PUBLIC_KEY_BYTES);
  assert.strictEqual(Buffer.from(env.signature, 'base64').length, Q.SIGNATURE_BYTES);
});

test('the commit, access, retain and erase records chain to the same store', () => {
  const authority = freshKey();
  const register = registerStore(authority);
  const commit = commitOf(authority, register);
  const access = Q.access({ key: authority, record: commit, actor: 'analyst-07', action: 'export' });
  const retain = Q.retain({ key: authority, record: access, policy: 'retain-7y', until: '2033-01-01T00:00:00.000Z' });
  const erase = Q.erase({ key: authority, record: retain, method: 'crypto-erase' });
  assert.strictEqual(commit.statement.storeId, register.statement.storeId);
  assert.strictEqual(commit.statement.storeRef, Q.recordRef(register));
  assert.strictEqual(access.statement.priorRef, Q.recordRef(commit));
  assert.strictEqual(retain.statement.priorRef, Q.recordRef(access));
  assert.strictEqual(erase.statement.priorRef, Q.recordRef(retain));
});

test('invalid inputs are refused before anything is signed', () => {
  const key = freshKey();
  const register = registerStore(key);
  const base = { key, store: register, recordId: 'r1', digestAlg: 'sha-256', digest: 'a'.repeat(64), scope: 'x' };
  assert.throws(() => Q.register({ key, system: 's', classification: 'secret' }), /classification must be one of/);
  assert.throws(() => Q.commit(Object.assign({}, base, { digestAlg: 'md5' })), /digestAlg must be one of/);
  assert.throws(() => Q.commit(Object.assign({}, base, { digest: 'abc' })), /digest must be 64, 96 or 128/);
  assert.throws(() => Q.commit(Object.assign({}, base, { unknownField: 1 })), /is not an option of commit/);
  assert.throws(() => Q.access({ key, record: register, actor: 'a', action: 'print' }), /action must be one of/);
  assert.throws(() => Q.erase({ key, record: register, method: 'shred' }), /method must be one of/);
});

test('a signing key must be a well formed 32 byte seed', () => {
  assert.throws(() => Q.register({ key: new Uint8Array(16), system: 's', classification: 'internal' }), /32 byte Uint8Array seed/);
  assert.throws(() => Q.register({ key: new Uint8Array(32), system: 's', classification: 'internal' }), /too few different byte values/);
});

test('a well formed record verifies and a type mismatch is invalid', async () => {
  const authority = freshKey();
  const register = registerStore(authority);
  const ok = await Q.verify(register, { type: 'register', network: 'testnet', requireAnchor: false, strict: false });
  assert.strictEqual(ok.status, 'valid');
  assert.strictEqual(ok.type, 'register');
  assert.strictEqual(ok.storeId, register.statement.storeId);
  const wrongType = await Q.verify(register, { type: 'commit', network: 'testnet', requireAnchor: false, strict: false });
  assert.strictEqual(wrongType.status, 'invalid');
  const wrongSigner = await Q.verify(register, { type: 'register', network: 'testnet', requireAnchor: false, strict: false, signerKeyId: Q.keyId(freshKey()) });
  assert.strictEqual(wrongSigner.status, 'invalid');
});

test('a tampered statement no longer verifies', async () => {
  const authority = freshKey();
  const register = registerStore(authority);
  const commit = commitOf(authority, register);
  const forged = JSON.parse(JSON.stringify(commit));
  forged.statement.digest = 'b'.repeat(64);
  const r = await Q.verify(forged, { type: 'commit', network: 'testnet', requireAnchor: false, strict: false });
  assert.strictEqual(r.status, 'invalid');
  assert.ok(r.checks.some((c) => c.name === 'signature' && !c.ok));
});

test('the prior link binds a commit to the register it refers to', async () => {
  const authority = freshKey();
  const register = registerStore(authority);
  const commit = commitOf(authority, register);
  const good = await Q.verify(commit, { type: 'commit', network: 'testnet', requireAnchor: false, strict: false, prior: register });
  assert.ok(good.checks.some((c) => c.name === 'prior' && c.ok));
  const otherRegister = registerStore(authority);
  const bad = await Q.verify(commit, { type: 'commit', network: 'testnet', requireAnchor: false, strict: false, prior: otherRegister });
  assert.strictEqual(bad.status, 'invalid');
  assert.ok(bad.checks.some((c) => c.name === 'prior' && !c.ok));
});

test('subjectRef is deterministic for the same secret and reference and differs otherwise', () => {
  const secret = new Uint8Array(32);
  globalThis.crypto.getRandomValues(secret);
  const a = Q.subjectRef(secret, 'row customer 42');
  const b = Q.subjectRef(secret, 'row customer 42');
  const c = Q.subjectRef(secret, 'row customer 43');
  assert.strictEqual(a, b);
  assert.notStrictEqual(a, c);
  assert.match(a, /^[0-9a-f]{64}$/);
});

test('the kind and constants are the ones pinned for the data line', () => {
  assert.strictEqual(Q.KIND, 1604);
  assert.strictEqual(Q.FORMAT, 'qdata/1');
  assert.deepStrictEqual([...Q.TYPES], ['register', 'commit', 'access', 'retain', 'erase']);
  assert.deepStrictEqual([...Q.CLASSES], ['public', 'internal', 'confidential', 'restricted']);
  assert.deepStrictEqual([...Q.DIGESTS], ['sha-256', 'sha-384', 'sha-512', 'sha3-256']);
  assert.deepStrictEqual([...Q.ACCESS], ['read', 'export', 'modify', 'share', 'delete']);
  assert.deepStrictEqual([...Q.ERASE], ['crypto-erase', 'overwrite', 'destroyed', 'anonymized']);
});
