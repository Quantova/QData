// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

export type Classification = 'public' | 'internal' | 'confidential' | 'restricted';
export type DigestAlgorithm = 'sha-256' | 'sha-384' | 'sha-512' | 'sha3-256';
export type AccessAction = 'read' | 'export' | 'modify' | 'share' | 'delete';
export type EraseMethod = 'crypto-erase' | 'overwrite' | 'destroyed' | 'anonymized';
export type RecordType = 'register' | 'commit' | 'access' | 'retain' | 'erase';

export interface KeyDescription {
  format: 'qdata-key/1';
  algorithm: 'ML-DSA-65';
  id: string;
  publicKey: string;
}

export type Party = string | Uint8Array | KeyDescription;

export interface Signer {
  id: string;
  publicKey: string;
}

export interface Envelope<T = Record<string, unknown>> {
  format: 'qdata/1';
  type: RecordType;
  algorithm: 'ML-DSA-65';
  signer: Signer;
  statement: T;
  signature: string;
  anchor?: unknown;
}

export interface RegisterOptions {
  key: Uint8Array;
  system: string;
  classification: Classification;
  authorityLabel?: string;
  registeredAt?: string;
  note?: string;
}

export interface CommitOptions {
  key: Uint8Array;
  store: Envelope;
  recordId: string;
  digestAlg: DigestAlgorithm;
  digest: string;
  scope: string;
  authorityLabel?: string;
  sealedAt?: string;
  note?: string;
}

export interface AccessOptions {
  key: Uint8Array;
  record: Envelope;
  actor: string;
  action: AccessAction;
  authorityLabel?: string;
  accessedAt?: string;
  note?: string;
}

export interface RetainOptions {
  key: Uint8Array;
  record: Envelope;
  policy: string;
  until: string;
  authorityLabel?: string;
  setAt?: string;
  note?: string;
}

export interface EraseOptions {
  key: Uint8Array;
  record: Envelope;
  method: EraseMethod;
  authorityLabel?: string;
  erasedAt?: string;
  note?: string;
}

export interface AnchorOptions {
  seed?: Uint8Array;
  index?: number;
  network?: string;
  rpc?: string;
  clients?: unknown[];
  trustSingleEndpoint?: boolean;
  trustCustomEndpoints?: boolean;
  allowLoopback?: boolean;
  maxFee?: string | number | bigint;
  meter?: string | number | bigint;
  timeoutMs?: number;
  onPending?: (pending: unknown) => void;
  signal?: AbortSignal;
}

export interface VerifyOptions {
  type?: RecordType;
  prior?: Envelope;
  storeId?: string;
  signerKeyId?: string;
  signerPublicKey?: string | Uint8Array;
  network: string;
  strict?: boolean;
  requireAnchor?: boolean;
  maxAnchorDelay?: number;
  at?: string;
  deadlineMs?: number;
  rpc?: string;
  clients?: unknown[];
  trustSingleEndpoint?: boolean;
  trustCustomEndpoints?: boolean;
  allowLoopback?: boolean;
}

export interface Check {
  name: string;
  ok: boolean;
  detail: string;
  transport: boolean;
  indeterminate: boolean;
  unproven: boolean;
}

export interface VerifyResult {
  valid: boolean;
  status: 'valid' | 'unproven' | 'indeterminate' | 'invalid';
  type: RecordType | null;
  storeId?: string;
  signerId?: string;
  statement?: Record<string, unknown>;
  anchoredAt?: string | null;
  endpoints: string[];
  officialEndpoints: boolean | null;
  checks: Check[];
}

export function generateKey(): Uint8Array;
export function publicKey(key: Uint8Array): Uint8Array;
export function keyId(key: Uint8Array): string;
export function describeKey(key: Uint8Array): KeyDescription;
export function subjectRef(secret: Uint8Array, reference: string): string;
export function register(options: RegisterOptions): Envelope;
export function commit(options: CommitOptions): Envelope;
export function access(options: AccessOptions): Envelope;
export function retain(options: RetainOptions): Envelope;
export function erase(options: EraseOptions): Envelope;
export function anchor(envelopes: Envelope | Envelope[], options: AnchorOptions): Promise<Envelope[]>;
export function complete(envelopes: Envelope | Envelope[], pending: unknown, options?: AnchorOptions): Promise<Envelope[]>;
export function verify(envelope: Envelope, options: VerifyOptions): Promise<VerifyResult>;
export function anchorDigest(envelope: Envelope): string;
export function recordRef(envelope: Envelope): string;

export const FORMAT: 'qdata/1';
export const ALGORITHM: 'ML-DSA-65';
export const KIND: 1604;
export const TYPES: readonly RecordType[];
export const CLASSES: readonly Classification[];
export const DIGESTS: readonly DigestAlgorithm[];
export const ACCESS: readonly AccessAction[];
export const ERASE: readonly EraseMethod[];
export const PUBLIC_KEY_BYTES: 1952;
export const SIGNATURE_BYTES: 3309;
