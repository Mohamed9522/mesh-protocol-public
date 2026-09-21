/**
 * MESH Protocol - src/crypto/prekeys.js
 *
 * Our own prekeys: the private halves stay on the phone (sealed by vault.js), the public halves go to the
 * relay (POST /prekeys). Also checks the signature on someone else's bundle: the relay verifies uploads
 * too, but a hostile relay is exactly what this check is for.
 *
 * Signing and verifying the wallet's Ed25519 signature is passed in by the caller (Stellar Keypair in the
 * app, node:crypto in tests), which keeps this file free of React Native and Stellar imports.
 *
 * The signed message must match services/mesh-relay/lib/prekeys.js exactly:
 *   "MESH-SPK-v1" \n owner address \n prekey id \n prekey public key (base64)
 */

import nacl from 'tweetnacl';
import naclUtil from 'tweetnacl-util'; // default import works both in Metro and in Node's ESM loader (used by the tests)
import { newKeyPair } from './ratchet.js';

const { encodeBase64, decodeBase64 } = naclUtil;

export const ONE_TIME_POOL_TARGET = 50;
export const ONE_TIME_POOL_LOW = 20;         // top up when fewer than this remain
export const MAX_LOCAL_ONE_TIME = 200;       // private halves kept; the relay hands out the lowest ids first, so the oldest are dropped
export const SIGNED_PREKEY_MAX_AGE_MS = 7 * 24 * 3600 * 1000;
const MAX_ID = 0x7fffffff;

export const signedPrekeyMessage = (address, id, pubB64) =>
  new TextEncoder().encode(['MESH-SPK-v1', address, String(id), pubB64].join('\n'));

/**
 * A fresh, empty store. Secrets are raw bytes here; seal it with vault.js before persisting (see toJSON/fromJSON).
 * Pass `rng` to start the ids at random numbers instead of 1: after a wallet is restored on a new phone, ids must not
 * collide with the old phone's, or a first message aimed at an old prekey would look valid and then fail to open.
 */
export function newPrekeyStore({ rng } = {}) {
  const start = () => (rng ? (new DataView(rng(4).buffer).getUint32(0) % 0x40000000) + 1 : 1);
  return { nextSpkId: start(), nextOtkId: start(), spk: null, prevSpk: null, otks: [], pendingReplace: false };
}

/** Makes a new signed prekey and keeps the previous one, so first messages already in flight still open. */
export function rotateSignedPrekey(store, { address, sign, rng = nacl.randomBytes, now = Date.now() }) {
  const kp = newKeyPair(rng);
  const id = store.nextSpkId;
  if (id > MAX_ID) throw new Error('prekey id space exhausted');
  const pub = encodeBase64(kp.public);
  const sig = encodeBase64(sign(signedPrekeyMessage(address, id, pub)));
  store.prevSpk = store.spk;
  store.spk = { id, secret: kp.secret, public: kp.public, createdAt: now };
  store.nextSpkId = id + 1;
  return { id, pub, sig }; // what the relay gets
}

export const signedPrekeyIsDue = (store, now = Date.now()) => !store.spk || now - store.spk.createdAt >= SIGNED_PREKEY_MAX_AGE_MS;

/** Adds `count` one-time prekeys. Ids are never reused. Returns the public halves to upload. */
export function makeOneTimePrekeys(store, count, rng = nacl.randomBytes) {
  const batch = [];
  for (let i = 0; i < count; i++) {
    const kp = newKeyPair(rng);
    const id = store.nextOtkId++;
    if (id > MAX_ID) throw new Error('prekey id space exhausted');
    store.otks.push({ id, secret: kp.secret, public: kp.public });
    batch.push({ id, pub: encodeBase64(kp.public) });
  }
  if (store.otks.length > MAX_LOCAL_ONE_TIME) store.otks.splice(0, store.otks.length - MAX_LOCAL_ONE_TIME);
  return batch;
}

/** The signed prekey a first message names: the current one, or the previous one during rotation. */
export function findSignedPrekey(store, id) {
  if (store.spk && store.spk.id === id) return store.spk;
  if (store.prevSpk && store.prevSpk.id === id) return store.prevSpk;
  return null;
}

/** Removes and returns a one-time prekey (each one may be used once; deleting it is what gives forward secrecy for the first message). */
export function takeOneTimePrekey(store, id) {
  const at = store.otks.findIndex((k) => k.id === id);
  if (at === -1) return null;
  return store.otks.splice(at, 1)[0];
}

/** Checks a bundle received from the relay against the contact's wallet address. */
export function verifySignedPrekey(address, spk, verify) {
  try {
    if (!spk || !Number.isInteger(spk.id) || spk.id < 1 || spk.id > MAX_ID) return false;
    if (decodeBase64(spk.pub).length !== 32) return false;
    return !!verify(address, signedPrekeyMessage(address, spk.id, spk.pub), decodeBase64(spk.sig));
  } catch {
    return false;
  }
}

// ── persistence (bytes <-> JSON), used with vault.js ────────────────────────
const enc = (k) => (k ? { id: k.id, secret: encodeBase64(k.secret), public: encodeBase64(k.public), createdAt: k.createdAt } : null);
const dec = (k) => (k ? { id: k.id, secret: decodeBase64(k.secret), public: decodeBase64(k.public), createdAt: k.createdAt } : null);

export function prekeyStoreToJSON(store) {
  return {
    nextSpkId: store.nextSpkId, nextOtkId: store.nextOtkId,
    spk: enc(store.spk), prevSpk: enc(store.prevSpk), otks: store.otks.map(enc),
    pendingReplace: !!store.pendingReplace,
  };
}

export function prekeyStoreFromJSON(o) {
  return {
    nextSpkId: o.nextSpkId, nextOtkId: o.nextOtkId,
    spk: dec(o.spk), prevSpk: dec(o.prevSpk), otks: o.otks.map(dec),
    pendingReplace: !!o.pendingReplace,
  };
}
