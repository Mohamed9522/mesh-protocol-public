/**
 * MESH Protocol - src/crypto/ratchet.js
 *
 * Forward-secret messaging: X3DH key agreement + Double Ratchet, following the Signal
 * specifications (signal.org/docs/specifications/x3dh and /doubleratchet), built only from
 * primitives already in the app: X25519 and HKDF/HMAC-SHA256 from @noble, and XSalsa20-Poly1305
 * from tweetnacl. See docs/FORWARD-SECRECY-DESIGN.md.
 *
 * NOT wire-compatible with Signal (own labels and own message layout); it borrows the design, not the bytes.
 * Pure functions, no React Native imports, so the same code is unit-tested in Node.
 *
 * Session state is immutable from the caller's view: encrypt() and decrypt() return a NEW state and
 * never modify the one passed in. A message that fails authentication therefore cannot move the
 * ratchet, so a forged or garbled message cannot break a conversation.
 *
 * Wire message (binary, the caller base64-encodes it):
 *   [1] version = 2   [1] flags (bit0 = carries the X3DH init block)
 *   [32] sender ratchet public key   [4] previous chain length (pn)   [4] message number (n)
 *   if init: [32] initiator identity key  [32] initiator ephemeral key  [4] signed prekey id  [4] one-time prekey id (0 = none)
 *   [32] tag = HMAC-SHA256(macKey, AD || header || ciphertext)   [..] ciphertext = secretbox(plaintext)
 * The header is authenticated but not encrypted; the relay already sees who talks to whom and when.
 */

import { x25519 } from '@noble/curves/ed25519.js';
import { hkdf } from '@noble/hashes/hkdf.js';
import { hmac } from '@noble/hashes/hmac.js';
import { sha256 } from '@noble/hashes/sha2.js';
import nacl from 'tweetnacl';
import naclUtil from 'tweetnacl-util'; // default import works both in Metro and in Node's ESM loader (used by the tests)

const { encodeBase64, decodeBase64 } = naclUtil;

export const WIRE_VERSION = 2;          // 1 is the legacy static-key nacl.box format
export const MAX_SKIP = 1000;           // most messages one incoming message may skip over
export const MAX_STORED_SKIPPED = 1000; // skipped-key cache size; the oldest are dropped first

const utf8 = (s) => new TextEncoder().encode(s);
const ZERO32 = new Uint8Array(32);
const HEADER_BASE = 42;   // version + flags + dh + pn + n
const INIT_LEN = 72;      // ik + ek + spkId + opkId
const TAG_LEN = 32;

function concat(...parts) {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let at = 0;
  for (const p of parts) { out.set(p, at); at += p.length; }
  return out;
}
const u32 = (n) => { const b = new Uint8Array(4); new DataView(b.buffer).setUint32(0, n, false); return b; };
const readU32 = (b, at) => new DataView(b.buffer, b.byteOffset + at, 4).getUint32(0, false);
const same = (a, b) => a.length === b.length && nacl.verify(a, b);
const fail = (code, msg) => Object.assign(new Error(msg || code), { code });

const dh = (secret, pub) => x25519.getSharedSecret(secret, pub); // throws on invalid or low-order points
export function newKeyPair(rng = nacl.randomBytes) {
  const secret = rng(32);
  return { secret, public: x25519.getPublicKey(secret) };
}

// ── key derivation ──────────────────────────────────────────────────────────
function kdfRK(rk, dhOut) {
  const out = hkdf(sha256, dhOut, rk, utf8('MESH-RK-v1'), 64);
  return [out.slice(0, 32), out.slice(32)];
}
function kdfCK(ck) {
  return [hmac(sha256, ck, Uint8Array.of(2)), hmac(sha256, ck, Uint8Array.of(1))]; // [next chain key, message key]
}
function expandMK(mk) {
  const out = hkdf(sha256, mk, ZERO32, utf8('MESH-MK-v1'), 32 + 24 + 32);
  return { encKey: out.slice(0, 32), nonce: out.slice(32, 56), macKey: out.slice(56) };
}

// ── X3DH ────────────────────────────────────────────────────────────────────
function x3dhSecret(dhs) {
  return hkdf(sha256, concat(new Uint8Array(32).fill(0xff), ...dhs), ZERO32, utf8('MESH-X3DH-v1'), 32);
}
const associatedData = (initiatorIk, responderIk) => concat(utf8('MESH-AD-v1'), initiatorIk, responderIk);

/**
 * Start a session with someone else's prekey bundle (fetched from the relay).
 * The caller must already have verified the signed prekey's signature and that
 * theirIdentityPub matches the key it pinned for this contact.
 * @param myIdentity   { secret, public } our long-term X25519 key (the app's naclSecret/naclPublic)
 * @param bundle       { theirIdentityPub, spk: {id, pub}, opk: {id, pub} | null }
 */
export function initiatorSession({ myIdentity, bundle, rng = nacl.randomBytes }) {
  const ek = newKeyPair(rng);
  const parts = [
    dh(myIdentity.secret, bundle.spk.pub),
    dh(ek.secret, bundle.theirIdentityPub),
    dh(ek.secret, bundle.spk.pub),
  ];
  if (bundle.opk) parts.push(dh(ek.secret, bundle.opk.pub));
  const sk = x3dhSecret(parts);

  const dhs = newKeyPair(rng);
  const [rk, cks] = kdfRK(sk, dh(dhs.secret, bundle.spk.pub));
  return {
    v: WIRE_VERSION,
    ad: associatedData(myIdentity.public, bundle.theirIdentityPub),
    peerIdentity: bundle.theirIdentityPub,
    dhs, dhr: bundle.spk.pub, rk, cks, ckr: null, ns: 0, nr: 0, pn: 0,
    skipped: new Map(),
    // sent with every message until the peer answers, so the first one may arrive in any order
    init: { ik: myIdentity.public, ek: ek.public, spkId: bundle.spk.id, opkId: bundle.opk ? bundle.opk.id : 0 },
    peerEk: null,
  };
}

/**
 * Accept a session from the init block of a first message.
 * @param myIdentity  our long-term { secret, public }
 * @param spk         { secret, public } the signed prekey the init names (id from init.spkId)
 * @param opk         { secret } the one-time prekey it names, or null when init.opkId === 0
 * @param init        parsed init block ({ ik, ek, spkId, opkId })
 * The caller must delete the one-time prekey secret afterwards and check init.ik against the pinned key.
 */
export function responderSession({ myIdentity, spk, opk, init }) {
  const parts = [
    dh(spk.secret, init.ik),
    dh(myIdentity.secret, init.ek),
    dh(spk.secret, init.ek),
  ];
  if (init.opkId !== 0) {
    if (!opk) throw fail('missing_opk', 'message names a one-time prekey we no longer hold');
    parts.push(dh(opk.secret, init.ek));
  }
  const sk = x3dhSecret(parts);
  return {
    v: WIRE_VERSION,
    ad: associatedData(init.ik, myIdentity.public),
    peerIdentity: init.ik,
    dhs: { secret: spk.secret, public: spk.public }, dhr: null, rk: sk, cks: null, ckr: null, ns: 0, nr: 0, pn: 0,
    skipped: new Map(),
    init: null,
    peerEk: init.ek,
  };
}

/** True if this init block belongs to the session we already built from it (a repeat of the first message). */
export function initMatchesSession(state, init) {
  return !!state.peerEk && same(state.peerEk, init.ek) && same(state.peerIdentity, init.ik);
}

// ── Double Ratchet ──────────────────────────────────────────────────────────
function cloneState(s) {
  return { ...s, skipped: new Map(s.skipped) }; // byte arrays are never mutated in place, so sharing them is safe
}
const skippedKey = (dhPub, n) => `${encodeBase64(dhPub)}:${n}`;

function skipMessageKeys(s, until) {
  if (until - s.nr > MAX_SKIP) throw fail('too_many_skipped', 'message number is implausibly far ahead');
  if (!s.ckr) return;
  while (s.nr < until) {
    const [ck, mk] = kdfCK(s.ckr);
    s.ckr = ck;
    s.skipped.set(skippedKey(s.dhr, s.nr), mk);
    s.nr += 1;
    if (s.skipped.size > MAX_STORED_SKIPPED) s.skipped.delete(s.skipped.keys().next().value);
  }
}

function dhRatchet(s, theirDh, rng) {
  s.pn = s.ns;
  s.ns = 0;
  s.nr = 0;
  s.dhr = theirDh;
  [s.rk, s.ckr] = kdfRK(s.rk, dh(s.dhs.secret, s.dhr));
  s.dhs = newKeyPair(rng);
  [s.rk, s.cks] = kdfRK(s.rk, dh(s.dhs.secret, s.dhr));
}

function buildHeader(s) {
  const init = s.init;
  return concat(
    Uint8Array.of(WIRE_VERSION, init ? 1 : 0),
    s.dhs.public, u32(s.pn), u32(s.ns),
    ...(init ? [init.ik, init.ek, u32(init.spkId), u32(init.opkId)] : []),
  );
}

/** @returns {{ state, wire: Uint8Array }} */
export function encrypt(state, plaintext) {
  if (!state.cks) throw fail('cannot_send_yet', 'a responder must receive a message before it can send');
  const s = cloneState(state);
  const [ck, mk] = kdfCK(s.cks);
  const header = buildHeader(s);
  s.cks = ck;
  s.ns += 1;
  const { encKey, nonce, macKey } = expandMK(mk);
  const ct = nacl.secretbox(plaintext, nonce, encKey);
  const tag = hmac(sha256, macKey, concat(s.ad, header, ct));
  return { state: s, wire: concat(header, tag, ct) };
}

/** Reads the header without decrypting: lets the caller find the prekeys an init block names. */
export function parseWire(wire) {
  if (!(wire instanceof Uint8Array) || wire.length < HEADER_BASE + TAG_LEN) throw fail('malformed', 'message too short');
  if (wire[0] !== WIRE_VERSION) throw fail('bad_version', `unsupported message version ${wire[0]}`);
  const hasInit = (wire[1] & 1) === 1;
  if (wire[1] & ~1) throw fail('malformed', 'unknown flags');
  const headerLen = HEADER_BASE + (hasInit ? INIT_LEN : 0);
  if (wire.length < headerLen + TAG_LEN) throw fail('malformed', 'message too short');
  const init = hasInit ? {
    ik: wire.slice(HEADER_BASE, HEADER_BASE + 32),
    ek: wire.slice(HEADER_BASE + 32, HEADER_BASE + 64),
    spkId: readU32(wire, HEADER_BASE + 64),
    opkId: readU32(wire, HEADER_BASE + 68),
  } : null;
  return {
    dh: wire.slice(2, 34), pn: readU32(wire, 34), n: readU32(wire, 38), init,
    header: wire.slice(0, headerLen),
    tag: wire.slice(headerLen, headerLen + TAG_LEN),
    ct: wire.slice(headerLen + TAG_LEN),
  };
}

function open(ad, msg, mk) {
  const { encKey, nonce, macKey } = expandMK(mk);
  if (!same(hmac(sha256, macKey, concat(ad, msg.header, msg.ct)), msg.tag)) throw fail('bad_tag', 'message failed authentication');
  const pt = nacl.secretbox.open(msg.ct, nonce, encKey);
  if (!pt) throw fail('bad_tag', 'message failed authentication');
  return pt;
}

/**
 * @returns {{ state, plaintext: Uint8Array }}
 * @throws with .code: malformed | bad_version | bad_tag | replay | too_many_skipped
 *   The state passed in is untouched on every failure.
 */
export function decrypt(state, wire, rng = nacl.randomBytes) {
  const msg = parseWire(wire);
  const s = cloneState(state);

  const cached = s.skipped.get(skippedKey(msg.dh, msg.n));
  if (cached) {
    const plaintext = open(s.ad, msg, cached);
    s.skipped.delete(skippedKey(msg.dh, msg.n));
    return { state: s, plaintext };
  }

  if (!s.dhr || !same(s.dhr, msg.dh)) {
    skipMessageKeys(s, msg.pn);   // keys still owed from the previous receiving chain
    dhRatchet(s, msg.dh, rng);
  } else if (msg.n < s.nr) {
    throw fail('replay', 'message already received, or too old');
  }
  skipMessageKeys(s, msg.n);
  const [ck, mk] = kdfCK(s.ckr);
  s.ckr = ck;
  s.nr += 1;
  const plaintext = open(s.ad, msg, mk); // throws before the caller ever sees the modified copy
  s.init = null;                         // the peer has answered: stop attaching the init block
  return { state: s, plaintext };
}

// ── persistence helpers (bytes <-> JSON), used with vault.js ────────────────
const b64 = (b) => (b ? encodeBase64(b) : null);
const unb64 = (s) => (s ? decodeBase64(s) : null);
const pair = (p) => ({ secret: b64(p.secret), public: b64(p.public) });
const unpair = (p) => ({ secret: unb64(p.secret), public: unb64(p.public) });

export function serializeState(s) {
  return {
    v: s.v, ad: b64(s.ad), peerIdentity: b64(s.peerIdentity), dhs: pair(s.dhs), dhr: b64(s.dhr),
    rk: b64(s.rk), cks: b64(s.cks), ckr: b64(s.ckr), ns: s.ns, nr: s.nr, pn: s.pn,
    skipped: [...s.skipped].map(([k, mk]) => [k, b64(mk)]),
    init: s.init ? { ik: b64(s.init.ik), ek: b64(s.init.ek), spkId: s.init.spkId, opkId: s.init.opkId } : null,
    peerEk: b64(s.peerEk),
  };
}

export function deserializeState(o) {
  if (!o || o.v !== WIRE_VERSION) throw fail('bad_state', 'unknown session state version');
  return {
    v: o.v, ad: unb64(o.ad), peerIdentity: unb64(o.peerIdentity), dhs: unpair(o.dhs), dhr: unb64(o.dhr),
    rk: unb64(o.rk), cks: unb64(o.cks), ckr: unb64(o.ckr), ns: o.ns, nr: o.nr, pn: o.pn,
    skipped: new Map(o.skipped.map(([k, mk]) => [k, unb64(mk)])),
    init: o.init ? { ik: unb64(o.init.ik), ek: unb64(o.init.ek), spkId: o.init.spkId, opkId: o.init.opkId } : null,
    peerEk: unb64(o.peerEk),
  };
}
