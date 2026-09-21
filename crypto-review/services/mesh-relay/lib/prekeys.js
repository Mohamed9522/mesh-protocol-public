'use strict';

/**
 * Prekey bundles for forward secrecy (see docs/FORWARD-SECRECY-DESIGN.md).
 * Everything the relay stores here is public: X25519 public keys and a signature.
 *
 * The signed prekey is signed with the owner's Stellar (Ed25519) key over
 *   "MESH-SPK-v1" / owner address / prekey id / prekey public key (base64)
 * joined with "\n". The fixed prefix keeps it from being mistaken for a request
 * signature or a Stellar transaction signature; the address binds it to one owner.
 * The relay checks the signature so junk is refused, but clients must check it too:
 * a hostile relay is exactly what the signature protects against.
 */

const crypto = require('crypto');
const { decodeStellarPublicKey } = require('./strkey');

const SPKI_ED25519_PREFIX = Buffer.from('302a300506032b6570032100', 'hex');
const X25519_B64_RE = /^[A-Za-z0-9+/]{43}=$/; // base64 of 32 bytes
const SIG_B64_RE = /^[A-Za-z0-9+/]{86}==$/;   // base64 of 64 bytes
const MAX_ONE_TIME_PREKEYS = 100;              // pool cap per user
const MAX_UPLOAD_BATCH = 100;
const MAX_PREKEY_ID = 0x7fffffff;

const isPrekeyId = (n) => Number.isInteger(n) && n >= 1 && n <= MAX_PREKEY_ID;
const isX25519B64 = (v) => typeof v === 'string' && X25519_B64_RE.test(v);

function signedPrekeyMessage(address, id, pubB64) {
  return Buffer.from(['MESH-SPK-v1', address, String(id), pubB64].join('\n'));
}

function verifySignedPrekey(address, { id, pub, sig }) {
  const raw = decodeStellarPublicKey(address);
  if (!raw || !isPrekeyId(id) || !isX25519B64(pub) || typeof sig !== 'string' || !SIG_B64_RE.test(sig)) return false;
  try {
    const key = crypto.createPublicKey({ key: Buffer.concat([SPKI_ED25519_PREFIX, raw]), format: 'der', type: 'spki' });
    return crypto.verify(null, signedPrekeyMessage(address, id, pub), key, Buffer.from(sig, 'base64'));
  } catch {
    return false;
  }
}

module.exports = {
  verifySignedPrekey, signedPrekeyMessage, isPrekeyId, isX25519B64,
  MAX_ONE_TIME_PREKEYS, MAX_UPLOAD_BATCH,
};
