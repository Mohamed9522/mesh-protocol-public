/**
 * MESH Protocol - src/crypto/legacy.js
 *
 * The original (v1) message format: nacl.box between the two long-term encryption keys, sent as
 * "nonce:ciphertext" in base64. No forward secrecy. Kept so messages from and to contacts whose app
 * is older than forward secrecy still work; messenger.js decides when it may be used.
 * Pure functions, no React Native imports.
 */

import nacl from 'tweetnacl';
import naclUtil from 'tweetnacl-util'; // default import works both in Metro and in Node's ESM loader (used by the tests)

const { encodeBase64, decodeBase64 } = naclUtil;

export function encryptV1(plaintext, recipientPublicB64, senderSecretB64, rng = nacl.randomBytes) {
  const nonce = rng(nacl.box.nonceLength);
  const boxed = nacl.box(new TextEncoder().encode(plaintext), nonce, decodeBase64(recipientPublicB64), decodeBase64(senderSecretB64));
  if (!boxed) throw new Error('nacl.box returned null');
  return encodeBase64(nonce) + ':' + encodeBase64(boxed);
}

/** Plaintext string, or null if it does not verify. */
export function decryptV1(payload, senderPublicB64, mySecretB64) {
  const [noncePart, encPart] = String(payload).split(':');
  if (!noncePart || !encPart) return null;
  let opened;
  try {
    opened = nacl.box.open(decodeBase64(encPart), decodeBase64(noncePart), decodeBase64(senderPublicB64), decodeBase64(mySecretB64));
  } catch {
    return null;
  }
  return opened ? new TextDecoder().decode(opened) : null;
}
