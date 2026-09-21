/**
 * MESH Protocol - src/crypto/vault.js
 *
 * Encrypts secret state (ratchet sessions, prekey secrets) before it is written to the local database,
 * so forward secrecy does not depend on the database file being unreadable.
 *
 * The 32-byte vault key is random, created once, and kept in expo-secure-store (Android Keystore backed),
 * separate from the database. Each record is sealed under a sub-key derived from the vault key and a label
 * (for example "session:<contact address>"), so a sealed record copied to another contact's row will not
 * open. The label is the only thing that binds a record to its place; the caller must always pass the same one.
 *
 * Limits, stated plainly: this protects the database file (backups, file extraction, a copied app folder).
 * It does not protect against malware running as the app, or a rooted phone where the Keystore is exposed.
 * It also cannot stop an attacker with the file from swapping in an OLDER sealed copy of the same record.
 *
 * Pure functions, no React Native imports, so the same code is unit-tested in Node.
 */

import { hkdf } from '@noble/hashes/hkdf.js';
import { sha256 } from '@noble/hashes/sha2.js';
import nacl from 'tweetnacl';
import naclUtil from 'tweetnacl-util'; // default import works both in Metro and in Node's ESM loader (used by the tests)

const { encodeBase64, decodeBase64 } = naclUtil;
const VAULT_VERSION = 1;
const utf8 = (s) => new TextEncoder().encode(s);

export function newVaultKey(rng = nacl.randomBytes) {
  return rng(32);
}

function subKey(vaultKey, label) {
  if (!(vaultKey instanceof Uint8Array) || vaultKey.length !== 32) throw new Error('vault key must be 32 bytes');
  if (typeof label !== 'string' || !label) throw new Error('vault label required');
  return hkdf(sha256, vaultKey, new Uint8Array(32), utf8(`MESH-VAULT-v1|${label}`), 32);
}

/** Seals any JSON-serializable value. Returns a base64 string safe to store in SQLite. */
export function seal(vaultKey, label, value, rng = nacl.randomBytes) {
  const nonce = rng(24);
  const box = nacl.secretbox(utf8(JSON.stringify(value)), nonce, subKey(vaultKey, label));
  const out = new Uint8Array(1 + 24 + box.length);
  out[0] = VAULT_VERSION;
  out.set(nonce, 1);
  out.set(box, 25);
  return encodeBase64(out);
}

/** @throws if the key, label or bytes are wrong: a failed open never returns partial data. */
export function open(vaultKey, label, sealed) {
  const bytes = decodeBase64(sealed);
  if (bytes.length < 1 + 24 + nacl.secretbox.overheadLength || bytes[0] !== VAULT_VERSION) throw new Error('vault record malformed');
  const plain = nacl.secretbox.open(bytes.slice(25), bytes.slice(1, 25), subKey(vaultKey, label));
  if (!plain) throw new Error('vault record could not be opened');
  return JSON.parse(new TextDecoder().decode(plain));
}
