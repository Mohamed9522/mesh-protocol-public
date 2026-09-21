/**
 * MESH Protocol - src/db/atRest.js
 *
 * Encryption of message text before it is written to the local SQLite file, using the vault key that lives in
 * secure storage (Android Keystore) and never in the database. Built on vault.js (XSalsa20-Poly1305).
 *
 * Each value is sealed under a sub-key bound to its "scope" (the contact's address for messages, "req:<address>"
 * for message requests), so a sealed value copied into another conversation's row will not open.
 *
 * What this protects: the database file on its own (a copied app folder, a cloud or adb backup, a forensic image
 * taken without the Keystore). What it does not: malware running as the app, or a rooted phone, which can ask the
 * Keystore for the key just as the app does. Contacts, timestamps and who-talks-to-whom are still stored plainly.
 *
 * Pure functions, no React Native imports, so the same code is unit-tested in Node.
 */

import { seal, open } from '../crypto/vault.js';

export const UNREADABLE = '🔒 This message could not be decrypted on this device.';

export const sealContent = (key, scope, text) => seal(key, `content:${scope}`, text);

/** The text, or null if the key or scope is wrong or the value was altered. */
export function openContent(key, scope, sealed) {
  try {
    const text = open(key, `content:${scope}`, sealed);
    return typeof text === 'string' ? text : null;
  } catch {
    return null;
  }
}
