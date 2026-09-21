/**
 * MESH Protocol - src/crypto/messenger.js
 *
 * The layer between the screens and the ratchet (ratchet.js). It decides which format a message uses,
 * keeps sessions and prekeys sealed in storage, and enforces the rules that keep forward secrecy honest.
 * Everything it touches (storage, relay, keys) is injected, so the whole flow is tested in Node.
 *
 * Rules, and why:
 *  - One lock for everything. ChatList and ChatView both poll; without it two passes could each load the same
 *    session, decrypt different messages, and the second write would silently undo the first.
 *  - Send: the advanced session is saved BEFORE the payload is returned for sending. If the app died between
 *    sending and saving, the next message would reuse a message key. A failed send just leaves a harmless gap.
 *  - Receive: the new session, the removal of a used one-time prekey and the caller's own save (the message
 *    row, the "seen" mark) happen in ONE storage transaction. If any part fails, none of it is kept, so the
 *    relay's redelivery decrypts again from the old state. The relay is told "delivered" only after this returns ok.
 *  - No silent downgrade. Once a contact has shown a prekey bundle, we never send them the old format and we
 *    refuse old-format messages from them: a relay hiding bundles must not be able to switch forward secrecy off.
 *  - Identity: a session is only created if the key in the bundle / init block equals the key we pinned for
 *    the contact (or, for a stranger, the key the relay's directory lists, which safety numbers then verify).
 *  - Sessions are a short list per contact (newest used first): if both people start a chat at the same moment,
 *    both sessions exist and every message opens under one of them.
 *
 * Storage contract (synchronous):
 *   getSessions(addr) -> sealed string | null     putSessions(addr, sealed | null)
 *   hasFs(addr) -> bool                          setFs(addr)
 *   getPrekeys() -> sealed | null                putPrekeys(sealed)
 *   transaction(fn) -> runs fn atomically; if fn throws, nothing it wrote is kept, and the error propagates
 * Relay contract (async): fetchBundle(addr) -> {status, json}; prekeyStatus() -> json | null; uploadPrekeys(body) -> status
 *
 * Wire prefix: "MESH2:" + base64(ratchet message). Anything else is the old "nonce:ciphertext" format.
 */

import nacl from 'tweetnacl';
import naclUtil from 'tweetnacl-util'; // default import works both in Metro and in Node's ESM loader (used by the tests)
import {
  initiatorSession, responderSession, encrypt, decrypt, parseWire,
  serializeState, deserializeState,
} from './ratchet.js';
import { seal, open } from './vault.js';
import {
  newPrekeyStore, rotateSignedPrekey, makeOneTimePrekeys, findSignedPrekey, takeOneTimePrekey,
  verifySignedPrekey, signedPrekeyIsDue, signedPrekeyMessage, prekeyStoreToJSON, prekeyStoreFromJSON,
  ONE_TIME_POOL_TARGET, ONE_TIME_POOL_LOW,
} from './prekeys.js';
import { encryptV1, decryptV1 } from './legacy.js';

const { encodeBase64, decodeBase64 } = naclUtil;

export const V2_PREFIX = 'MESH2:';
const MAX_SESSIONS = 4;
const utf8 = (s) => new TextEncoder().encode(s);
const same = (a, b) => a.length === b.length && nacl.verify(a, b);
const fail = (code, msg) => Object.assign(new Error(msg || code), { code });

/** Failures that will never succeed on retry: the caller should tell the relay it is delivered and move on. */
export const PERMANENT_RECEIVE_FAILURES = new Set(['replay', 'malformed', 'bad_version', 'too_many_skipped', 'unknown_prekey', 'v1_not_allowed']);

export function createMessenger({ identity, myAddress, sign, verify, vaultKey, storage, relay, rng = nacl.randomBytes }) {
  const identityB64 = { public: encodeBase64(identity.public), secret: encodeBase64(identity.secret) };

  let queue = Promise.resolve();
  function locked(fn) {
    const run = queue.then(fn, fn);
    queue = run.catch(() => {});
    return run;
  }

  // ── sealed storage helpers ───────────────────────────────────────────────
  function loadSessions(addr) {
    const sealed = storage.getSessions(addr);
    if (!sealed) return [];
    let opened;
    try { opened = open(vaultKey, `sessions:${addr}`, sealed); }
    catch { throw fail('vault_unreadable', 'stored session could not be opened'); } // never silently start over
    return opened.sessions.map(deserializeState);
  }
  const saveSessions = (addr, list) =>
    storage.putSessions(addr, list.length ? seal(vaultKey, `sessions:${addr}`, { sessions: list.map(serializeState) }, rng) : null);

  function loadPrekeys() {
    const sealed = storage.getPrekeys();
    if (!sealed) return null;
    try { return prekeyStoreFromJSON(open(vaultKey, 'prekeys', sealed)); }
    catch { throw fail('vault_unreadable', 'stored prekeys could not be opened'); }
  }
  const sealPrekeys = (store) => seal(vaultKey, 'prekeys', prekeyStoreToJSON(store), rng);

  // ── sending ──────────────────────────────────────────────────────────────
  function trySend(to, bytes) {
    const list = loadSessions(to);
    const at = list.findIndex((s) => s.cks);
    if (at === -1) return null;
    const e = encrypt(list[at], bytes);
    list[at] = e.state;
    storage.transaction(() => saveSessions(to, list)); // saved before the caller sends
    return { payload: V2_PREFIX + encodeBase64(e.wire), secure: true };
  }

  /**
   * @returns {{ payload: string, secure: boolean }}  secure=false means the old format was used (no forward secrecy)
   * @throws with .code: no_key | no_downgrade | bundle_unavailable | identity_mismatch | bad_prekey_signature | vault_unreadable
   */
  async function encryptFor({ to, plaintext, pinnedNaclPublic }) {
    const bytes = utf8(plaintext);
    const existing = await locked(() => trySend(to, bytes));
    if (existing) return existing;

    if (!pinnedNaclPublic) throw fail('no_key', 'no pinned encryption key for this contact');
    const res = await relay.fetchBundle(to); // network, outside the lock: a slow relay must not block receiving

    if (res.status === 404) {
      if (storage.hasFs(to)) throw fail('no_downgrade', 'this contact has forward secrecy; refusing to fall back to the old format');
      return { payload: encryptV1(plaintext, pinnedNaclPublic, identityB64.secret, rng), secure: false };
    }
    if (res.status !== 200 || !res.json) throw fail('bundle_unavailable', `prekey server answered ${res.status}`);

    const b = res.json;
    let identityKey; let spkPub; let opkPub = null;
    try {
      identityKey = decodeBase64(b.identityKey);
      spkPub = decodeBase64(b.signedPrekey.pub);
      if (b.oneTimePrekey) opkPub = decodeBase64(b.oneTimePrekey.pub);
    } catch { throw fail('bundle_unavailable', 'malformed prekey bundle'); }
    if (identityKey.length !== 32 || spkPub.length !== 32 || (opkPub && opkPub.length !== 32)
        || !Number.isInteger(b.signedPrekey.id) || (b.oneTimePrekey && !Number.isInteger(b.oneTimePrekey.id))) {
      throw fail('bundle_unavailable', 'malformed prekey bundle');
    }
    if (!same(identityKey, decodeBase64(pinnedNaclPublic))) throw fail('identity_mismatch', 'bundle key differs from the pinned key');
    if (!verifySignedPrekey(to, b.signedPrekey, verify)) throw fail('bad_prekey_signature', 'signed prekey is not signed by the contact');

    return locked(() => {
      const raced = trySend(to, bytes); // a session may have appeared while we were fetching
      if (raced) return raced;
      const list = loadSessions(to);
      const session = initiatorSession({
        myIdentity: identity, rng,
        bundle: {
          theirIdentityPub: identityKey,
          spk: { id: b.signedPrekey.id, pub: spkPub },
          opk: b.oneTimePrekey ? { id: b.oneTimePrekey.id, pub: opkPub } : null,
        },
      });
      const e = encrypt(session, bytes);
      storage.transaction(() => {
        saveSessions(to, [e.state, ...list].slice(0, MAX_SESSIONS));
        storage.setFs(to);
      });
      return { payload: V2_PREFIX + encodeBase64(e.wire), secure: true };
    });
  }

  // ── receiving ────────────────────────────────────────────────────────────
  /**
   * @param from                the sender's wallet address (from the relay pointer)
   * @param payload             the blob string
   * @param pinnedNaclPublic    the key we pinned for this contact, or null for a stranger
   * @param lookupNaclPublic    async () => base64 key | null; used only for a stranger
   * @param commit              (plaintext) => void; the caller's save (message row, seen mark). Runs inside the same
   *                            transaction as the state update; if it throws, nothing is kept.
   * @returns {{ok: true, plaintext} | {ok: false, reason}}
   */
  async function receive({ from, payload, pinnedNaclPublic, lookupNaclPublic, commit }) {
    const isV2 = typeof payload === 'string' && payload.startsWith(V2_PREFIX);
    let wire = null; let parsed = null;
    if (isV2) {
      try { wire = decodeBase64(payload.slice(V2_PREFIX.length)); parsed = parseWire(wire); }
      catch (e) { return { ok: false, reason: e.code || 'malformed' }; }
    }

    // Who to trust as the sender's identity key. A lookup is a network call, so it happens before the lock.
    let trustedKey = pinnedNaclPublic || null;
    if (!trustedKey && (!isV2 || parsed.init) && lookupNaclPublic) trustedKey = await lookupNaclPublic();

    return locked(() => (isV2 ? receiveV2(from, wire, parsed, trustedKey, commit) : receiveV1(from, payload, trustedKey, commit)));
  }

  function receiveV1(from, payload, trustedKey, commit) {
    if (storage.hasFs(from)) return { ok: false, reason: 'v1_not_allowed' };
    if (!trustedKey) return { ok: false, reason: 'no_key' };
    const plaintext = decryptV1(payload, trustedKey, identityB64.secret);
    if (plaintext === null) return { ok: false, reason: 'bad_tag' };
    storage.transaction(() => commit(plaintext));
    return { ok: true, plaintext };
  }

  function receiveV2(from, wire, parsed, trustedKey, commit) {
    const sessions = loadSessions(from);
    let hit = null; let lastError = null; let sawReplay = false;
    for (let i = 0; i < sessions.length && !hit; i++) {
      try { hit = { i, ...decrypt(sessions[i], wire, rng) }; } catch (e) { lastError = e; if (e.code === 'replay') sawReplay = true; }
    }
    if (!hit && sawReplay) return { ok: false, reason: 'replay' }; // same chain, number already used: not a new session

    let nextSessions; let sealedPrekeys = null;
    if (hit) {
      nextSessions = [hit.state, ...sessions.filter((_, i) => i !== hit.i)]; // the session that worked goes first
    } else {
      if (!parsed.init) return { ok: false, reason: lastError ? (lastError.code || 'bad_tag') : 'no_session' };
      const { init } = parsed;
      if (!trustedKey || !same(init.ik, decodeBase64(trustedKey))) return { ok: false, reason: 'untrusted_identity' };
      const store = loadPrekeys();
      if (!store) return { ok: false, reason: 'unknown_prekey' };
      const spk = findSignedPrekey(store, init.spkId);
      const opk = init.opkId ? takeOneTimePrekey(store, init.opkId) : null;
      if (!spk || (init.opkId && !opk)) return { ok: false, reason: 'unknown_prekey' };
      try {
        const fresh = responderSession({ myIdentity: identity, spk, opk, init });
        hit = { ...decrypt(fresh, wire, rng) };
      } catch (e) {
        return { ok: false, reason: e.code || 'bad_tag' }; // the one-time prekey was only removed from our in-memory copy
      }
      nextSessions = [hit.state, ...sessions].slice(0, MAX_SESSIONS);
      sealedPrekeys = sealPrekeys(store);
    }

    const plaintext = new TextDecoder().decode(hit.plaintext);
    storage.transaction(() => {
      saveSessions(from, nextSessions);
      if (sealedPrekeys) storage.putPrekeys(sealedPrekeys);
      storage.setFs(from);
      commit(plaintext);
    });
    return { ok: true, plaintext };
  }

  // ── our own prekeys ──────────────────────────────────────────────────────
  /**
   * Makes sure the relay holds a current signed prekey and enough one-time prekeys. Safe to call often
   * (app start, foreground). New private keys are saved locally BEFORE they are uploaded, so any key the relay
   * hands out always has its private half here. Returns a short status string (useful in tests and logs).
   */
  async function ensurePrekeys({ now = Date.now() } = {}) {
    let status = null;
    try { status = await relay.prekeyStatus(); } catch { return 'relay_unreachable'; }
    if (!status) return 'relay_unreachable';

    const plan = await locked(() => {
      let store = loadPrekeys();
      if (!store) store = newPrekeyStore({ rng });
      // New install or restored wallet: whatever one-time prekeys the relay holds are not ours. The flag is kept
      // on disk until an upload succeeds, so a failed first attempt cannot leave the old phone's keys in place.
      if (!store.spk) store.pendingReplace = true;
      const fresh = store.pendingReplace;

      const body = { stellarPublic: myAddress };
      let changed = false;
      if (fresh || signedPrekeyIsDue(store, now)) {
        body.signedPrekey = rotateSignedPrekey(store, { address: myAddress, sign, rng, now });
        changed = true;
      } else if (status.signedPrekeyId !== store.spk.id) {
        const pub = encodeBase64(store.spk.public); // relay lost or replaced it: publish ours again (same key, fresh signature)
        body.signedPrekey = { id: store.spk.id, pub, sig: encodeBase64(sign(signedPrekeyMessage(myAddress, store.spk.id, pub))) };
      }

      const have = fresh ? 0 : status.oneTimePrekeys;
      if (fresh || have < ONE_TIME_POOL_LOW) {
        body.oneTimePrekeys = makeOneTimePrekeys(store, ONE_TIME_POOL_TARGET - have, rng);
        if (fresh) body.replaceOneTime = true;
        changed = true;
      }
      if (!body.signedPrekey && !body.oneTimePrekeys) return null;
      if (changed) storage.transaction(() => storage.putPrekeys(sealPrekeys(store)));
      return body;
    });
    if (!plan) return 'up_to_date';

    let code;
    try { code = await relay.uploadPrekeys(plan); } catch { return 'relay_unreachable'; }
    if (code !== 200) return `upload_failed_${code}`;
    if (plan.replaceOneTime) {
      await locked(() => {
        const store = loadPrekeys();
        if (store && store.pendingReplace) { store.pendingReplace = false; storage.transaction(() => storage.putPrekeys(sealPrekeys(store))); }
      });
    }
    return 'uploaded';
  }

  /** The contact's encryption key changed (re-pinned): old sessions are meaningless. The no-downgrade flag stays. */
  const discardSessions = (addr) => locked(() => storage.transaction(() => storage.putSessions(addr, null)));

  return { encryptFor, receive, ensurePrekeys, discardSessions };
}
