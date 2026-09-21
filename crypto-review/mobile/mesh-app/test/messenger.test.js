// Run: npm test   (node --experimental-default-type=module --test test/*.test.js)
// Whole-flow tests of src/crypto/messenger.js with a fake relay and fake storage (no phone, no network).
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import naclUtil from 'tweetnacl-util';
import { newKeyPair } from '../src/crypto/ratchet.js';
import { newVaultKey } from '../src/crypto/vault.js';
import { createMessenger, V2_PREFIX, PERMANENT_RECEIVE_FAILURES } from '../src/crypto/messenger.js';
import { encryptV1 } from '../src/crypto/legacy.js';
import { signedPrekeyMessage, prekeyStoreFromJSON, SIGNED_PREKEY_MAX_AGE_MS } from '../src/crypto/prekeys.js';
import { open } from '../src/crypto/vault.js';

const { encodeBase64 } = naclUtil;
const b64 = encodeBase64;

// ── fake world ──────────────────────────────────────────────────────────────
function makeServer() {
  return { bundles: new Map(), hideBundles: new Set(), signers: new Map() };
}

function fakeStorage() {
  const state = { sessions: new Map(), fs: new Set(), prekeys: null };
  const snap = () => ({ sessions: new Map(state.sessions), fs: new Set(state.fs), prekeys: state.prekeys });
  const restore = (s) => { state.sessions = s.sessions; state.fs = s.fs; state.prekeys = s.prekeys; };
  return {
    state,
    getSessions: (a) => state.sessions.get(a) ?? null,
    putSessions: (a, v) => { if (v === null) state.sessions.delete(a); else state.sessions.set(a, v); },
    hasFs: (a) => state.fs.has(a),
    setFs: (a) => { state.fs.add(a); },
    getPrekeys: () => state.prekeys,
    putPrekeys: (v) => { state.prekeys = v; },
    transaction(fn) { const s = snap(); try { return fn(); } catch (e) { restore(s); throw e; } },
  };
}

function fakeRelay(server, address) {
  return {
    async fetchBundle(addr) {
      const b = server.bundles.get(addr);
      if (!b || !b.spk || server.hideBundles.has(addr)) return { status: 404, json: null };
      const otk = b.otks.length ? b.otks.shift() : null;
      return { status: 200, json: { stellarPublic: addr, identityKey: b.identityKey, signedPrekey: b.spk, oneTimePrekey: otk } };
    },
    async prekeyStatus() {
      const b = server.bundles.get(address);
      return { signedPrekeyId: b?.spk ? b.spk.id : null, oneTimePrekeys: b ? b.otks.length : 0 };
    },
    async uploadPrekeys(body) {
      const b = server.bundles.get(address) || { identityKey: null, spk: null, otks: [] };
      if (body.signedPrekey) b.spk = body.signedPrekey;
      if (body.replaceOneTime) b.otks = [];
      if (body.oneTimePrekeys) b.otks.push(...body.oneTimePrekeys);
      if (b.otks.length > 100) return 409;
      server.bundles.set(address, b);
      return 200;
    },
  };
}

let counter = 0;
/** A phone: wallet signer, identity key, storage, messenger. Pass `from` to re-create the same phone (restart) or a wallet restore. */
function makePhone(server, name, { from, freshStorage = false } = {}) {
  const wallet = from?.wallet ?? (() => {
    const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
    return { address: `G${name.toUpperCase()}${++counter}`.padEnd(56, 'X'), publicKey, privateKey };
  })();
  server.signers.set(wallet.address, wallet.publicKey);
  const identity = from?.identity ?? newKeyPair();
  const vaultKey = from?.vaultKey ?? newVaultKey();
  const storage = freshStorage ? fakeStorage() : (from?.storage ?? fakeStorage());
  const messenger = createMessenger({
    identity, myAddress: wallet.address, vaultKey, storage, relay: fakeRelay(server, wallet.address),
    sign: (msg) => new Uint8Array(crypto.sign(null, Buffer.from(msg), wallet.privateKey)),
    verify: (addr, msg, sig) => { const k = server.signers.get(addr); return !!k && crypto.verify(null, Buffer.from(msg), k, Buffer.from(sig)); },
  });
  const phone = { name, wallet, address: wallet.address, identity, identityB64: b64(identity.public), vaultKey, storage, messenger, inbox: [] };
  phone.publish = async () => {
    const r = await messenger.ensurePrekeys();
    const b = server.bundles.get(wallet.address); if (b) b.identityKey = phone.identityB64;
    return r;
  };
  /** delivers a payload to `to` the way a screen would, saving into that phone's inbox */
  phone.deliverTo = (to, payload, extra = {}) => to.messenger.receive({
    from: phone.address, payload, pinnedNaclPublic: phone.identityB64, commit: (t) => to.inbox.push(t), ...extra,
  });
  phone.send = async (to, text) => {
    const r = await phone.messenger.encryptFor({ to: to.address, plaintext: text, pinnedNaclPublic: to.identityB64 });
    return r;
  };
  return phone;
}

const setup = async () => {
  const server = makeServer();
  const alice = makePhone(server, 'alice');
  const bob = makePhone(server, 'bob');
  await alice.publish(); await bob.publish();
  return { server, alice, bob };
};

// ── tests ───────────────────────────────────────────────────────────────────
describe('sending and receiving through the messenger', () => {
  test('first message opens a forward-secret session; the conversation continues both ways', async () => {
    const { alice, bob } = await setup();
    const m1 = await alice.send(bob, 'hello');
    assert.equal(m1.secure, true);
    assert.ok(m1.payload.startsWith(V2_PREFIX));
    assert.deepEqual(await alice.deliverTo(bob, m1.payload), { ok: true, plaintext: 'hello' });

    const reply = await bob.send(alice, 'hi back');
    assert.equal((await bob.deliverTo(alice, reply.payload)).ok, true);
    for (let i = 0; i < 4; i++) {
      assert.equal((await bob.deliverTo(alice, (await bob.send(alice, `b${i}`)).payload)).plaintext, `b${i}`);
      assert.equal((await alice.deliverTo(bob, (await alice.send(bob, `a${i}`)).payload)).plaintext, `a${i}`);
    }
    assert.deepEqual(bob.inbox.slice(0, 2), ['hello', 'a0']);
  });

  test('a contact with no prekeys (older app) gets the old format, marked as not forward secret', async () => {
    const server = makeServer();
    const alice = makePhone(server, 'alice');
    const old = makePhone(server, 'old');            // never publishes
    const r = await alice.send(old, 'legacy hello');
    assert.equal(r.secure, false);
    assert.ok(!r.payload.startsWith(V2_PREFIX));
    assert.equal((await alice.deliverTo(old, r.payload)).plaintext, 'legacy hello');
  });

  test('old-format messages from an old contact are still readable, including from a stranger via lookup', async () => {
    const { alice, bob } = await setup();
    const payload = encryptV1('from an old app', bob.identityB64, b64(alice.identity.secret));
    const asStranger = await bob.messenger.receive({
      from: alice.address, payload, pinnedNaclPublic: null,
      lookupNaclPublic: async () => alice.identityB64, commit: (t) => bob.inbox.push(t),
    });
    assert.equal(asStranger.plaintext, 'from an old app');
  });

  test('no silent downgrade: once a contact showed a bundle, hiding it does not switch forward secrecy off', async () => {
    const { server, alice, bob } = await setup();
    await alice.deliverTo(bob, (await alice.send(bob, 'first')).payload);
    await alice.messenger.discardSessions(bob.address);            // e.g. the contact re-pinned; the flag must survive
    server.hideBundles.add(bob.address);                            // a hostile relay now says "no bundle"
    await assert.rejects(alice.send(bob, 'second'), { code: 'no_downgrade' });
    // and an old-format message from that contact is refused on receipt
    const v1 = encryptV1('forged old format', alice.identityB64, b64(bob.identity.secret));
    const r = await bob.deliverTo(alice, v1);
    assert.deepEqual(r, { ok: false, reason: 'v1_not_allowed' });
    assert.ok(PERMANENT_RECEIVE_FAILURES.has('v1_not_allowed'));
  });

  test('a bundle whose identity key is not the pinned one is refused (relay key swap)', async () => {
    const { server, alice, bob } = await setup();
    server.bundles.get(bob.address).identityKey = b64(newKeyPair().public);
    await assert.rejects(alice.send(bob, 'x'), { code: 'identity_mismatch' });
    assert.equal(alice.storage.getSessions(bob.address), null, 'nothing was stored either');
  });

  test('a signed prekey not signed by the contact is refused', async () => {
    const { server, alice, bob } = await setup();
    const mallory = crypto.generateKeyPairSync('ed25519');
    const pub = b64(newKeyPair().public);
    const b = server.bundles.get(bob.address);
    b.spk = { id: 99, pub, sig: b64(crypto.sign(null, Buffer.from(signedPrekeyMessage(bob.address, 99, pub)), mallory.privateKey)) };
    await assert.rejects(alice.send(bob, 'x'), { code: 'bad_prekey_signature' });
  });

  test('a stranger cannot start a session under someone else\'s identity key', async () => {
    const { alice, bob } = await setup();
    const wire = (await alice.send(bob, 'hi')).payload;
    const r = await bob.messenger.receive({
      from: alice.address, payload: wire, pinnedNaclPublic: null,
      lookupNaclPublic: async () => b64(newKeyPair().public), commit: () => assert.fail('must not commit'),
    });
    assert.deepEqual(r, { ok: false, reason: 'untrusted_identity' });
  });
});

describe('crash safety and atomicity', () => {
  test('if the caller\'s save fails, nothing is kept and redelivery still works (one-time prekey not burnt)', async () => {
    const { alice, bob } = await setup();
    const { payload } = await alice.send(bob, 'important');
    const before = { p: bob.storage.state.prekeys, s: bob.storage.getSessions(alice.address) };

    await assert.rejects(alice.deliverTo(bob, payload, { commit: () => { throw new Error('disk full'); } }), /disk full/);
    assert.equal(bob.storage.state.prekeys, before.p, 'prekeys untouched');
    assert.equal(bob.storage.getSessions(alice.address), before.s, 'session untouched');
    assert.equal(bob.storage.hasFs(alice.address), false);

    assert.deepEqual(await alice.deliverTo(bob, payload), { ok: true, plaintext: 'important' }); // the relay redelivers
  });

  test('the same message twice is a permanent "replay", not a second copy', async () => {
    const { alice, bob } = await setup();
    const { payload } = await alice.send(bob, 'once');
    await alice.deliverTo(bob, payload);
    const again = await alice.deliverTo(bob, payload);
    assert.deepEqual(again, { ok: false, reason: 'replay' });
    assert.ok(PERMANENT_RECEIVE_FAILURES.has('replay'));
    assert.deepEqual(bob.inbox, ['once']);
  });

  test('sending saves the advanced session first: after a restart the next message uses a fresh key', async () => {
    const { server, alice, bob } = await setup();
    const one = await alice.send(bob, 'one');
    await alice.deliverTo(bob, one.payload);
    const two = await alice.send(bob, 'two');                          // "crash": this payload is never sent
    const savedAfterTwo = alice.storage.getSessions(bob.address);

    const restarted = makePhone(server, 'x', { from: alice });         // same keys, same storage
    const three = await restarted.messenger.encryptFor({ to: bob.address, plaintext: 'three', pinnedNaclPublic: bob.identityB64 });
    assert.notEqual(three.payload, two.payload);
    assert.notEqual(alice.storage.getSessions(bob.address), savedAfterTwo);
    assert.equal((await alice.deliverTo(bob, three.payload)).plaintext, 'three');
    assert.equal((await alice.deliverTo(bob, two.payload)).plaintext, 'two', 'the message that was "lost" is still readable if it turns up late');
  });

  test('a tampered stored session is reported, never silently replaced', async () => {
    const { alice, bob } = await setup();
    await alice.send(bob, 'x');
    const sealed = alice.storage.getSessions(bob.address);
    alice.storage.putSessions(bob.address, sealed.slice(0, -4) + 'AAAA');
    await assert.rejects(alice.send(bob, 'y'), { code: 'vault_unreadable' });
  });

  test('nothing secret is stored in the clear', async () => {
    const { alice, bob } = await setup();
    await alice.deliverTo(bob, (await alice.send(bob, 'x')).payload);
    const blobs = [bob.storage.state.prekeys, bob.storage.getSessions(alice.address)];
    const prekeys = prekeyStoreFromJSON(open(bob.vaultKey, 'prekeys', bob.storage.state.prekeys));
    for (const blob of blobs) {
      assert.ok(!blob.includes(b64(prekeys.spk.secret)));
      assert.ok(!Buffer.from(blob, 'base64').includes(Buffer.from(prekeys.spk.secret)));
    }
  });
});

describe('concurrency', () => {
  test('many messages received at once, out of order, all arrive and none is lost', async () => {
    const { alice, bob } = await setup();
    const payloads = [];
    for (let i = 0; i < 8; i++) payloads.push((await alice.send(bob, `m${i}`)).payload);
    const shuffled = [4, 0, 7, 2, 6, 1, 5, 3].map((i) => payloads[i]);
    const results = await Promise.all(shuffled.map((p) => alice.deliverTo(bob, p)));
    assert.ok(results.every((r) => r.ok), JSON.stringify(results));
    assert.deepEqual([...bob.inbox].sort(), Array.from({ length: 8 }, (_, i) => `m${i}`).sort());
  });

  test('sends running in parallel each get their own key', async () => {
    const { alice, bob } = await setup();
    const sent = await Promise.all(Array.from({ length: 6 }, (_, i) => alice.send(bob, `p${i}`)));
    assert.equal(new Set(sent.map((s) => s.payload)).size, 6);
    for (const s of sent) assert.equal((await alice.deliverTo(bob, s.payload)).ok, true);
    assert.equal(bob.inbox.length, 6);
  });

  test('a receive and a send at the same moment do not undo each other', async () => {
    const { alice, bob } = await setup();
    await alice.deliverTo(bob, (await alice.send(bob, 'setup')).payload);
    const fromAlice = (await alice.send(bob, 'a-next')).payload;
    const [received, sent] = await Promise.all([alice.deliverTo(bob, fromAlice), bob.send(alice, 'b-next')]);
    assert.equal(received.ok, true);
    assert.equal((await bob.deliverTo(alice, sent.payload)).plaintext, 'b-next');
    assert.equal((await alice.deliverTo(bob, (await alice.send(bob, 'a-after')).payload)).plaintext, 'a-after');
  });

  test('both people start a chat at the same moment: every message still opens', async () => {
    const { alice, bob } = await setup();
    const fromA = await alice.send(bob, 'a first');
    const fromB = await bob.send(alice, 'b first');
    assert.equal((await alice.deliverTo(bob, fromA.payload)).plaintext, 'a first');
    assert.equal((await bob.deliverTo(alice, fromB.payload)).plaintext, 'b first');
    for (let i = 0; i < 3; i++) {
      assert.equal((await alice.deliverTo(bob, (await alice.send(bob, `a${i}`)).payload)).ok, true);
      assert.equal((await bob.deliverTo(alice, (await bob.send(alice, `b${i}`)).payload)).ok, true);
    }
    assert.equal(bob.inbox.length, 4);
    assert.equal(alice.inbox.length, 4);
  });
});

describe('our own prekeys', () => {
  test('first run publishes a signed prekey and a full pool; the second run does nothing', async () => {
    const server = makeServer();
    const a = makePhone(server, 'a');
    assert.equal(await a.publish(), 'uploaded');
    const b = server.bundles.get(a.address);
    assert.equal(b.otks.length, 50);
    assert.equal(await a.publish(), 'up_to_date');
  });

  test('the pool is topped up when it runs low', async () => {
    const { server, alice, bob } = await setup();
    const relay = fakeRelay(server, bob.address);
    for (let i = 0; i < 35; i++) await relay.fetchBundle(bob.address);   // senders consumed 35
    assert.equal(server.bundles.get(bob.address).otks.length, 15);
    assert.equal(await bob.messenger.ensurePrekeys(), 'uploaded');
    assert.equal(server.bundles.get(bob.address).otks.length, 50);
    // and a first message using one of the new keys opens
    assert.equal((await alice.deliverTo(bob, (await alice.send(bob, 'hi')).payload)).ok, true);
  });

  test('the signed prekey rotates after a week, and first messages that used the old one still open', async () => {
    const { server, alice, bob } = await setup();
    const oldId = server.bundles.get(bob.address).spk.id;
    const inFlight = (await alice.send(bob, 'sent before rotation')).payload;     // names the old signed prekey
    assert.equal(await bob.messenger.ensurePrekeys({ now: Date.now() + SIGNED_PREKEY_MAX_AGE_MS + 1000 }), 'uploaded');
    assert.equal(server.bundles.get(bob.address).spk.id, oldId + 1);
    assert.equal((await alice.deliverTo(bob, inFlight)).plaintext, 'sent before rotation');
  });

  test('if the relay lost our signed prekey it is published again (same key)', async () => {
    const { server, bob } = await setup();
    const kept = server.bundles.get(bob.address).spk;
    server.bundles.get(bob.address).spk = null;
    assert.equal(await bob.messenger.ensurePrekeys(), 'uploaded');
    assert.equal(server.bundles.get(bob.address).spk.pub, kept.pub);
  });

  test('a wallet restored on a new phone replaces the old phone\'s one-time prekeys', async () => {
    const { server, alice, bob } = await setup();
    const oldPool = server.bundles.get(bob.address).otks.map((k) => k.pub);
    const restored = makePhone(server, 'bob2', { from: bob, freshStorage: true });   // same wallet, same identity key, empty phone
    restored.inbox = bob.inbox;
    assert.equal(await restored.publish(), 'uploaded');
    const pool = server.bundles.get(bob.address).otks.map((k) => k.pub);
    assert.equal(pool.length, 50);
    assert.ok(pool.every((k) => !oldPool.includes(k)), 'no key from the old phone is left on the relay');
    const first = await alice.send(bob, 'to the restored phone');
    assert.equal((await alice.deliverTo(restored, first.payload)).plaintext, 'to the restored phone');
  });

  test('if the first upload fails, the retry still replaces the old phone\'s one-time prekeys', async () => {
    const { server, alice, bob } = await setup();
    const oldPool = server.bundles.get(bob.address).otks.map((k) => k.pub);
    const restored = makePhone(server, 'bob4', { from: bob, freshStorage: true });
    // make the first upload fail by pointing this phone's relay at a server that errors once
    let failures = 1;
    const flaky = createMessenger({
      identity: bob.identity, myAddress: bob.address, vaultKey: restored.vaultKey, storage: restored.storage,
      sign: (msg) => new Uint8Array(crypto.sign(null, Buffer.from(msg), bob.wallet.privateKey)), verify: () => true,
      relay: { ...fakeRelay(server, bob.address), uploadPrekeys: async (body) => (failures-- > 0 ? 500 : fakeRelay(server, bob.address).uploadPrekeys(body)) },
    });
    assert.equal(await flaky.ensurePrekeys(), 'upload_failed_500');
    assert.equal(server.bundles.get(bob.address).otks.length, 50, 'old pool still there after the failure');
    assert.equal(await flaky.ensurePrekeys(), 'uploaded');
    const pool = server.bundles.get(bob.address).otks.map((k) => k.pub);
    assert.ok(pool.every((k) => !oldPool.includes(k)), 'replaced on the retry');
    assert.equal(await flaky.ensurePrekeys(), 'up_to_date');
  });

  test('a first message that names an unknown prekey is a permanent failure and burns nothing', async () => {
    const { alice, bob } = await setup();
    const { payload } = await alice.send(bob, 'hi');
    const restored = makePhone(makeServer(), 'bob3', { from: bob, freshStorage: true });   // knows none of our prekeys
    await restored.publish();
    const r = await alice.deliverTo(restored, payload);
    assert.deepEqual(r, { ok: false, reason: 'unknown_prekey' });
    assert.ok(PERMANENT_RECEIVE_FAILURES.has('unknown_prekey'));
  });

  test('after a key change the old sessions are dropped and a new one is negotiated', async () => {
    const { alice, bob } = await setup();
    await alice.deliverTo(bob, (await alice.send(bob, 'one')).payload);
    await alice.messenger.discardSessions(bob.address);
    assert.equal(alice.storage.getSessions(bob.address), null);
    const again = await alice.send(bob, 'two');
    assert.ok(parseInit(again.payload), 'a fresh session starts with an init block');
    assert.equal((await alice.deliverTo(bob, again.payload)).plaintext, 'two');
  });
});

describe('robustness', () => {
  test('garbage payloads are rejected without touching state', async () => {
    const { alice, bob } = await setup();
    for (const junk of [V2_PREFIX + '%%%', V2_PREFIX, V2_PREFIX + b64(new Uint8Array(10)), 'not a message', ':', '']) {
      const r = await alice.deliverTo(bob, junk);
      assert.equal(r.ok, false, junk);
    }
    assert.equal(bob.storage.getSessions(alice.address), null);
    assert.equal(bob.inbox.length, 0);
  });

  test('a message of an unknown version is a permanent failure', async () => {
    const { alice, bob } = await setup();
    const wire = new Uint8Array(Buffer.from((await alice.send(bob, 'x')).payload.slice(V2_PREFIX.length), 'base64'));
    wire[0] = 9;
    const r = await alice.deliverTo(bob, V2_PREFIX + b64(wire));
    assert.deepEqual(r, { ok: false, reason: 'bad_version' });
  });
});

function parseInit(payload) {
  const wire = Buffer.from(payload.slice(V2_PREFIX.length), 'base64');
  return (wire[1] & 1) === 1;
}
