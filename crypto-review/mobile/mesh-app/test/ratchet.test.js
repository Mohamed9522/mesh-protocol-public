// Run: npm test   (node --experimental-default-type=module --test test/*.test.js)
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import nacl from 'tweetnacl';
import naclUtil from 'tweetnacl-util';
import { x25519 } from '@noble/curves/ed25519.js';
import { hkdf } from '@noble/hashes/hkdf.js';
import { hmac } from '@noble/hashes/hmac.js';
import { sha256 } from '@noble/hashes/sha2.js';
import {
  newKeyPair, initiatorSession, responderSession, initMatchesSession, encrypt, decrypt, parseWire,
  serializeState, deserializeState, MAX_SKIP, MAX_STORED_SKIPPED,
} from '../src/crypto/ratchet.js';
import { newVaultKey, seal, open } from '../src/crypto/vault.js';
import {
  newPrekeyStore, rotateSignedPrekey, makeOneTimePrekeys, findSignedPrekey, takeOneTimePrekey,
  verifySignedPrekey, signedPrekeyIsDue, prekeyStoreToJSON, prekeyStoreFromJSON, SIGNED_PREKEY_MAX_AGE_MS,
} from '../src/crypto/prekeys.js';

const { encodeBase64 } = naclUtil;
const hex = (b) => Buffer.from(b).toString('hex');
const unhex = (h) => new Uint8Array(Buffer.from(h, 'hex'));
const text = (s) => new TextEncoder().encode(s);
const str = (b) => new TextDecoder().decode(b);

// ── known-answer tests for the primitives (published vectors) ───────────────
describe('primitives match published test vectors', () => {
  test('X25519, RFC 7748 section 6.1', () => {
    const aSk = unhex('77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a');
    const bSk = unhex('5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb');
    assert.equal(hex(x25519.getPublicKey(aSk)), '8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a');
    assert.equal(hex(x25519.getPublicKey(bSk)), 'de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f');
    const shared = '4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742';
    assert.equal(hex(x25519.getSharedSecret(aSk, x25519.getPublicKey(bSk))), shared);
    assert.equal(hex(x25519.getSharedSecret(bSk, x25519.getPublicKey(aSk))), shared);
  });

  test('HKDF-SHA256, RFC 5869 test case 1', () => {
    const okm = hkdf(sha256, unhex('0b'.repeat(22)), unhex('000102030405060708090a0b0c'), unhex('f0f1f2f3f4f5f6f7f8f9'), 42);
    assert.equal(hex(okm), '3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865');
  });

  test('HMAC-SHA256, RFC 4231 test case 1', () => {
    const mac = hmac(sha256, unhex('0b'.repeat(20)), text('Hi There'));
    assert.equal(hex(mac), 'b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7');
  });
});

// ── helpers ─────────────────────────────────────────────────────────────────
const ADDR_B = 'GBVSA4OAHASGMD7J2T2V22MDTPIK2ZCHXWDKRSAPNJQUSKDSQPHEEMBR';

/** A wallet-style signer (Ed25519) standing in for the Stellar keypair. */
function makeSigner() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  const raw = publicKey.export({ format: 'der', type: 'spki' }).subarray(-32);
  return {
    address: ADDR_B, // the address string is only ever used as a label in the signed message
    sign: (msg) => new Uint8Array(crypto.sign(null, Buffer.from(msg), privateKey)),
    verify: (_address, msg, sig) => crypto.verify(null, Buffer.from(msg), publicKey, Buffer.from(sig)),
    raw,
  };
}

/** Bob publishes a bundle; Alice starts a session and Bob accepts her first message. */
function pair({ withOpk = true } = {}) {
  const aliceId = newKeyPair();
  const bobId = newKeyPair();
  const bobSigner = makeSigner();
  const bobStore = newPrekeyStore();
  const spkWire = rotateSignedPrekey(bobStore, { address: bobSigner.address, sign: bobSigner.sign });
  const otkWire = withOpk ? makeOneTimePrekeys(bobStore, 3) : [];
  const bundle = {
    theirIdentityPub: bobId.public,
    spk: { id: spkWire.id, pub: naclUtil.decodeBase64(spkWire.pub) },
    opk: withOpk ? { id: otkWire[0].id, pub: naclUtil.decodeBase64(otkWire[0].pub) } : null,
  };
  const alice = initiatorSession({ myIdentity: aliceId, bundle });

  const bobAccepts = (wire) => {
    const { init } = parseWire(wire);
    const spk = findSignedPrekey(bobStore, init.spkId);
    const opk = init.opkId ? takeOneTimePrekey(bobStore, init.opkId) : null;
    return responderSession({ myIdentity: bobId, spk, opk, init });
  };
  return { aliceId, bobId, bobStore, bobSigner, spkWire, bundle, alice, bobAccepts };
}

/** Sends `msg` from a to b, returning both new states and the wire bytes. */
function send(from, to, msg) {
  const e = encrypt(from, text(msg));
  const d = decrypt(to, e.wire);
  assert.equal(str(d.plaintext), msg);
  return { from: e.state, to: d.state, wire: e.wire };
}

// ── protocol behaviour ──────────────────────────────────────────────────────
describe('X3DH + Double Ratchet', () => {
  test('a first message opens session, replies flow both ways, many turns', () => {
    const p = pair();
    const first = encrypt(p.alice, text('hello bob'));
    let bob = p.bobAccepts(first.wire);
    const d = decrypt(bob, first.wire);
    assert.equal(str(d.plaintext), 'hello bob');
    bob = d.state;
    let alice = first.state;

    for (let i = 0; i < 6; i++) {
      let r = send(bob, alice, `bob says ${i}`); bob = r.from; alice = r.to;
      r = send(alice, bob, `alice says ${i}`); alice = r.from; bob = r.to;
    }
  });

  test('works when the one-time prekeys ran out', () => {
    const p = pair({ withOpk: false });
    const first = encrypt(p.alice, text('no opk'));
    assert.equal(parseWire(first.wire).init.opkId, 0);
    const bob = p.bobAccepts(first.wire);
    assert.equal(str(decrypt(bob, first.wire).plaintext), 'no opk');
  });

  test('several messages in a row before any reply; init block repeats until answered', () => {
    const p = pair();
    let alice = p.alice;
    const wires = [];
    for (let i = 0; i < 4; i++) { const e = encrypt(alice, text(`m${i}`)); alice = e.state; wires.push(e.wire); }
    assert.ok(wires.every((w) => parseWire(w).init), 'every message before the first reply carries the init block');
    let bob = p.bobAccepts(wires[0]);
    wires.forEach((w, i) => {
      assert.ok(initMatchesSession(bob, parseWire(w).init), 'later init blocks are recognised as the same session');
      const d = decrypt(bob, w); bob = d.state;
      assert.equal(str(d.plaintext), `m${i}`);
    });
    // Bob answers; once Alice has read it she stops attaching init
    const reply = encrypt(bob, text('got them'));
    const back = decrypt(alice, reply.wire);
    assert.equal(back.state.init, null);
    assert.equal(parseWire(encrypt(back.state, text('next')).wire).init, null);
  });

  test('a responder cannot send before it has received something', () => {
    const p = pair();
    const bob = p.bobAccepts(encrypt(p.alice, text('x')).wire);
    assert.throws(() => encrypt(bob, text('too early')), { code: 'cannot_send_yet' });
  });

  test('out-of-order delivery inside one chain', () => {
    const p = pair();
    let alice = p.alice;
    const ws = [];
    for (let i = 0; i < 5; i++) { const e = encrypt(alice, text(`m${i}`)); alice = e.state; ws.push(e.wire); }
    let bob = p.bobAccepts(ws[0]);
    for (const i of [3, 0, 4, 1, 2]) {
      const d = decrypt(bob, ws[i]); bob = d.state;
      assert.equal(str(d.plaintext), `m${i}`);
    }
    assert.equal(bob.skipped.size, 0, 'every skipped key is used and deleted');
  });

  test('messages from an old chain arriving after the peer ratcheted', () => {
    const p = pair();
    let alice = p.alice;
    const a = [];
    for (let i = 0; i < 3; i++) { const e = encrypt(alice, text(`a${i}`)); alice = e.state; a.push(e.wire); }
    let bob = p.bobAccepts(a[0]);
    bob = decrypt(bob, a[0]).state;            // a1, a2 still in flight
    let r = send(bob, alice, 'reply'); bob = r.from; alice = r.to;
    r = send(alice, bob, 'a3 on a new chain'); alice = r.from; bob = r.to;
    for (const i of [2, 1]) {                   // late, from the previous chain
      const d = decrypt(bob, a[i]); bob = d.state;
      assert.equal(str(d.plaintext), `a${i}`);
    }
  });

  test('a replayed message is rejected', () => {
    const p = pair();
    const e = encrypt(p.alice, text('once'));
    let bob = p.bobAccepts(e.wire);
    bob = decrypt(bob, e.wire).state;
    assert.throws(() => decrypt(bob, e.wire), { code: 'replay' });
  });

  test('a message is rejected the second time even after it was fetched from the skipped-key cache', () => {
    const p = pair();
    let alice = p.alice;
    const ws = [];
    for (let i = 0; i < 3; i++) { const e = encrypt(alice, text(`m${i}`)); alice = e.state; ws.push(e.wire); }
    let bob = p.bobAccepts(ws[0]);
    bob = decrypt(bob, ws[2]).state;
    bob = decrypt(bob, ws[1]).state;
    assert.throws(() => decrypt(bob, ws[1]));
  });

  test('a failed decryption leaves the session untouched and usable', () => {
    const p = pair();
    const e1 = encrypt(p.alice, text('first'));
    let bob = p.bobAccepts(e1.wire);
    const before = JSON.stringify(serializeState(bob));

    const flip = (w, at) => { const c = w.slice(); c[at] ^= 1; return c; };
    const e2 = encrypt(e1.state, text('second'));
    const cases = {
      'ciphertext': flip(e2.wire, e2.wire.length - 1),
      'tag': flip(e2.wire, 42 + 72 + 3),
      'ratchet key': flip(e2.wire, 5),
      'message number': flip(e2.wire, 41),
      'init block': flip(e2.wire, 50),
      'truncated': e2.wire.slice(0, 60),
    };
    for (const [name, bad] of Object.entries(cases)) {
      assert.throws(() => decrypt(bob, bad), Error, name);
    }
    assert.equal(JSON.stringify(serializeState(bob)), before, 'state object was not mutated');
    const ok = decrypt(bob, e1.wire);            // the real first message still opens
    assert.equal(str(ok.plaintext), 'first');
    assert.equal(str(decrypt(ok.state, e2.wire).plaintext), 'second');
  });

  test('an absurd message number is refused without storing anything', () => {
    const p = pair();
    const e = encrypt(p.alice, text('x'));
    const bob = p.bobAccepts(e.wire);
    const evil = e.wire.slice();
    new DataView(evil.buffer).setUint32(38, MAX_SKIP + 5, false);
    assert.throws(() => decrypt(bob, evil), { code: 'too_many_skipped' });
    assert.equal(bob.skipped.size, 0);
  });

  test('the skipped-key cache is capped and drops the oldest first', () => {
    const p = pair();
    let alice = p.alice;
    const ws = [];
    const total = 2 * (MAX_SKIP - 100) + 4;
    for (let i = 0; i < total; i++) { const e = encrypt(alice, text('x')); alice = e.state; ws.push(e.wire); }
    let bob = p.bobAccepts(ws[0]);
    bob = decrypt(bob, ws[0]).state;
    bob = decrypt(bob, ws[MAX_SKIP - 100]).state;            // skips 1..899
    bob = decrypt(bob, ws[2 * (MAX_SKIP - 100)]).state;      // skips another ~899
    assert.ok(bob.skipped.size <= MAX_STORED_SKIPPED);
    assert.equal(bob.skipped.size, MAX_STORED_SKIPPED, 'exactly full, not over');
    assert.throws(() => decrypt(bob, ws[1]), Error, 'the oldest skipped key was dropped');
    assert.equal(str(decrypt(bob, ws[2 * (MAX_SKIP - 100) - 1]).plaintext), 'x', 'recent ones still open');
  });

  test('a message under the wrong identity (tampered init) cannot open', () => {
    const p = pair();
    const e = encrypt(p.alice, text('secret'));
    const impostor = newKeyPair();
    const forged = e.wire.slice();
    forged.set(impostor.public, 42); // claims to come from a different identity key
    const { init } = parseWire(forged);
    const bob = responderSession({
      myIdentity: p.bobId, spk: findSignedPrekey(p.bobStore, init.spkId),
      opk: init.opkId ? { secret: p.bobStore.otks.find((k) => k.id === init.opkId).secret } : null, init,
    });
    assert.throws(() => decrypt(bob, forged), { code: 'bad_tag' });
  });

  test('a missing one-time prekey is reported, not guessed', () => {
    const p = pair();
    const e = encrypt(p.alice, text('x'));
    const { init } = parseWire(e.wire);
    assert.throws(() => responderSession({ myIdentity: p.bobId, spk: p.bobStore.spk, opk: null, init }), { code: 'missing_opk' });
  });

  test('an unknown message version is refused', () => {
    const p = pair();
    const e = encrypt(p.alice, text('x'));
    const w = e.wire.slice(); w[0] = 1;
    assert.throws(() => parseWire(w), { code: 'bad_version' });
  });

  test('ciphertext does not contain the plaintext', () => {
    const p = pair();
    const e = encrypt(p.alice, text('a very recognisable plaintext string'));
    assert.ok(!Buffer.from(e.wire).includes('recognisable'));
  });
});

// ── the security properties this design exists for ──────────────────────────
describe('forward secrecy and healing', () => {
  test('stealing the long-term keys AND the current session later does not open past messages', () => {
    const p = pair();
    let alice = p.alice;
    let r = encrypt(alice, text('old secret 1')); alice = r.state; const old1 = r.wire;
    let bob = p.bobAccepts(old1);
    bob = decrypt(bob, old1).state;
    r = send(bob, alice, 'reply'); bob = r.from; alice = r.to;
    r = encrypt(alice, text('old secret 2')); alice = r.state; const old2 = r.wire;
    bob = decrypt(bob, old2).state;

    // the phone is compromised now: attacker gets Bob's identity secret, his prekey store and his session
    const stolen = deserializeState(serializeState(bob));
    assert.throws(() => decrypt(stolen, old1), Error, 'recorded message 1 stays sealed');
    assert.throws(() => decrypt(stolen, old2), Error, 'recorded message 2 stays sealed');

    // the one-time prekey that protected message 1 was deleted when it was used, so even the
    // stolen identity key plus the stolen prekey store cannot rebuild the session from the recording
    assert.throws(() => p.bobAccepts(old1), { code: 'missing_opk' });
  });

  test('one-time prekeys are deleted once used, so the first message is also forward secret', () => {
    const p = pair();
    const e = encrypt(p.alice, text('x'));
    const opkId = parseWire(e.wire).init.opkId;
    p.bobAccepts(e.wire);
    assert.equal(p.bobStore.otks.find((k) => k.id === opkId), undefined);
    assert.throws(() => p.bobAccepts(e.wire), { code: 'missing_opk' });
  });

  test('a stolen copy of the session stops working after one full round trip (post-compromise healing)', () => {
    const q = pair();
    const first = encrypt(q.alice, text('hi'));
    let bob = decrypt(q.bobAccepts(first.wire), first.wire).state;
    let alice = first.state;
    let s = send(bob, alice, 'hello back'); bob = s.from; alice = s.to;

    const stolenBob = deserializeState(serializeState(bob)); // attacker copies Bob's state here
    s = send(alice, bob, 'still readable by the thief'); alice = s.from; bob = s.to;
    assert.equal(str(decrypt(stolenBob, s.wire).plaintext), 'still readable by the thief');

    s = send(bob, alice, 'bob ratchets with a fresh key'); bob = s.from; alice = s.to;
    s = send(alice, bob, 'alice answers'); alice = s.from; bob = s.to;
    s = send(bob, alice, 'after healing'); bob = s.from; alice = s.to;
    assert.throws(() => decrypt(stolenBob, s.wire), Error, 'the thief is locked out');
  });

  test('each message uses a different key (no two ciphertexts share a tag or nonce input)', () => {
    const p = pair();
    let alice = p.alice;
    const tags = new Set();
    for (let i = 0; i < 20; i++) { const e = encrypt(alice, text('same text')); alice = e.state; tags.add(hex(parseWire(e.wire).tag)); }
    assert.equal(tags.size, 20);
  });
});

// ── persistence ─────────────────────────────────────────────────────────────
describe('state serialization and the vault', () => {
  test('a session survives serialize, seal, open, deserialize and keeps working', () => {
    const p = pair();
    const first = encrypt(p.alice, text('hi'));
    let bob = decrypt(p.bobAccepts(first.wire), first.wire).state;
    let alice = first.state;
    let s = send(bob, alice, 'a'); bob = s.from; alice = s.to;

    const key = newVaultKey();
    const blob = seal(key, 'session:contactA', serializeState(bob));
    bob = deserializeState(open(key, 'session:contactA', blob));
    s = send(alice, bob, 'still works after a restart');
    assert.equal(s.to.nr > 0, true);
  });

  test('skipped keys survive persistence', () => {
    const p = pair();
    let alice = p.alice; const ws = [];
    for (let i = 0; i < 3; i++) { const e = encrypt(alice, text(`m${i}`)); alice = e.state; ws.push(e.wire); }
    let bob = decrypt(p.bobAccepts(ws[0]), ws[2]).state;
    const key = newVaultKey();
    bob = deserializeState(open(key, 'x', seal(key, 'x', serializeState(bob))));
    assert.equal(str(decrypt(bob, ws[1]).plaintext), 'm1');
  });

  test('the sealed record does not contain any secret in the clear', () => {
    const p = pair();
    const e = encrypt(p.alice, text('x'));
    const bob = decrypt(p.bobAccepts(e.wire), e.wire).state;
    const key = newVaultKey();
    const blob = seal(key, 'session:a', serializeState(bob));
    for (const secret of [bob.dhs.secret, bob.rk, bob.ckr, bob.cks]) {
      assert.ok(!blob.includes(encodeBase64(secret)), 'no raw secret in the stored string');
      assert.ok(!Buffer.from(blob, 'base64').includes(Buffer.from(secret)), 'nor in its decoded bytes');
    }
    assert.ok(!blob.includes('dhs') && !blob.includes('secret'), 'no field names leak');
  });

  test('wrong key, wrong label, tampering and truncation all fail to open', () => {
    const key = newVaultKey();
    const blob = seal(key, 'session:a', { hello: 'world' });
    assert.deepEqual(open(key, 'session:a', blob), { hello: 'world' });
    assert.throws(() => open(newVaultKey(), 'session:a', blob));
    assert.throws(() => open(key, 'session:b', blob), Error, 'a record copied to another contact will not open');
    const bytes = Buffer.from(blob, 'base64'); bytes[bytes.length - 1] ^= 1;
    assert.throws(() => open(key, 'session:a', bytes.toString('base64')));
    assert.throws(() => open(key, 'session:a', blob.slice(0, 20)));
    assert.throws(() => seal(new Uint8Array(16), 'x', {}), /32 bytes/);
    assert.throws(() => seal(key, '', {}), /label/);
  });

  test('sealing the same value twice gives different bytes (fresh nonce)', () => {
    const key = newVaultKey();
    assert.notEqual(seal(key, 'x', { a: 1 }), seal(key, 'x', { a: 1 }));
  });

  test('the prekey store round-trips through the vault', () => {
    const signer = makeSigner();
    const store = newPrekeyStore();
    rotateSignedPrekey(store, { address: signer.address, sign: signer.sign });
    makeOneTimePrekeys(store, 5);
    const key = newVaultKey();
    const back = prekeyStoreFromJSON(open(key, 'prekeys', seal(key, 'prekeys', prekeyStoreToJSON(store))));
    assert.deepEqual(hex(back.spk.secret), hex(store.spk.secret));
    assert.equal(back.otks.length, 5);
    assert.equal(back.nextOtkId, 6);
  });
});

// ── prekeys ─────────────────────────────────────────────────────────────────
describe('prekeys', () => {
  test('a signed prekey verifies under its owner and fails under a tampered key, id, address or signer', () => {
    const owner = makeSigner();
    const other = makeSigner();
    const store = newPrekeyStore();
    const spk = rotateSignedPrekey(store, { address: owner.address, sign: owner.sign });
    assert.equal(verifySignedPrekey(owner.address, spk, owner.verify), true);
    assert.equal(verifySignedPrekey(owner.address, { ...spk, id: spk.id + 1 }, owner.verify), false);
    assert.equal(verifySignedPrekey(owner.address, { ...spk, pub: encodeBase64(nacl.randomBytes(32)) }, owner.verify), false);
    assert.equal(verifySignedPrekey(owner.address, spk, other.verify), false, 'signed by someone else');
    assert.equal(verifySignedPrekey('GDQP2KPQGKIHYJGXNUIYOMHARUARCA7DJT5FO2FFOOKY3B2WSQHG4W37', spk, (a, m, s) => owner.verify(a, m, s)), false, 'bound to the owner address');
    assert.equal(verifySignedPrekey(owner.address, null, owner.verify), false);
    assert.equal(verifySignedPrekey(owner.address, { ...spk, sig: 'not base64!' }, owner.verify), false);
  });

  test('the signed message matches the relay\'s format byte for byte', async () => {
    const { signedPrekeyMessage } = await import('../src/crypto/prekeys.js');
    const relay = await import('../../../services/mesh-relay/lib/prekeys.js');
    const r = relay.default || relay;
    const pub = encodeBase64(nacl.randomBytes(32));
    assert.equal(hex(signedPrekeyMessage(ADDR_B, 7, pub)), hex(r.signedPrekeyMessage(ADDR_B, 7, pub)));
  });

  test('rotation keeps the previous signed prekey for in-flight first messages, then forgets it', () => {
    const s = makeSigner();
    const store = newPrekeyStore();
    const one = rotateSignedPrekey(store, { address: s.address, sign: s.sign });
    const two = rotateSignedPrekey(store, { address: s.address, sign: s.sign });
    assert.equal(two.id, one.id + 1);
    assert.ok(findSignedPrekey(store, one.id) && findSignedPrekey(store, two.id));
    rotateSignedPrekey(store, { address: s.address, sign: s.sign });
    assert.equal(findSignedPrekey(store, one.id), null);
  });

  test('one-time prekey ids are never reused, even after they are consumed', () => {
    const store = newPrekeyStore();
    const a = makeOneTimePrekeys(store, 3);
    takeOneTimePrekey(store, a[2].id);
    const b = makeOneTimePrekeys(store, 2);
    assert.deepEqual(b.map((k) => k.id), [4, 5]);
    assert.equal(takeOneTimePrekey(store, 999), null);
  });

  test('rotation is due after a week', () => {
    const s = makeSigner();
    const store = newPrekeyStore();
    assert.equal(signedPrekeyIsDue(store), true);
    rotateSignedPrekey(store, { address: s.address, sign: s.sign, now: 1000 });
    assert.equal(signedPrekeyIsDue(store, 1000 + SIGNED_PREKEY_MAX_AGE_MS - 1), false);
    assert.equal(signedPrekeyIsDue(store, 1000 + SIGNED_PREKEY_MAX_AGE_MS), true);
  });
});

// ── regression vector ───────────────────────────────────────────────────────
// Produced by this implementation with a fixed random source and then pinned. It is NOT an independent
// vector (no other implementation of this exact format exists): it exists so any accidental change to a
// label, a KDF input, a header field or the message layout fails loudly instead of silently breaking
// compatibility between phones on different versions.
describe('pinned protocol vector', () => {
  const counterRng = () => { let c = 0; return (n) => Uint8Array.from({ length: n }, (_, i) => (++c * 31 + i * 7) & 0xff); };

  test('fixed keys always give the same session secrets and the same first message bytes', () => {
    const rng = counterRng();
    const aliceId = newKeyPair(rng), bobId = newKeyPair(rng), spk = newKeyPair(rng), opk = newKeyPair(rng);
    const alice = initiatorSession({
      myIdentity: aliceId, rng,
      bundle: { theirIdentityPub: bobId.public, spk: { id: 1, pub: spk.public }, opk: { id: 1, pub: opk.public } },
    });
    const e = encrypt(alice, text('MESH vector'));
    const bob = responderSession({ myIdentity: bobId, spk, opk, init: parseWire(e.wire).init });
    assert.equal(str(decrypt(bob, e.wire, rng).plaintext), 'MESH vector');
    assert.equal(hex(alice.ad), hex(bob.ad));
    const got = { wire: hex(e.wire), rk: hex(alice.rk) };
    assert.deepEqual(got, VECTOR, `vector changed: ${JSON.stringify(got)}`);
  });
});

const VECTOR = {
  wire: '02013007aa2b1375292e02c9f6c701127dcb9f3102481397afe1fb131bed95cedf45000000000000000077b1387f6222555fba0bcde6cad29017fc1a0e0d145ec19579103b82b7af9641129c59dd9feb3918773d3ca11cda8b4820e5a7b962e5e195809e51df8023ca1a00000001000000012b4f9292cc0e8a3c3cf6d180cf8f6e57a552a030f3b72773491da345304470cef16c23bc49c62edb6f407bf6fa9054c630e453149dcc350eae2ffd',
  rk: '96b16f94310a473a4184cdca0a66271f3a2d1f6638e9aa4288c27f8ca79780cb',
};
