// EXCERPT for review, not runnable on its own: the three prekey routes of the relay (services/mesh-relay/index.js).
// The relay stores PUBLIC keys only. Names not defined here (db, limiter, events, deny, isOwner, isAddress, LIMITS,
// tooMany, verifySignedPrekey, isPrekeyId, isX25519B64, MAX_ONE_TIME_PREKEYS, MAX_UPLOAD_BATCH) are defined in the
// full relay, which is private for now. Requests are signed by the caller's Stellar (Ed25519) key; request.meshKey
// is the verified signer.

// ── Prekeys (forward secrecy) ───────────────────────────────────────────────
// Only public keys live here. A sender fetches a bundle to start an encrypted session
// with someone who may be offline; each fetch hands out one single-use prekey.

// Upload a new signed prekey (replaces the old one) and/or more one-time prekeys.
// replaceOneTime:true first empties the user's one-time pool (used after a wallet restore on a new phone).
fastify.post('/prekeys', async (request, reply) => {
  const { stellarPublic, signedPrekey, oneTimePrekeys, replaceOneTime } = request.body || {};
  if (!isAddress(stellarPublic)) return deny(reply, 400, 'invalid address');
  if (!isOwner(request, stellarPublic)) return deny(reply, 403, 'forbidden');
  if (replaceOneTime !== undefined && replaceOneTime !== true) return deny(reply, 400, 'invalid replaceOneTime');
  if (replaceOneTime && oneTimePrekeys === undefined) return deny(reply, 400, 'replaceOneTime needs oneTimePrekeys');
  if (signedPrekey === undefined && oneTimePrekeys === undefined) return deny(reply, 400, 'nothing to upload');

  if (signedPrekey !== undefined) {
    if (!signedPrekey || typeof signedPrekey !== 'object' || !verifySignedPrekey(stellarPublic, signedPrekey)) {
      return deny(reply, 400, 'invalid signedPrekey');
    }
  }
  let batch = [];
  if (oneTimePrekeys !== undefined) {
    if (!Array.isArray(oneTimePrekeys) || oneTimePrekeys.length === 0 || oneTimePrekeys.length > MAX_UPLOAD_BATCH) {
      return deny(reply, 400, `oneTimePrekeys must be 1-${MAX_UPLOAD_BATCH} items`);
    }
    const ids = new Set();
    for (const k of oneTimePrekeys) {
      if (!k || !isPrekeyId(k.id) || !isX25519B64(k.pub) || ids.has(k.id)) return deny(reply, 400, 'invalid oneTimePrekeys');
      ids.add(k.id);
    }
    batch = oneTimePrekeys;
  }
  // Prekeys belong to a registered identity, and are only valid for the key it registered.
  if (!db.prepare('SELECT 1 FROM users WHERE stellarPublic = ?').get(stellarPublic)) return deny(reply, 409, 'not registered');

  db.exec('BEGIN');
  try {
    if (signedPrekey !== undefined) {
      db.prepare(`
        INSERT INTO signed_prekeys (stellarPublic, id, pub, sig, created_at) VALUES (?, ?, ?, ?, ?)
        ON CONFLICT(stellarPublic) DO UPDATE SET id = excluded.id, pub = excluded.pub, sig = excluded.sig, created_at = excluded.created_at
      `).run(stellarPublic, signedPrekey.id, signedPrekey.pub, signedPrekey.sig, Date.now());
    }
    if (replaceOneTime) {
      // A restored wallet on a new phone: the old phone's one-time prekeys have no private half any more.
      db.prepare('DELETE FROM one_time_prekeys WHERE stellarPublic = ?').run(stellarPublic);
    }
    if (batch.length) {
      const have = db.prepare('SELECT COUNT(*) AS c FROM one_time_prekeys WHERE stellarPublic = ?').get(stellarPublic).c;
      if (have + batch.length > MAX_ONE_TIME_PREKEYS) {
        db.exec('ROLLBACK');
        return deny(reply, 409, `pool is capped at ${MAX_ONE_TIME_PREKEYS}; you have ${have}`);
      }
      const insert = db.prepare('INSERT OR IGNORE INTO one_time_prekeys (stellarPublic, id, pub) VALUES (?, ?, ?)');
      for (const k of batch) insert.run(stellarPublic, k.id, k.pub);
    }
    db.exec('COMMIT');
  } catch (e) {
    try { db.exec('ROLLBACK'); } catch {}
    throw e;
  }
  events.log('prekeys_uploaded', { signed: signedPrekey !== undefined, oneTime: batch.length });
  return { ok: true };
});

// The owner's own view, so the app knows when to top up or rotate.
// (Registered before /prekeys/:address; "status" is not a valid address anyway.)
fastify.get('/prekeys/status', async (request) => {
  const who = request.meshKey;
  if (who === null) return { signedPrekeyId: null, signedPrekeyAgeMs: null, oneTimePrekeys: 0 };
  const spk = db.prepare('SELECT id, created_at FROM signed_prekeys WHERE stellarPublic = ?').get(who);
  const c = db.prepare('SELECT COUNT(*) AS c FROM one_time_prekeys WHERE stellarPublic = ?').get(who).c;
  return { signedPrekeyId: spk ? spk.id : null, signedPrekeyAgeMs: spk ? Date.now() - spk.created_at : null, oneTimePrekeys: c };
});

// Fetch someone's bundle to start a session. Consumes one one-time prekey when any are left;
// without one the session still works, just with slightly weaker replay properties (as in Signal).
fastify.get('/prekeys/:address', async (request, reply) => {
  const { address } = request.params;
  if (!isAddress(address)) return deny(reply, 404, 'not found');
  if (request.meshKey === null) return deny(reply, 401, 'unsigned'); // needs a known requester to rate-limit draining

  // Draining someone's prekey pool is the one abuse this endpoint invites: cap it per requester and target.
  const pair = limiter.hit('prekey-pair', `${request.meshKey}:${address}`, LIMITS.prekeyFetchPerTargetHour, 3600 * 1000);
  if (!pair.ok) return tooMany(reply, pair.retryAfter, 'prekey_pair');

  const id = db.prepare('SELECT username, naclPublic FROM users WHERE stellarPublic = ?').get(address);
  const spk = db.prepare('SELECT id, pub, sig FROM signed_prekeys WHERE stellarPublic = ?').get(address);
  if (!id || !spk) return deny(reply, 404, 'not found'); // unknown or older app: sender falls back to v1

  let otk = null;
  db.exec('BEGIN');
  try {
    otk = db.prepare(`
      DELETE FROM one_time_prekeys WHERE rowid = (
        SELECT rowid FROM one_time_prekeys WHERE stellarPublic = ? ORDER BY id LIMIT 1
      ) RETURNING id, pub
    `).get(address) || null;
    db.exec('COMMIT');
  } catch (e) {
    try { db.exec('ROLLBACK'); } catch {}
    throw e;
  }
  events.log('prekey_fetched', { oneTime: otk ? 'given' : 'exhausted' });
  return {
    stellarPublic: address,
    identityKey: id.naclPublic,
    signedPrekey: { id: spk.id, pub: spk.pub, sig: spk.sig },
    oneTimePrekey: otk ? { id: otk.id, pub: otk.pub } : null,
  };
});

