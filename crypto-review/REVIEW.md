# MESH Protocol: cryptography for independent review

**Status: shared for review only. This is not the app.** MESH is an Android messenger with payments inside the chat
([project page](../README.md)). This folder contains only its cryptographic code, extracted so that people who know this
area can find what we got wrong. **We are not cryptographers, the design has had no outside review, and it is not
wire-compatible with Signal.** The rest of the source is private for now.

**Licence:** this repository, including this folder, is licensed under the GNU Affero General Public License v3.0 (AGPLv3) — see [`LICENSE`](../LICENSE) at the repository root. In short: you may use, modify and redistribute this code, including running a modified version as a network service, but any such distribution or hosted service must make its own source available under the same license.

**How to send feedback:** open an issue at https://github.com/Mohamed9522/mesh-protocol-public/issues (label it `crypto-review`).
Specific findings ("step X in `ratchet.js` line N is wrong because...") help most; general opinions are welcome too.
If you find a vulnerability that should not be public yet, email contact@meshprotocol.ru with "SECURITY" in the subject.

What is **not** included: the Android UI, the relay's networking code, request signing between app and relay, Stellar payments,
the update system. The relay's three prekey routes are included as a non-runnable excerpt (`services/mesh-relay/prekey-routes.excerpt.js`).

## 1. What we ask reviewers to look at (in priority order)
1. `mobile/mesh-app/src/crypto/ratchet.js`: the X3DH agreement, KDF chain, message layout, authentication, skipped-key handling.
2. `mobile/mesh-app/src/crypto/messenger.js`: the rules around it (session storage, atomicity, downgrade handling, simultaneous starts).
3. `mobile/mesh-app/src/crypto/prekeys.js` + `services/mesh-relay/lib/prekeys.js` + the three `/prekeys` routes in `services/mesh-relay/index.js`:
   prekey signing and the relay's role.
4. `mobile/mesh-app/src/crypto/vault.js` and `src/db/atRest.js`: encryption of secrets and message text on the phone.

Out of scope for this review (already known, separate work): the request-signing scheme between app and relay (`services/mesh-relay/lib/auth.js`),
Stellar payments, the update-signing system, UI code.

## 2. Goals and non-goals
**Goals.**
- Forward secrecy: a phone compromised later does not reveal messages already sent and received.
- Post-compromise healing: a copy of a session state stops working after one full round trip.
- A malicious or curious relay cannot read messages, and cannot silently turn forward secrecy off or swap keys undetected
  (users can compare a 60-digit safety number outside the relay).
- Lost, duplicated and out-of-order messages are handled; a forged or damaged message can never move the ratchet.

**Non-goals (stated plainly).**
- **Metadata:** the relay sees who talks to whom and when. Forward secrecy does not change that.
- One device per wallet; no multi-device sync.
- Protection against malware running as the app, or a rooted phone (it can ask the Android Keystore for keys as the app does).
- Deniability, and hiding message lengths (padding is not implemented).
- The first message to a stranger relies on trusting the relay's directory for their identity key until the users compare safety numbers (trust on first use).

## 3. Primitives
| Purpose | Choice | Library |
|---|---|---|
| Diffie-Hellman | X25519 | `@noble/curves` 2.0.1 |
| KDF | HKDF-SHA256 | `@noble/hashes` 2.0.1 |
| MAC | HMAC-SHA256 | `@noble/hashes` |
| Message encryption | XSalsa20-Poly1305 (`secretbox`) | `tweetnacl` 1.0.3 |
| Prekey signatures | Ed25519, the user's Stellar wallet key | Stellar SDK on the phone, Node `crypto` on the relay |
| Randomness | `tweetnacl` `randomBytes` (platform CSPRNG) | |

Identity DH key = a static X25519 key derived from the recovery phrase (BIP32 path `m/44'/148'/1'`), published in the relay's directory
together with the wallet address. The wallet's Ed25519 key signs signed prekeys.

## 4. Protocol as implemented
Domain-separation labels are fixed strings: `MESH-X3DH-v1`, `MESH-RK-v1`, `MESH-MK-v1`, `MESH-AD-v1`, `MESH-SPK-v1`, `MESH-VAULT-v1`.

**Prekeys.** Each user uploads one signed prekey (X25519, rotated weekly, the previous one kept for in-flight first messages) and a pool of
up to 100 one-time prekeys. The signed prekey is signed over `"MESH-SPK-v1\n" + wallet address + "\n" + id + "\n" + base64(pub)`.
The relay stores public material only. Fetching a bundle deletes one one-time prekey (rate-limited: 6 per hour per requester and target).

**X3DH.** Initiator A fetches B's bundle (identity key IK_B, signed prekey SPK_B and its signature, optional one-time prekey OPK_B), checks the
signature against B's wallet address and that IK_B equals the key it pinned for B, generates ephemeral EK_A, and computes
`DH1 = DH(IK_A, SPK_B)`, `DH2 = DH(EK_A, IK_B)`, `DH3 = DH(EK_A, SPK_B)`, `DH4 = DH(EK_A, OPK_B)` (if present).
`SK = HKDF-SHA256(ikm = 0xFF*32 || DH1 || DH2 || DH3 [|| DH4], salt = 32 zero bytes, info = "MESH-X3DH-v1", 32)`.
`AD = "MESH-AD-v1" || IK_A || IK_B` (raw X25519 public keys).
B derives the same SK from the init block, deletes the used one-time prekey, and only keeps the session if the first message authenticates.

**Double Ratchet** (per the Signal specification). `KDF_RK(rk, dh) = HKDF(ikm = dh, salt = rk, info = "MESH-RK-v1", 64)` gives new root key and chain key.
`KDF_CK(ck)`: message key = `HMAC(ck, 0x01)`, next chain key = `HMAC(ck, 0x02)`.
From each message key, `HKDF(mk, zero salt, "MESH-MK-v1", 88)` gives: 32-byte encryption key, 24-byte nonce, 32-byte MAC key.
`ciphertext = secretbox(plaintext, nonce, encKey)`; `tag = HMAC-SHA256(macKey, AD || header || ciphertext)`. (So the header and AD are authenticated
by the HMAC, since `secretbox` has no associated data; the Poly1305 tag inside `secretbox` is redundant.)
Skipped message keys are cached (at most 1000 stored, at most 1000 skipped by one message; oldest dropped).

**Wire format** (`ratchet.js` header comment has the byte layout): version 2, flags, sender ratchet key, previous-chain length, message number,
optional init block (IK_A, EK_A, SPK id, OPK id), tag, ciphertext. The header is authenticated, not encrypted. The relay carries it as `"MESH2:" + base64`.

**Session handling** (`messenger.js`). A contact has up to 4 sessions, newest-used first; both sides starting a chat at once yields two sessions
and every message opens under one of them. A session is only created if the init block's identity key equals the pinned key (or, for a stranger, the directory's).
Once a contact has shown a prekey bundle we never send the old format to them and refuse old-format messages from them (no silent downgrade).
Sending saves the advanced session **before** the payload leaves the phone. Receiving stores the new session, the removal of a used one-time prekey and the
message row in one database transaction.

**At rest.** Sessions and prekey secrets are sealed (`secretbox`, random 24-byte nonce) under a sub-key `HKDF(vaultKey, "MESH-VAULT-v1|" + label)` where the label
names the record (e.g. `sessions:<contact>`). The 32-byte vault key is random, created once, and kept in Android secure storage (Keystore-backed), never in the database.
Message text uses the same vault with label `content:<contact>` per message; existing plaintext was migrated in place with `secure_delete` and `VACUUM`.
An attacker with the database file can substitute an older sealed copy of the same record (rollback); this is not prevented.

## 5. Code map
| File | Lines | What it is |
|---|---|---|
| `mobile/mesh-app/src/crypto/ratchet.js` | 282 | X3DH + Double Ratchet, wire format, state (de)serialisation |
| `mobile/mesh-app/src/crypto/messenger.js` | 283 | send/receive rules, sessions list, prekey upkeep, no-downgrade |
| `mobile/mesh-app/src/crypto/prekeys.js` | 112 | own prekey store, signature checks |
| `mobile/mesh-app/src/crypto/vault.js` | 56 | sealing records under the vault key |
| `mobile/mesh-app/src/db/atRest.js` | 31 | sealing message text |
| `mobile/mesh-app/src/crypto/legacy.js` | 33 | the old v1 format (`nacl.box`), kept for older apps |
| `services/mesh-relay/lib/prekeys.js` + `prekey-routes.excerpt.js` | 46 + ~90 | relay side: bundle storage, signature check, rate limits (routes are an excerpt) |

## 6. Tests and how to run them
Requires Node 22. From `mobile/mesh-app` in this folder: `npm install`, then `npm test`: **60 tests** (34 in `ratchet.test.js`, 26 in `messenger.test.js`). They run standalone against a fake relay and fake storage; no phone, network or account is needed.
- `test/ratchet.test.js` (34): published vectors for the primitives (X25519 RFC 7748 section 6.1, HKDF RFC 5869 case 1, HMAC RFC 4231 case 1);
  ratchet behaviour; forward secrecy and healing properties; vault; prekeys; and a **pinned regression vector** (fixed keys give fixed session secret and first message bytes).
  That vector was produced by this implementation. It is not independent, since no other implementation of this exact format exists, so it detects accidental change, not error.
- `test/messenger.test.js` (26): whole flows against a fake relay and storage: downgrade attempts, key swap, forged prekeys, atomic receive, crash between send and save,
  concurrency, simultaneous starts, prekey top-up and rotation, wallet restore.
- (The app's real-SQLite test for message-text encryption is not included here because it needs the app's database layer; `src/db/atRest.js` is included and is only 31 lines.)
- Real-phone check (21 Sept 2026): two Android phones (one on Android 8.1), normal chat, offline delivery, simultaneous start on a fresh pair, fast two-way typing.

## 7. Where we are least sure (questions we would like answered)
1. **Cross-use of the wallet key.** The Ed25519 wallet key also signs relay requests (`MESH-REQ-v1` prefix) and Stellar transactions. Signed prekeys use `MESH-SPK-v1`. Is that domain separation enough?
2. **Identity keys not signed.** IK_A and IK_B (static X25519) are not signed by the wallet key, unlike Signal, where the identity key is the trust root. Authenticity of IK comes from the relay directory plus optional safety-number comparison. Is binding it into AD, or into an XEdDSA-style signature, worth doing?
3. **AD binds the identity keys but not the wallet addresses.** Should it?
4. **Double authentication:** `secretbox` (Poly1305) plus an HMAC over AD||header||ciphertext with a separately derived key. Is anything wrong with deriving the nonce deterministically from the message key (each message key is used once)?
5. **HKDF salts:** the X3DH salt is 32 zero bytes; the message-key expansion also uses a zero salt. Acceptable?
6. **Skipped-key cache limits** (1000 / 1000) and the effect of a malicious sender forcing up to 1000 derivations per message; any denial-of-service concern we missed?
7. **One-time prekey draining** by any registered user (mitigated only by rate limits and the fallback without a one-time prekey).
8. **Multiple sessions per contact:** trying each in turn on receive; any oracle or state-confusion risk?
9. **Message sizes are not padded.**
10. **Unencrypted header** exposes ratchet public keys and counters to the relay. Acceptable given the relay already sees metadata?
11. **Rollback of sealed records** by someone holding the database file (see section 4). Is a counter kept in the Keystore worth the complexity?

## 8. Feedback we would value most
The eleven questions in section 7, in particular questions 1 to 3 (use of the wallet's Ed25519 key, identity keys not being signed, what the associated data binds).
A short answer per question, or "this is fine because...", is a great help.
