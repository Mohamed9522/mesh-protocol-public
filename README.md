# MESH Protocol

**An Android messenger where money moves inside the chat.**
End-to-end encrypted with forward secrecy. Identity is a 12-word recovery phrase: no phone number, no email. Payments are Stellar transactions sent from inside a conversation.

🌐 [meshprotocol.ru](https://meshprotocol.ru) · 📧 contact@meshprotocol.ru · 🐞 [Report an issue](https://github.com/Mohamed9522/mesh-protocol-public/issues)

> **Status: testnet beta, early software, built by one developer.**
> Payments use **Stellar testnet: no real funds**. The cryptography has **not** yet had an independent review (the code is published in [`crypto-review/`](crypto-review/REVIEW.md) for anyone to review). Please read [Known limits](#known-limits) before you use it.

---

## What is MESH?

MESH is a messenger with built-in payments. Messages are encrypted on your phone before they leave it. A small **relay server** carries each encrypted message and keeps it only until your recipient's phone confirms delivery, then deletes it. You can send XLM to the person you are talking to from inside the chat, and the receiving app verifies the payment on the Stellar network.

Your identity is a 12-word recovery phrase. It generates your Stellar address and your encryption keys on your device. There is no account to create and no personal data to hand over.

## How it works

```
Sender's phone                       Relay (temporary)                 Recipient's phone
──────────────                       ─────────────────                 ─────────────────
1. Encrypt the message on the phone
   (X3DH + Double Ratchet: every
   message gets its own key)
2. Signed request ───────────────►  3. Hold the encrypted message
                                       until delivery is confirmed
                                    4. Push notification (no content) ─► 5. Fetch, decrypt on the phone
                                                                        6. Confirm delivery
                                    7. Relay deletes its copy  ◄────────
```

- **Ordinary messages never touch the blockchain.** Only payments are Stellar transactions.
- **Forward secrecy:** each message key is used once and then deleted, so a phone compromised later cannot open messages that were already sent. Keys also heal after a compromise once the conversation continues.
- **Safety numbers:** a 60-digit number (and QR code) that two people compare outside the app to confirm nobody swapped a key.
- **Encrypted on your phone:** message text is stored encrypted in the app's database. An optional **app lock** (fingerprint or PIN) also blocks screenshots and hides MESH in the app switcher.
- **Signed updates:** app updates are signed with a key that only the developer holds.

## Features (beta)

| Feature | Status |
|---|---|
| End-to-end encrypted messaging with forward secrecy | ✅ Working |
| @username search and discovery | ✅ Working |
| Message requests (control who can reach you) | ✅ Working |
| Send XLM inside a chat, verified on Stellar (testnet) | ✅ Working |
| Photos | ✅ Working |
| Push notifications | ✅ Working |
| Safety numbers (key verification) | ✅ Working |
| Encrypted message storage on the phone | ✅ Working |
| Optional app lock (fingerprint / PIN) | ✅ Working |
| Copy, forward, delete a message for yourself; delete a chat | ✅ Working |
| Day separators in chats | ✅ Working |
| Recovery phrase restore on a new phone (account, not old chats) | ✅ Working |
| Signed over-the-air updates | ✅ Working |
| USDC payments and payment requests | 🔲 Planned |
| Stellar mainnet | 🔲 Planned, only after legal review |
| Voice notes, file sharing | 🔲 Planned |
| Profile pictures | 🔲 Planned |
| iOS, desktop | 🔲 Planned |

## Downloads paused

**MESH is under maintenance and being rebranded.** Downloads of the app are paused, and no build is offered here for now. This repository stays up for the published cryptography (`crypto-review/`). We will announce when a new version is available.

## Known limits

We would rather you hear these from us:

- **Testnet only.** No real funds move. Mainnet depends on legal review and is not scheduled.
- **The cryptography has not been independently reviewed.** It is built from standard primitives (X25519, HKDF-SHA256, HMAC-SHA256, XSalsa20-Poly1305) following the Signal specifications, but the composition is our own and unreviewed. The design is not wire-compatible with Signal.
- **One relay today, run by us.** All messages pass through a single relay that we operate. It cannot read message content, but it does see delivery metadata: which address sends to which, and when. Removing that single point is the main goal: see [Run your own relay](#the-plan-run-your-own-relay).
- **Backups.** The relay's database is backed up to a private Cloudflare R2 bucket; a message that was delivered and deleted can persist in a backup for about 2 days.
- **On your phone,** message text is encrypted, but contacts and timestamps are not. Malware running as the app, or a rooted phone, can still read them.
- **One device per recovery phrase.** Restoring on a new phone brings back your account, not your old chats.
- Android only. One developer. Expect bugs.

## Tech stack

| Component | Technology |
|---|---|
| Mobile app | React Native / Expo, Android |
| Encryption | X3DH + Double Ratchet; X25519, HKDF-SHA256, HMAC-SHA256, XSalsa20-Poly1305 (`@noble/curves`, `@noble/hashes`, `tweetnacl`) |
| Identity | BIP39 recovery phrase → Stellar (Ed25519) and X25519 keys |
| Payments | Stellar, verified on-chain by the receiving app |
| Relay | Node.js 22, Fastify, SQLite, Caddy (HTTPS), Litestream (backups) |
| Push | Firebase Cloud Messaging via Expo (generic text, no content) |
| On the phone | Expo SQLite (message text encrypted), Expo SecureStore (Android Keystore) |

## Privacy

Full policy: [meshprotocol.ru/privacy.html](https://meshprotocol.ru/privacy.html). In short, the relay stores your public Stellar address, your public encryption key, your username, your push token, prekeys (public), and each encrypted message until it is delivered (at most 14 days if never collected). Usage logs keep a salted hash of your address and IP for 90 days, never message content.

## The plan: run your own relay

Today there is one relay, run by us. The goal is a **network of relays that anyone can run**: a small program (and, later, a ready-made image) that turns an old office PC or a Raspberry Pi at home into your own message server. Your phone and your contacts' phones would connect through it, your messages would wait there until delivered, and payments would still go straight over Stellar. Think of it as your own messaging server at home, with money transfer built in. This is a roadmap item, not something you can do yet.

## Source code

Most of the source code is currently **private**. The **cryptography is public for independent review**: see [`crypto-review/`](crypto-review/REVIEW.md) (the ratchet, session handling, prekeys, the storage vault, their tests, and a reviewer's guide, with 60 tests you can run yourself). We are not cryptographers and this has not been reviewed; if you know this area, please tell us what is wrong, by [opening an issue](https://github.com/Mohamed9522/mesh-protocol-public/issues). More will be published after that review.

This repository is licensed under [AGPLv3](LICENSE).

## FAQ

**Do I need to pay anything?** No. Ordinary messages are free. Payments pay Stellar's network fee (0.00001 XLM). On testnet, XLM is free from Friendbot.

**What if I lose my phone?** Install MESH on a new phone and enter your 12-word phrase to restore your account. Old chats stay on the old phone.

**Can MESH read my messages?** No. Messages are encrypted on your phone with keys the relay never has. It can see who sent to whom and when.

**Where is the relay?** It is one relay that we operate on a rented server (RUVDS, Russia). Message content is end-to-end encrypted, so the server cannot read it; it sees delivery metadata. The plan is that you can run your own relay instead (see below).

## Contact

- Bugs, questions, security concerns: [GitHub Issues](https://github.com/Mohamed9522/mesh-protocol-public/issues)
- Email: contact@meshprotocol.ru
- Website: [meshprotocol.ru](https://meshprotocol.ru)

## Version history

| Version | Date | Notes |
|---|---|---|
| 0.2.1 (build 7) | Sept 2026 | Current beta. Same as 0.2.0 without the unused microphone, audio-settings and draw-over-other-apps permissions. |
| 0.2.0 (build 6) | Sept 2026 | Relay-only delivery, signed requests, push, photos, safety numbers, forward secrecy, encrypted storage, app lock, message actions. |
| v0.0.14 and earlier | Mar to Apr 2026 | First prototype. **Obsolete**; cannot connect. |

---

*MESH Protocol is an independent project built by one developer.*
*© 2026 Mohamed Abdellah · meshprotocol.ru*
