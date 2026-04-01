# MESH Protocol

**Encrypted messaging on the Stellar blockchain.**
No phone number. No email. No central server. No identity required.

🌐 [meshprotocol.ru](https://meshprotocol.ru) · 📧 contact@meshprotocol.ru

---

## What is MESH?

MESH is a decentralized, end-to-end encrypted messaging app. Every message is encrypted on your device before it leaves, stored on IPFS, and delivered via a Stellar blockchain transaction. No company, government, or server operator can read your messages — not even us.

Your identity is a 12-word recovery phrase. That is all. No account. No verification. No data collected.

---

## How it works

```
Sender                          Recipient
──────                          ─────────
1. Encrypt message (NaCl)
2. Upload encrypted blob → IPFS
3. Send Stellar transaction (pointer in memo)
4. Notify relay server
                                5. Check relay for pending
                                6. Fetch blob from IPFS
                                7. Decrypt with private key
                                8. Message appears
```

The relay server only ever handles encrypted pointers — never message content.

---

## Features — Testnet v0.0.14

| Feature | Status |
|---------|--------|
| End-to-end encrypted messaging | ✅ Working |
| @username search and discovery | ✅ Working |
| Message request inbox | ✅ Working |
| Send XLM directly in chat | ✅ Working |
| BIP39 12-word recovery phrase | ✅ Working |
| Change username from Settings | ✅ Working |
| Chat background (photo or color) | ✅ Working |
| Accent color themes | ✅ Working |
| Push notifications | 🔲 Coming soon |
| Voice notes | 🔲 Coming soon |
| Image sharing | 🔲 Coming soon |
| Profile pictures | 🔲 Coming soon |
| iOS app | 🔲 Coming soon |

---

## Download

### Testnet (pre-release)

> ⚠️ This is a testnet build. Stellar Testnet XLM only — no real funds involved.

**[⬇ Download MESH v0.0.14 — Android APK](https://github.com/Mohamed9522/mesh-protocol-public/releases/tag/v0.0.14)**

Android only. Free. No account required to download.

### Mainnet

Coming soon. Follow this repo for updates.

---

## Getting Started — Step by Step

### Step 1 — Install the APK

1. Download the APK from the link above
2. On your Android device go to **Settings → Security**
3. Enable **"Install from unknown sources"** (or "Install unknown apps")
4. Open the downloaded APK file and tap Install

---

### Step 2 — Create your account

When you open MESH for the first time you will see a 12-word recovery phrase.

**Write these 12 words down. Store them somewhere safe.**

This phrase IS your account. It generates your Stellar address and encryption keys. If you lose it, your account cannot be recovered — by you or by anyone else. MESH never stores it.

Tap **Continue** after saving your phrase.

---

### Step 3 — Choose your username

Pick an `@username`. This is how other people find you on MESH. Rules:
- 3 to 20 characters
- Letters, numbers, underscores only
- No spaces

You can change your username later in Settings if it is available.

Tap **Set Username** to continue.

---

### Step 4 — Activate your testnet wallet

Your Stellar address was just generated. Before you can send messages, your address needs to exist on the Stellar testnet network. This is a one-time step — it takes 10 seconds.

1. On your phone or any browser, open this link and replace `YOUR_ADDRESS` with your Stellar address:

```
https://friendbot.stellar.org/?addr=YOUR_ADDRESS
```

2. You can find your Stellar address by tapping the **M logo** in the top left of the chat list screen.

3. The page will return a JSON response saying success. Your wallet now has 10,000 testnet XLM — enough to send hundreds of thousands of messages.

---

### Step 5 — Find someone and start chatting

1. Tap the **⋮ menu** in the top right of the chat list
2. Tap **Add Contact**
3. Search for someone by their `@username`
4. Open their profile and send a message

If someone sends you a message first and you have not added them, it will appear in **Message Requests** (also in the ⋮ menu). You can accept or delete it.

---

### Step 6 — Send XLM (optional)

Inside any chat, tap the contact's name at the top to open their profile. You will see a **Send XLM** button. Enter an amount and confirm. The transfer happens instantly on the Stellar testnet.

---

## Tech Stack

| Component | Technology |
|-----------|-----------|
| Mobile app | React Native / Expo (Android) |
| Encryption | NaCl box — Curve25519 + XSalsa20 + Poly1305 |
| Message storage | IPFS via Pinata |
| Delivery layer | Stellar blockchain |
| Identity | BIP39 mnemonic → Stellar + NaCl keypair |
| Relay server | Node.js / Fastify / SQLite |
| Local storage | Expo SQLite + SecureStore |

---

## Roadmap

### Now — Testnet
Working app. Real encryption. Real Stellar transactions. Open for community testing.

### Next — Mainnet
- Move to Stellar mainnet (real XLM)
- Profile pictures
- Auto-update system
- Stable public APK on meshprotocol.ru

### Milestone 3 — seeking $15,000
- Voice notes
- Image and file sharing
- Push notifications
- Relay federation across multiple countries

### Milestone 4 — seeking $50,000
- iOS app
- Windows and macOS desktop
- Video calls
- Group chats
- Open developer API

---

## Privacy and Security

- Messages are encrypted **on your device** before they leave
- The relay server never sees plaintext — only encrypted pointers
- MESH collects no personal data — no name, no email, no phone number
- Your keys never leave your device
- Full privacy policy: [meshprotocol.ru/privacy.html](https://meshprotocol.ru/privacy.html)

---

## Frequently Asked Questions

**Do I need to pay anything?**
No. The app is free. Each message costs 0.00001 XLM (about $0.000003). On testnet, XLM is free from Friendbot.

**What if I lose my phone?**
Install MESH on a new device and enter your 12-word recovery phrase. Your account and keys are restored instantly. Your message history is stored locally so new messages will arrive but old ones are gone.

**Can MESH read my messages?**
No. Technically impossible. Messages are encrypted with your keys before leaving your device. We never have your private key.

**Is the source code open?**
The source code is currently private. It will be made public at v0.0.1 mainnet launch. The protocol architecture is fully documented above.

**Where is the relay server?**
The relay server runs on a VPS in Russia. It stores only your Stellar public address, NaCl public key, and username — all public by design. Message content is never stored on the relay.

---

## Contact and Community

- Website: [meshprotocol.ru](https://meshprotocol.ru)
- Talk to us: [meshprotocol.ru/community.html](https://meshprotocol.ru/community.html)
- Email: contact@meshprotocol.ru
- Support: support@meshprotocol.ru

---

## Build History

| Version | Date | Network | Changes |
|---------|------|---------|---------|
| v0.0.14 | 2026-04-02 | Testnet | Wallpaper, accent color, change username, settings overhaul |
| v0.0.13 | 2026-03-31 | Testnet | Accept request fix, attachment sheet, mic button redesign |
| v0.0.12 | 2026-03-30 | Testnet | Input bar, Settings screen, accept bug fix |
| v0.0.11 | 2026-03-29 | Testnet | Message requests, Welcome screen, username lookup |

---

*MESH Protocol is an independent project built by one developer.*
*© 2026 Mohamed Abdellah · meshprotocol.ru*
