'use strict';

// Stellar "G..." addresses (StrKey): base32( version byte + 32-byte ed25519 key + CRC16 ).
// Implemented here so the relay needs no Stellar SDK just to check a signature.

const ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
const VERSION_ED25519_PUBLIC = 6 << 3; // gives the leading "G"

function crc16xmodem(bytes) {
  let crc = 0;
  for (const byte of bytes) {
    crc ^= byte << 8;
    for (let i = 0; i < 8; i++) {
      crc = crc & 0x8000 ? ((crc << 1) ^ 0x1021) & 0xffff : (crc << 1) & 0xffff;
    }
  }
  return crc;
}

function base32Decode(str) {
  const out = [];
  let value = 0;
  let bits = 0;
  for (const ch of str) {
    const idx = ALPHABET.indexOf(ch);
    if (idx === -1) return null;
    value = (value << 5) | idx;
    bits += 5;
    if (bits >= 8) {
      out.push((value >>> (bits - 8)) & 0xff);
      bits -= 8;
      value &= (1 << bits) - 1;
    }
  }
  return Buffer.from(out);
}

function base32Encode(buf) {
  let out = '';
  let value = 0;
  let bits = 0;
  for (const byte of buf) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      out += ALPHABET[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
    value &= (1 << bits) - 1;
  }
  if (bits > 0) out += ALPHABET[(value << (5 - bits)) & 31];
  return out;
}

/** Returns the raw 32-byte public key, or null if the address is malformed or its checksum is wrong. */
function decodeStellarPublicKey(address) {
  if (typeof address !== 'string' || !/^G[A-Z2-7]{55}$/.test(address)) return null;
  const raw = base32Decode(address);
  if (!raw || raw.length !== 35 || raw[0] !== VERSION_ED25519_PUBLIC) return null;
  if (crc16xmodem(raw.subarray(0, 33)) !== raw.readUInt16LE(33)) return null;
  return Buffer.from(raw.subarray(1, 33));
}

function encodeStellarPublicKey(key32) {
  const payload = Buffer.concat([Buffer.from([VERSION_ED25519_PUBLIC]), key32]);
  const checksum = Buffer.alloc(2);
  checksum.writeUInt16LE(crc16xmodem(payload));
  return base32Encode(Buffer.concat([payload, checksum]));
}

module.exports = { decodeStellarPublicKey, encodeStellarPublicKey };
