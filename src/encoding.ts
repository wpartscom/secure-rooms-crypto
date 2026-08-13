import { SecureRoomsCryptoError } from "./errors";

// Encoding helpers (no sodium). Formats in SPEC.md.

const B64_ALPHABET =
  "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/** Base64 URL-safe, no padding. */
export function toBase64(bytes: Uint8Array): string {
  let out = "";
  for (let i = 0; i < bytes.length; i += 3) {
    const a = bytes[i];
    const b = i + 1 < bytes.length ? bytes[i + 1] : 0;
    const c = i + 2 < bytes.length ? bytes[i + 2] : 0;
    const n = (a << 16) | (b << 8) | c;
    out += B64_ALPHABET[(n >> 18) & 63];
    out += B64_ALPHABET[(n >> 12) & 63];
    out += i + 1 < bytes.length ? B64_ALPHABET[(n >> 6) & 63] : "=";
    out += i + 2 < bytes.length ? B64_ALPHABET[n & 63] : "=";
  }
  return out.replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/, "");
}

export function fromBase64(input: string): Uint8Array {
  let str = input.replaceAll("-", "+").replaceAll("_", "/");
  while (str.length % 4 !== 0) str += "=";
  if (!/^[A-Za-z0-9+/]*={0,2}$/.test(str)) {
    throw new SecureRoomsCryptoError("INVALID_FORMAT", "invalid base64 input");
  }
  const out: number[] = [];
  for (let i = 0; i < str.length; i += 4) {
    const c0 = B64_ALPHABET.indexOf(str[i]);
    const c1 = B64_ALPHABET.indexOf(str[i + 1]);
    const c2 = str[i + 2] === "=" ? 0 : B64_ALPHABET.indexOf(str[i + 2]);
    const c3 = str[i + 3] === "=" ? 0 : B64_ALPHABET.indexOf(str[i + 3]);
    const n = (c0 << 18) | (c1 << 12) | (c2 << 6) | c3;
    out.push((n >> 16) & 0xff);
    if (str[i + 2] !== "=") out.push((n >> 8) & 0xff);
    if (str[i + 3] !== "=") out.push(n & 0xff);
  }
  return new Uint8Array(out);
}

export function toHex(bytes: Uint8Array): string {
  let out = "";
  for (const b of bytes) out += b.toString(16).padStart(2, "0");
  return out;
}

export function fromHex(hex: string): Uint8Array {
  if (!/^[0-9a-fA-F]*$/.test(hex) || hex.length % 2 !== 0) {
    throw new SecureRoomsCryptoError("INVALID_FORMAT", "invalid hex input");
  }
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

const B32_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

export function base32Encode(bytes: Uint8Array): string {
  let bits = 0;
  let value = 0;
  let out = "";
  for (const byte of bytes) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      out += B32_ALPHABET[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) {
    out += B32_ALPHABET[(value << (5 - bits)) & 31];
  }
  return out;
}

export function base32Decode(str: string): Uint8Array {
  if (!/^[A-Z2-7]*$/.test(str)) {
    throw new SecureRoomsCryptoError("INVALID_FORMAT", "invalid base32 input");
  }
  let bits = 0;
  let value = 0;
  const out: number[] = [];
  for (const ch of str) {
    value = (value << 5) | B32_ALPHABET.indexOf(ch);
    bits += 5;
    if (bits >= 8) {
      out.push((value >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }
  return new Uint8Array(out);
}

export function u16le(n: number): Uint8Array {
  return new Uint8Array([n & 0xff, (n >> 8) & 0xff]);
}

export function u32le(n: number): Uint8Array {
  if (!Number.isInteger(n) || n < 0 || n > 0xffffffff) {
    throw new SecureRoomsCryptoError("INVALID_INPUT", "value does not fit u32");
  }
  return new Uint8Array([n & 0xff, (n >> 8) & 0xff, (n >> 16) & 0xff, (n >> 24) & 0xff]);
}

export function u64le(n: bigint): Uint8Array {
  const out = new Uint8Array(8);
  let v = n;
  for (let i = 0; i < 8; i++) {
    out[i] = Number(v & 0xffn);
    v >>= 8n;
  }
  return out;
}

export function readU64le(bytes: Uint8Array, offset: number): bigint {
  let v = 0n;
  for (let i = 7; i >= 0; i--) {
    v = (v << 8n) | BigInt(bytes[offset + i]);
  }
  return v;
}

const textEncoder = new TextEncoder();

export function utf8(s: string): Uint8Array {
  return textEncoder.encode(s);
}

export function concat(...arrays: Uint8Array[]): Uint8Array {
  let total = 0;
  for (const a of arrays) total += a.length;
  const out = new Uint8Array(total);
  let offset = 0;
  for (const a of arrays) {
    out.set(a, offset);
    offset += a.length;
  }
  return out;
}

export function lpString(s: string): Uint8Array {
  const bytes = utf8(s);
  if (bytes.length > 0xffff) {
    throw new SecureRoomsCryptoError("INVALID_INPUT", "string too long for u16 length prefix");
  }
  return concat(u16le(bytes.length), bytes);
}

export function buildKeyWrapSigningInput(
  roomId: string,
  epoch: number,
  recipientId: string,
  sealedKey: Uint8Array,
): Uint8Array {
  return concat(lpString(roomId), u32le(epoch), lpString(recipientId), sealedKey);
}

export function buildMessageAAD(
  roomId: string,
  epoch: number,
  senderUserId: string,
  clientMsgId: string,
): Uint8Array {
  return concat(
    lpString(roomId),
    u32le(epoch),
    lpString(senderUserId),
    lpString(clientMsgId),
  );
}
