import { describe, expect, it } from "vitest";
import {
  base32Decode,
  base32Encode,
  buildKeyWrapSigningInput,
  buildMessageAAD,
  deriveMasterKey,
  deriveRecoveryKey,
  encryptMessage,
  fingerprint,
  formatRecoveryCode,
  fromBase64,
  fromHex,
  parseRecoveryCode,
  toBase64,
  toHex,
  wrapIdentity,
  wrapIdentityWithRecoveryCode,
} from "../src/index";
import {
  BACKUP_PASSPHRASE_BLOB_HEX,
  BACKUP_RECOVERY_BLOB_HEX,
  CLIENT_MSG_ID,
  EPOCH,
  FINGERPRINT,
  fixtureIdentity,
  KEYWRAP_TUPLE_HEX,
  MASTER_KEY_HEX,
  MESSAGE_AAD_HEX,
  MESSAGE_CIPHERTEXT_HEX,
  MESSAGE_NONCE_HEX,
  MESSAGE_PLAINTEXT,
  MESSAGE_SIGNATURE_HEX,
  PASSPHRASE,
  RECIPIENT_ID,
  RECOVERY_BYTES_HEX,
  RECOVERY_CODE,
  RECOVERY_KEY_HEX,
  ROOM_ID,
  ROOM_KEY_HEX,
  SALT_HEX,
  SEALED_KEY_HEX,
  SENDER_ID,
} from "./fixtures";

// Fixed inputs must match frozen outputs.
describe("known-answer vectors", () => {
  it("deriveMasterKey: Argon2id(passphrase, salt, MODERATE) matches vector", async () => {
    const mk = await deriveMasterKey(PASSPHRASE, fromHex(SALT_HEX));
    expect(toHex(mk)).toBe(MASTER_KEY_HEX);
  });

  it("fingerprint: BLAKE2b-128 of public keys, groups of 4", async () => {
    const id = fixtureIdentity();
    const fp = await fingerprint(id.x25519PublicKey, id.ed25519PublicKey);
    expect(fp).toBe(FINGERPRINT);
    expect(fp).toMatch(/^([0-9A-F]{4} ){7}[0-9A-F]{4}$/);
  });

  it("recovery code: Base32 8 groups x 5 of the 25 code bytes", () => {
    expect(formatRecoveryCode(fromHex(RECOVERY_BYTES_HEX))).toBe(RECOVERY_CODE);
    expect(toHex(parseRecoveryCode(RECOVERY_CODE))).toBe(RECOVERY_BYTES_HEX);
    // lowercase / no hyphens ok
    expect(toHex(parseRecoveryCode(RECOVERY_CODE.replaceAll("-", "").toLowerCase()))).toBe(
      RECOVERY_BYTES_HEX,
    );
  });

  it("recovery key: crypto_kdf_derive_from_key chain matches vector", async () => {
    const key = await deriveRecoveryKey(fromHex(RECOVERY_BYTES_HEX));
    expect(toHex(key)).toBe(RECOVERY_KEY_HEX);
  });

  it("message AAD framing matches vector", () => {
    const aad = buildMessageAAD(ROOM_ID, EPOCH, SENDER_ID, CLIENT_MSG_ID);
    expect(toHex(aad)).toBe(MESSAGE_AAD_HEX);
  });

  it("key-wrap signing tuple framing matches vector", () => {
    const tuple = buildKeyWrapSigningInput(ROOM_ID, EPOCH, RECIPIENT_ID, fromHex(SEALED_KEY_HEX));
    expect(toHex(tuple)).toBe(KEYWRAP_TUPLE_HEX);
  });

  it("encryptMessage with fixed nonce reproduces ciphertext and signature", async () => {
    const id = fixtureIdentity();
    const enc = await encryptMessage({
      roomKey: fromHex(ROOM_KEY_HEX),
      roomId: ROOM_ID,
      epoch: EPOCH,
      senderUserId: SENDER_ID,
      clientMsgId: CLIENT_MSG_ID,
      plaintext: MESSAGE_PLAINTEXT,
      signerEd25519PrivateKey: id.ed25519PrivateKey,
      nonce: fromHex(MESSAGE_NONCE_HEX),
    });
    expect(toHex(enc.ciphertext)).toBe(MESSAGE_CIPHERTEXT_HEX);
    expect(toHex(enc.signature)).toBe(MESSAGE_SIGNATURE_HEX);
    expect(toHex(enc.nonce)).toBe(MESSAGE_NONCE_HEX);
  });

  it("wrapIdentity with fixed salt+nonce reproduces the passphrase blob", async () => {
    const blob = await wrapIdentity(fixtureIdentity(), PASSPHRASE, {
      salt: fromHex(SALT_HEX),
      nonce: fromHex("202122232425262728292a2b2c2d2e2f3031323334353637"),
    });
    expect(toHex(blob)).toBe(BACKUP_PASSPHRASE_BLOB_HEX);
  });

  it("wrapIdentityWithRecoveryCode with fixed nonce reproduces the recovery blob", async () => {
    const blob = await wrapIdentityWithRecoveryCode(fixtureIdentity(), RECOVERY_CODE, {
      nonce: fromHex("505152535455565758595a5b5c5d5e5f6061626364656667"),
    });
    expect(toHex(blob)).toBe(BACKUP_RECOVERY_BLOB_HEX);
  });
});

describe("encoding helpers", () => {
  it("base64 url-safe round-trip, no padding", () => {
    const bytes = fromHex("000102fffefd");
    const b64 = toBase64(bytes);
    expect(b64).not.toMatch(/[+/=]/);
    expect(toHex(fromBase64(b64))).toBe("000102fffefd");
  });

  it("base32 RFC4648 test vectors", () => {
    expect(base32Encode(new Uint8Array(0))).toBe("");
    expect(base32Encode(new TextEncoder().encode("f"))).toBe("MY");
    expect(base32Encode(new TextEncoder().encode("fo"))).toBe("MZXQ");
    expect(base32Encode(new TextEncoder().encode("foo"))).toBe("MZXW6");
    expect(base32Encode(new TextEncoder().encode("foob"))).toBe("MZXW6YQ");
    expect(base32Encode(new TextEncoder().encode("fooba"))).toBe("MZXW6YTB");
    expect(base32Encode(new TextEncoder().encode("foobar"))).toBe("MZXW6YTBOI");
    expect(new TextDecoder().decode(base32Decode("MZXW6YTBOI"))).toBe("foobar");
  });
});
