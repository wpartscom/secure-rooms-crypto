import { describe, expect, it } from "vitest";
import {
  createRoomKey,
  createStreamDecryptor,
  createStreamEncryptor,
  decryptMessage,
  decryptStream,
  encryptMessage,
  encryptStream,
  generateIdentity,
  generateRecoveryCode,
  isSodiumReady,
  initSodium,
  LIB_BUILD_HASH,
  LIB_VERSION,
  openRoomKey,
  parseRecoveryCode,
  ROOM_KEY_BYTES,
  sealRoomKeyFor,
  STREAM_CHUNK_SIZE,
  STREAM_TAG_FINAL,
  toHex,
  unwrapIdentity,
  unwrapIdentityWithRecoveryCode,
  utf8RoundTripCheck,
  wrapIdentity,
  wrapIdentityWithRecoveryCode,
} from "./helpers";

describe("round-trip", () => {
  it("initSodium twice", async () => {
    await initSodium();
    await initSodium();
    expect(isSodiumReady()).toBe(true);
  });

  it("passphrase backup round-trip", async () => {
    const identity = await generateIdentity();
    const blob = await wrapIdentity(identity, "a long enough test passphrase");
    const restored = await unwrapIdentity(blob, "a long enough test passphrase");
    expect(toHex(restored.x25519PrivateKey)).toBe(toHex(identity.x25519PrivateKey));
    expect(toHex(restored.x25519PublicKey)).toBe(toHex(identity.x25519PublicKey));
    expect(toHex(restored.ed25519PrivateKey)).toBe(toHex(identity.ed25519PrivateKey));
    expect(toHex(restored.ed25519PublicKey)).toBe(toHex(identity.ed25519PublicKey));
  });

  it("recovery backup round-trip", async () => {
    const identity = await generateIdentity();
    const { code, bytes } = await generateRecoveryCode();
    expect(toHex(parseRecoveryCode(code))).toBe(toHex(bytes));
    const blob = await wrapIdentityWithRecoveryCode(identity, code);
    const restored = await unwrapIdentityWithRecoveryCode(blob, code);
    expect(toHex(restored.x25519PrivateKey)).toBe(toHex(identity.x25519PrivateKey));
    expect(toHex(restored.ed25519PrivateKey)).toBe(toHex(identity.ed25519PrivateKey));
    // unwrapIdentity also accepts recovery blobs
    const restored2 = await unwrapIdentity(blob, code);
    expect(toHex(restored2.x25519PrivateKey)).toBe(toHex(identity.x25519PrivateKey));
  });

  it("seal and open room key", async () => {
    const wrapper = await generateIdentity();
    const recipient = await generateIdentity();
    const roomKey = await createRoomKey();
    expect(roomKey.length).toBe(ROOM_KEY_BYTES);

    const { sealedKey, signature } = await sealRoomKeyFor({
      roomKey,
      roomId: "018e8f9a-0000-7000-8000-0000000000aa",
      epoch: 3,
      recipientId: "user-recipient",
      recipientX25519PublicKey: recipient.x25519PublicKey,
      signerEd25519PrivateKey: wrapper.ed25519PrivateKey,
    });
    const opened = await openRoomKey({
      sealedKey,
      signature,
      roomId: "018e8f9a-0000-7000-8000-0000000000aa",
      epoch: 3,
      recipientId: "user-recipient",
      signerEd25519PublicKey: wrapper.ed25519PublicKey,
      recipientX25519PrivateKey: recipient.x25519PrivateKey,
    });
    expect(toHex(opened)).toBe(toHex(roomKey));
  });

  it("encrypt and decrypt message", async () => {
    const sender = await generateIdentity();
    const roomKey = await createRoomKey();
    const params = {
      roomKey,
      roomId: "room-1",
      epoch: 1,
      senderUserId: "user-1",
      clientMsgId: "018e8f9b-0000-7000-8000-0000000000bb",
    };
    const enc = await encryptMessage({
      ...params,
      plaintext: "hello, secure room",
      signerEd25519PrivateKey: sender.ed25519PrivateKey,
    });
    const dec = await decryptMessage({
      ...params,
      ciphertext: enc.ciphertext,
      nonce: enc.nonce,
      signature: enc.signature,
      signerEd25519PublicKey: sender.ed25519PublicKey,
    });
    expect(utf8RoundTripCheck(dec)).toBe("hello, secure room");
  });

  it("stream: multi-chunk round-trip at the default 1 MiB chunk size", async () => {
    const key = await createRoomKey();
    const data = new Uint8Array(2.5 * STREAM_CHUNK_SIZE);
    for (let i = 0; i < data.length; i++) data[i] = (i * 31) & 0xff;
    const { header, chunks } = await encryptStream(key, data);
    expect(chunks.length).toBe(3);
    const restored = await decryptStream(key, header, chunks);
    expect(toHex(restored)).toBe(toHex(data));
  });

  it("stream: empty input round-trips as a single final chunk", async () => {
    const key = await createRoomKey();
    const { header, chunks } = await encryptStream(key, new Uint8Array(0));
    expect(chunks.length).toBe(1);
    const restored = await decryptStream(key, header, chunks);
    expect(restored.length).toBe(0);
  });

  it("stream: incremental encryptor/decryptor round-trip", async () => {
    const key = await createRoomKey();
    const encryptor = await createStreamEncryptor(key);
    const c1 = encryptor.push(new Uint8Array([1, 2, 3]));
    const c2 = encryptor.push(new Uint8Array([4, 5]), STREAM_TAG_FINAL);
    const decryptor = await createStreamDecryptor(key, encryptor.header);
    const p1 = decryptor.pull(c1);
    const p2 = decryptor.pull(c2);
    expect(Array.from(p1.plaintext)).toEqual([1, 2, 3]);
    expect(Array.from(p2.plaintext)).toEqual([4, 5]);
    expect(p2.tag).toBe(STREAM_TAG_FINAL);
  });

  it("version constants are exposed", () => {
    expect(LIB_VERSION).toBe("0.1.0");
    expect(typeof LIB_BUILD_HASH).toBe("string");
    expect(LIB_BUILD_HASH.length).toBeGreaterThan(0);
  });
});
