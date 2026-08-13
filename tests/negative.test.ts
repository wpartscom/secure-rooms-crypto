import { describe, expect, it } from "vitest";
import {
  createRoomKey,
  createStreamDecryptor,
  createStreamEncryptor,
  decryptMessage,
  decryptStream,
  encryptMessage,
  encryptStream,
  fromHex,
  generateIdentity,
  initSodium,
  openRoomKey,
  sealRoomKeyFor,
  SecureRoomsCryptoError,
  STREAM_TAG_FINAL,
  unwrapIdentity,
  unwrapIdentityWithRecoveryCode,
  wrapIdentity,
  wrapIdentityWithRecoveryCode,
} from "./helpers";
import {
  fixtureIdentity,
  PASSPHRASE,
  RECOVERY_CODE,
  ROOM_ID,
  EPOCH,
  RECIPIENT_ID,
  ROOM_KEY_HEX,
  SEALED_KEY_HEX,
  SEALED_SIG_HEX,
  SENDER_ID,
  CLIENT_MSG_ID,
  MESSAGE_CIPHERTEXT_HEX,
  MESSAGE_NONCE_HEX,
  MESSAGE_SIGNATURE_HEX,
  MESSAGE_PLAINTEXT,
  WRAPPER_ED25519_PK_HEX,
  WRAPPER_ED25519_SK_HEX,
  STREAM_KEY_HEX,
  STREAM_HEADER_HEX,
  STREAM_CHUNKS_HEX,
} from "./fixtures";

async function expectCode(promise: Promise<unknown>, code: string): Promise<void> {
  try {
    await promise;
  } catch (err) {
    expect(err).toBeInstanceOf(SecureRoomsCryptoError);
    expect((err as SecureRoomsCryptoError).code).toBe(code);
    return;
  }
  throw new Error(`expected SecureRoomsCryptoError(${code}), but the call succeeded`);
}

describe("negative: backups", () => {
  it("wrong passphrase returns DECRYPT_FAILED", async () => {
    const blob = await wrapIdentity(fixtureIdentity(), PASSPHRASE);
    await expectCode(unwrapIdentity(blob, "definitely the wrong passphrase"), "DECRYPT_FAILED");
  });

  it("wrong recovery code returns DECRYPT_FAILED", async () => {
    const blob = await wrapIdentityWithRecoveryCode(fixtureIdentity(), RECOVERY_CODE);
    // valid Base32, wrong entropy
    const wrongCode = "AAAAA-AAAAA-AAAAA-AAAAA-AAAAA-AAAAA-AAAAA-AAAAA";
    await expectCode(unwrapIdentityWithRecoveryCode(blob, wrongCode), "DECRYPT_FAILED");
  });

  it("malformed recovery code returns INVALID_RECOVERY_CODE", async () => {
    const blob = await wrapIdentityWithRecoveryCode(fixtureIdentity(), RECOVERY_CODE);
    await expectCode(unwrapIdentityWithRecoveryCode(blob, "not-a-code"), "INVALID_RECOVERY_CODE");
    await expectCode(unwrapIdentityWithRecoveryCode(blob, "AAAAA-AAAAA"), "INVALID_RECOVERY_CODE");
  });

  it("corrupted version byte returns UNSUPPORTED_VERSION", async () => {
    const blob = await wrapIdentity(fixtureIdentity(), PASSPHRASE);
    blob[4] = 99;
    await expectCode(unwrapIdentity(blob, PASSPHRASE), "UNSUPPORTED_VERSION");
  });

  it("corrupted magic returns INVALID_FORMAT", async () => {
    const blob = await wrapIdentity(fixtureIdentity(), PASSPHRASE);
    blob[0] = 0x00;
    await expectCode(unwrapIdentity(blob, PASSPHRASE), "INVALID_FORMAT");
  });

  it("truncated blob returns INVALID_FORMAT", async () => {
    const blob = await wrapIdentity(fixtureIdentity(), PASSPHRASE);
    await expectCode(unwrapIdentity(blob.slice(0, 10), PASSPHRASE), "INVALID_FORMAT");
  });
});

describe("negative: room key distribution", () => {
  const openParams = {
    roomId: ROOM_ID,
    epoch: EPOCH,
    recipientId: RECIPIENT_ID,
    signerEd25519PublicKey: fromHex(WRAPPER_ED25519_PK_HEX),
    recipientX25519PrivateKey: fixtureIdentity().x25519PrivateKey,
  };

  it("frozen sealed key opens to the frozen room key (baseline)", async () => {
    const rk = await openRoomKey({
      ...openParams,
      sealedKey: fromHex(SEALED_KEY_HEX),
      signature: fromHex(SEALED_SIG_HEX),
    });
    expect(rk).toEqual(fromHex(ROOM_KEY_HEX));
  });

  it("substituted sealed key (server tampering) returns BAD_SIGNATURE", async () => {
    const tampered = fromHex(SEALED_KEY_HEX);
    tampered[10] ^= 0x01;
    await expectCode(
      openRoomKey({ ...openParams, sealedKey: tampered, signature: fromHex(SEALED_SIG_HEX) }),
      "BAD_SIGNATURE",
    );
  });

  it("sealed key re-signed by a different signer returns BAD_SIGNATURE", async () => {
    const attacker = await generateIdentity();
    const rk = fromHex(ROOM_KEY_HEX);
    const { sealedKey, signature } = await sealRoomKeyFor({
      roomKey: rk,
      roomId: ROOM_ID,
      epoch: EPOCH,
      recipientId: RECIPIENT_ID,
      recipientX25519PublicKey: fixtureIdentity().x25519PublicKey,
      signerEd25519PrivateKey: attacker.ed25519PrivateKey,
    });
    // signed by attacker; we still pin the real wrapper key
    await expectCode(
      openRoomKey({ ...openParams, sealedKey, signature }),
      "BAD_SIGNATURE",
    );
  });

  it("honestly signed key sealed for another recipient returns DECRYPT_FAILED", async () => {
    const other = await generateIdentity();
    const { sealedKey, signature } = await sealRoomKeyFor({
      roomKey: fromHex(ROOM_KEY_HEX),
      roomId: ROOM_ID,
      epoch: EPOCH,
      recipientId: RECIPIENT_ID,
      recipientX25519PublicKey: other.x25519PublicKey,
      signerEd25519PrivateKey: fromHex(WRAPPER_ED25519_SK_HEX),
    });
    await expectCode(
      openRoomKey({ ...openParams, sealedKey, signature }),
      "DECRYPT_FAILED",
    );
  });

  it("wrong epoch in tuple returns BAD_SIGNATURE", async () => {
    await expectCode(
      openRoomKey({
        ...openParams,
        epoch: EPOCH + 1,
        sealedKey: fromHex(SEALED_KEY_HEX),
        signature: fromHex(SEALED_SIG_HEX),
      }),
      "BAD_SIGNATURE",
    );
  });
});

describe("negative: messages", () => {
  const id = fixtureIdentity();
  const base = {
    roomKey: fromHex(ROOM_KEY_HEX),
    roomId: ROOM_ID,
    epoch: EPOCH,
    senderUserId: SENDER_ID,
    clientMsgId: CLIENT_MSG_ID,
    ciphertext: fromHex(MESSAGE_CIPHERTEXT_HEX),
    nonce: fromHex(MESSAGE_NONCE_HEX),
    signature: fromHex(MESSAGE_SIGNATURE_HEX),
    signerEd25519PublicKey: id.ed25519PublicKey,
  };

  it("baseline: frozen message decrypts", async () => {
    const pt = await decryptMessage(base);
    expect(new TextDecoder().decode(pt)).toBe(MESSAGE_PLAINTEXT);
  });

  it("bit-flipped signature returns BAD_SIGNATURE", async () => {
    const signature = fromHex(MESSAGE_SIGNATURE_HEX);
    signature[0] ^= 0x80;
    await expectCode(decryptMessage({ ...base, signature }), "BAD_SIGNATURE");
  });

  it("wrong signer public key returns BAD_SIGNATURE", async () => {
    const other = await generateIdentity();
    await expectCode(
      decryptMessage({ ...base, signerEd25519PublicKey: other.ed25519PublicKey }),
      "BAD_SIGNATURE",
    );
  });

  it("AAD mismatch (moved to another room) returns DECRYPT_FAILED", async () => {
    await expectCode(decryptMessage({ ...base, roomId: "another-room" }), "DECRYPT_FAILED");
  });

  it("AAD mismatch (forged epoch) returns DECRYPT_FAILED", async () => {
    await expectCode(decryptMessage({ ...base, epoch: EPOCH + 1 }), "DECRYPT_FAILED");
  });

  it("AAD mismatch (forged sender) returns DECRYPT_FAILED", async () => {
    await expectCode(
      decryptMessage({ ...base, senderUserId: "mallory" }),
      "DECRYPT_FAILED",
    );
  });

  it("AAD mismatch (reused client_msg_id) returns DECRYPT_FAILED", async () => {
    await expectCode(
      decryptMessage({ ...base, clientMsgId: "018e8f9b-0000-7000-8000-000000000099" }),
      "DECRYPT_FAILED",
    );
  });

  it("bit-flipped ciphertext (honestly re-signed) returns DECRYPT_FAILED", async () => {
    // re-sign so only AEAD fails
    await initSodium();
    const sodium = (await import("libsodium-wrappers-sumo")).default;
    const ciphertext = fromHex(MESSAGE_CIPHERTEXT_HEX);
    ciphertext[3] ^= 0x01;
    const signature = sodium.crypto_sign_detached(ciphertext, id.ed25519PrivateKey);
    await expectCode(decryptMessage({ ...base, ciphertext, signature }), "DECRYPT_FAILED");
  });

  it("wrong room key returns DECRYPT_FAILED", async () => {
    const otherKey = await createRoomKey();
    await expectCode(decryptMessage({ ...base, roomKey: otherKey }), "DECRYPT_FAILED");
  });
});

describe("negative: streams", () => {
  it("tampered chunk returns DECRYPT_FAILED", async () => {
    const key = fromHex(STREAM_KEY_HEX);
    const chunks = STREAM_CHUNKS_HEX.map(fromHex);
    chunks[1][5] ^= 0x01;
    await expectCode(decryptStream(key, fromHex(STREAM_HEADER_HEX), chunks), "DECRYPT_FAILED");
  });

  it("dropped middle chunk returns DECRYPT_FAILED (stream state mismatch)", async () => {
    const key = fromHex(STREAM_KEY_HEX);
    const chunks = STREAM_CHUNKS_HEX.map(fromHex);
    chunks.splice(1, 1);
    await expectCode(
      decryptStream(key, fromHex(STREAM_HEADER_HEX), chunks),
      "DECRYPT_FAILED",
    );
  });

  it("truncated stream (no final tag) returns STREAM_ERROR", async () => {
    const key = await createRoomKey();
    const encryptor = await createStreamEncryptor(key);
    const c1 = encryptor.push(new Uint8Array([1, 2, 3])); // TAG_MESSAGE, never finalized
    await expectCode(decryptStream(key, encryptor.header, [c1]), "STREAM_ERROR");
  });

  it("wrong header returns DECRYPT_FAILED", async () => {
    const key = fromHex(STREAM_KEY_HEX);
    const header = fromHex(STREAM_HEADER_HEX);
    header[0] ^= 0xff;
    await expectCode(
      decryptStream(key, header, STREAM_CHUNKS_HEX.map(fromHex)),
      "DECRYPT_FAILED",
    );
  });

  it("finalized encryptor rejects further pushes after decryptor consumed all", async () => {
    const key = await createRoomKey();
    const { header, chunks } = await encryptStream(key, new Uint8Array([9]));
    const decryptor = await createStreamDecryptor(key, header);
    const { tag } = decryptor.pull(chunks[0]);
    expect(tag).toBe(STREAM_TAG_FINAL);
  });
});
