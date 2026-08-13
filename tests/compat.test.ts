import { describe, expect, it } from "vitest";
import {
  decryptMessage,
  decryptStream,
  fromHex,
  openRoomKey,
  unwrapIdentity,
  unwrapIdentityWithRecoveryCode,
} from "./helpers";
import {
  BACKUP_PASSPHRASE_BLOB_HEX,
  BACKUP_RECOVERY_BLOB_HEX,
  CLIENT_MSG_ID,
  EPOCH,
  fixtureIdentity,
  MESSAGE_CIPHERTEXT_HEX,
  MESSAGE_NONCE_HEX,
  MESSAGE_PLAINTEXT,
  MESSAGE_SIGNATURE_HEX,
  PASSPHRASE,
  RECIPIENT_ID,
  RECOVERY_CODE,
  ROOM_ID,
  ROOM_KEY_HEX,
  SEALED_KEY_HEX,
  SEALED_SIG_HEX,
  SENDER_ID,
  STREAM_CHUNKS_HEX,
  STREAM_DATA_HEX,
  STREAM_HEADER_HEX,
  STREAM_KEY_HEX,
  WRAPPER_ED25519_PK_HEX,
} from "./fixtures";

// Frozen v1 blobs must keep working.
describe("format v1 backward compatibility", () => {
  it("decrypts a frozen v1 passphrase backup blob", async () => {
    const identity = await unwrapIdentity(fromHex(BACKUP_PASSPHRASE_BLOB_HEX), PASSPHRASE);
    const expected = fixtureIdentity();
    expect(identity.x25519PrivateKey).toEqual(expected.x25519PrivateKey);
    expect(identity.x25519PublicKey).toEqual(expected.x25519PublicKey);
    expect(identity.ed25519PrivateKey).toEqual(expected.ed25519PrivateKey);
    expect(identity.ed25519PublicKey).toEqual(expected.ed25519PublicKey);
  });

  it("decrypts a frozen v1 recovery backup blob", async () => {
    const identity = await unwrapIdentityWithRecoveryCode(
      fromHex(BACKUP_RECOVERY_BLOB_HEX),
      RECOVERY_CODE,
    );
    expect(identity.ed25519PrivateKey).toEqual(fixtureIdentity().ed25519PrivateKey);
  });

  it("opens a frozen v1 sealed room key", async () => {
    const roomKey = await openRoomKey({
      sealedKey: fromHex(SEALED_KEY_HEX),
      signature: fromHex(SEALED_SIG_HEX),
      roomId: ROOM_ID,
      epoch: EPOCH,
      recipientId: RECIPIENT_ID,
      signerEd25519PublicKey: fromHex(WRAPPER_ED25519_PK_HEX),
      recipientX25519PrivateKey: fixtureIdentity().x25519PrivateKey,
    });
    expect(roomKey).toEqual(fromHex(ROOM_KEY_HEX));
  });

  it("decrypts a frozen v1 message", async () => {
    const plaintext = await decryptMessage({
      roomKey: fromHex(ROOM_KEY_HEX),
      roomId: ROOM_ID,
      epoch: EPOCH,
      senderUserId: SENDER_ID,
      clientMsgId: CLIENT_MSG_ID,
      ciphertext: fromHex(MESSAGE_CIPHERTEXT_HEX),
      nonce: fromHex(MESSAGE_NONCE_HEX),
      signature: fromHex(MESSAGE_SIGNATURE_HEX),
      signerEd25519PublicKey: fixtureIdentity().ed25519PublicKey,
    });
    expect(new TextDecoder().decode(plaintext)).toBe(MESSAGE_PLAINTEXT);
  });

  it("decrypts a frozen v1 secretstream", async () => {
    const data = await decryptStream(
      fromHex(STREAM_KEY_HEX),
      fromHex(STREAM_HEADER_HEX),
      STREAM_CHUNKS_HEX.map(fromHex),
    );
    expect(data).toEqual(fromHex(STREAM_DATA_HEX));
  });
});
