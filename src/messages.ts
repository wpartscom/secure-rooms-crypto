import { getSodium } from "./sodium";
import { SecureRoomsCryptoError } from "./errors";
import { buildMessageAAD, utf8 } from "./encoding";
import { ROOM_KEY_BYTES } from "./room";

export const MESSAGE_NONCE_BYTES = 24;

export interface EncryptMessageParams {
  roomKey: Uint8Array;
  roomId: string;
  epoch: number;
  senderUserId: string;
  clientMsgId: string;
  /** App JSON or raw bytes. */
  plaintext: Uint8Array | string;
  signerEd25519PrivateKey: Uint8Array;
  /** Fixed nonce for tests only. */
  nonce?: Uint8Array;
}

export interface EncryptedMessage {
  ciphertext: Uint8Array;
  nonce: Uint8Array;
  signature: Uint8Array;
}

/** XChaCha20-Poly1305 under RK + Ed25519 over ciphertext. */
export async function encryptMessage(params: EncryptMessageParams): Promise<EncryptedMessage> {
  const s = await getSodium();
  if (params.roomKey.length !== ROOM_KEY_BYTES) {
    throw new SecureRoomsCryptoError("INVALID_INPUT", "roomKey must be 32 bytes");
  }
  const plaintext =
    typeof params.plaintext === "string" ? utf8(params.plaintext) : params.plaintext;
  const aad = buildMessageAAD(
    params.roomId,
    params.epoch,
    params.senderUserId,
    params.clientMsgId,
  );
  const nonce =
    params.nonce ?? s.randombytes_buf(s.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);
  if (nonce.length !== MESSAGE_NONCE_BYTES) {
    throw new SecureRoomsCryptoError("INVALID_INPUT", "nonce must be 24 bytes");
  }
  const ciphertext = s.crypto_aead_xchacha20poly1305_ietf_encrypt(
    plaintext,
    aad,
    null,
    nonce,
    params.roomKey,
  );
  const signature = s.crypto_sign_detached(ciphertext, params.signerEd25519PrivateKey);
  return { ciphertext, nonce, signature };
}

export interface DecryptMessageParams {
  roomKey: Uint8Array;
  roomId: string;
  epoch: number;
  senderUserId: string;
  clientMsgId: string;
  ciphertext: Uint8Array;
  nonce: Uint8Array;
  signature: Uint8Array;
  signerEd25519PublicKey: Uint8Array;
}

/** Verify sender sig, then decrypt with the same AAD. */
export async function decryptMessage(params: DecryptMessageParams): Promise<Uint8Array> {
  const s = await getSodium();
  const valid = s.crypto_sign_verify_detached(
    params.signature,
    params.ciphertext,
    params.signerEd25519PublicKey,
  );
  if (!valid) {
    throw new SecureRoomsCryptoError(
      "BAD_SIGNATURE",
      "message signature does not verify against the sender's pinned public key",
    );
  }
  const aad = buildMessageAAD(
    params.roomId,
    params.epoch,
    params.senderUserId,
    params.clientMsgId,
  );
  try {
    return s.crypto_aead_xchacha20poly1305_ietf_decrypt(
      null,
      params.ciphertext,
      aad,
      params.nonce,
      params.roomKey,
    );
  } catch {
    throw new SecureRoomsCryptoError(
      "DECRYPT_FAILED",
      "message authentication failed (wrong key, tampered ciphertext or AAD mismatch)",
    );
  }
}
