import { getSodium } from "./sodium";
import { SecureRoomsCryptoError } from "./errors";
import { buildKeyWrapSigningInput } from "./encoding";

export const ROOM_KEY_BYTES = 32;
export const SEALED_ROOM_KEY_BYTES = 32 + 48; // crypto_box_seal overhead
export const SIGNATURE_BYTES = 64;

export async function createRoomKey(): Promise<Uint8Array> {
  const s = await getSodium();
  return s.randombytes_buf(ROOM_KEY_BYTES);
}

export interface SealRoomKeyParams {
  roomKey: Uint8Array;
  roomId: string;
  epoch: number;
  recipientId: string;
  recipientX25519PublicKey: Uint8Array;
  signerEd25519PrivateKey: Uint8Array;
}

export interface SealedRoomKey {
  sealedKey: Uint8Array;
  /** Over lp(room_id) | epoch | lp(recipient_id) | sealed_key */
  signature: Uint8Array;
}

/** crypto_box_seal + Ed25519 over the keywrap tuple. */
export async function sealRoomKeyFor(params: SealRoomKeyParams): Promise<SealedRoomKey> {
  const s = await getSodium();
  if (params.roomKey.length !== ROOM_KEY_BYTES) {
    throw new SecureRoomsCryptoError("INVALID_INPUT", "roomKey must be 32 bytes");
  }
  const sealedKey = s.crypto_box_seal(params.roomKey, params.recipientX25519PublicKey);
  const signature = s.crypto_sign_detached(
    buildKeyWrapSigningInput(params.roomId, params.epoch, params.recipientId, sealedKey),
    params.signerEd25519PrivateKey,
  );
  return { sealedKey, signature };
}

export interface OpenRoomKeyParams {
  sealedKey: Uint8Array;
  signature: Uint8Array;
  roomId: string;
  epoch: number;
  /** Must match the recipient id used at seal time. */
  recipientId: string;
  /** Who sealed the key. */
  signerEd25519PublicKey: Uint8Array;
  recipientX25519PrivateKey: Uint8Array;
}

/** Verify wrapper sig, then unseal. BAD_SIGNATURE / DECRYPT_FAILED. */
export async function openRoomKey(params: OpenRoomKeyParams): Promise<Uint8Array> {
  const s = await getSodium();
  const valid = s.crypto_sign_verify_detached(
    params.signature,
    buildKeyWrapSigningInput(params.roomId, params.epoch, params.recipientId, params.sealedKey),
    params.signerEd25519PublicKey,
  );
  if (!valid) {
    throw new SecureRoomsCryptoError(
      "BAD_SIGNATURE",
      "room key wrapper signature does not verify (possible key substitution)",
    );
  }
  const publicKey = s.crypto_scalarmult_base(params.recipientX25519PrivateKey);
  try {
    return s.crypto_box_seal_open(params.sealedKey, publicKey, params.recipientX25519PrivateKey);
  } catch {
    throw new SecureRoomsCryptoError(
      "DECRYPT_FAILED",
      "sealed room key does not open with this private key",
    );
  }
}
