import { getSodium } from "./sodium";
import { SecureRoomsCryptoError } from "./errors";
import { concat, toHex } from "./encoding";

export const X25519_PUBLIC_KEY_BYTES = 32;
export const X25519_PRIVATE_KEY_BYTES = 32;
export const ED25519_PUBLIC_KEY_BYTES = 32;
export const ED25519_PRIVATE_KEY_BYTES = 64; // seed || public
export const FINGERPRINT_BYTES = 16;

export interface IdentityKeyPair {
  x25519PublicKey: Uint8Array;
  x25519PrivateKey: Uint8Array;
  ed25519PublicKey: Uint8Array;
  ed25519PrivateKey: Uint8Array;
}

export function validateIdentity(identity: IdentityKeyPair): void {
  const checks: Array<[Uint8Array, number, string]> = [
    [identity.x25519PublicKey, X25519_PUBLIC_KEY_BYTES, "x25519PublicKey"],
    [identity.x25519PrivateKey, X25519_PRIVATE_KEY_BYTES, "x25519PrivateKey"],
    [identity.ed25519PublicKey, ED25519_PUBLIC_KEY_BYTES, "ed25519PublicKey"],
    [identity.ed25519PrivateKey, ED25519_PRIVATE_KEY_BYTES, "ed25519PrivateKey"],
  ];
  for (const [value, expected, name] of checks) {
    if (!(value instanceof Uint8Array) || value.length !== expected) {
      throw new SecureRoomsCryptoError(
        "INVALID_INPUT",
        `${name} must be a ${expected}-byte Uint8Array`,
      );
    }
  }
}

export async function generateIdentity(): Promise<IdentityKeyPair> {
  const s = await getSodium();
  const box = s.crypto_box_keypair();
  const sign = s.crypto_sign_keypair();
  return {
    x25519PublicKey: box.publicKey,
    x25519PrivateKey: box.privateKey,
    ed25519PublicKey: sign.publicKey,
    ed25519PrivateKey: sign.privateKey,
  };
}

/** BLAKE2b-128 safety number: uppercase hex, groups of 4. */
export async function fingerprint(
  x25519PublicKey: Uint8Array,
  ed25519PublicKey: Uint8Array,
): Promise<string> {
  if (x25519PublicKey.length !== X25519_PUBLIC_KEY_BYTES) {
    throw new SecureRoomsCryptoError("INVALID_INPUT", "x25519PublicKey must be 32 bytes");
  }
  if (ed25519PublicKey.length !== ED25519_PUBLIC_KEY_BYTES) {
    throw new SecureRoomsCryptoError("INVALID_INPUT", "ed25519PublicKey must be 32 bytes");
  }
  const s = await getSodium();
  const hash = s.crypto_generichash(
    FINGERPRINT_BYTES,
    concat(x25519PublicKey, ed25519PublicKey),
    null,
  );
  const hex = toHex(hash).toUpperCase();
  return (hex.match(/.{4}/g) ?? []).join(" ");
}
