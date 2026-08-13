import { getSodium } from "./sodium";
import { SecureRoomsCryptoError } from "./errors";

export const MASTER_KEY_BYTES = 32;
export const PWHASH_SALT_BYTES = 16;
export const PWHASH_OPSLIMIT_MODERATE = 3;
export const PWHASH_MEMLIMIT_MODERATE = 67_108_864; // 64 MiB
export const MIN_PASSPHRASE_LENGTH = 12; // hint for the app

export async function deriveMasterKey(
  passphrase: string,
  salt: Uint8Array,
): Promise<Uint8Array> {
  if (typeof passphrase !== "string" || passphrase.length === 0) {
    throw new SecureRoomsCryptoError("INVALID_INPUT", "passphrase must be a non-empty string");
  }
  if (!(salt instanceof Uint8Array) || salt.length !== PWHASH_SALT_BYTES) {
    throw new SecureRoomsCryptoError(
      "INVALID_INPUT",
      `salt must be a ${PWHASH_SALT_BYTES}-byte Uint8Array`,
    );
  }
  const s = await getSodium();
  return s.crypto_pwhash(
    MASTER_KEY_BYTES,
    passphrase,
    salt,
    s.crypto_pwhash_OPSLIMIT_MODERATE,
    s.crypto_pwhash_MEMLIMIT_MODERATE,
    s.crypto_pwhash_ALG_ARGON2ID13,
  );
}
