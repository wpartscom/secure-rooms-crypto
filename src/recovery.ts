import { getSodium } from "./sodium";
import { SecureRoomsCryptoError } from "./errors";
import { base32Decode, base32Encode } from "./encoding";

export const RECOVERY_CODE_BYTES = 25;
export const RECOVERY_CODE_GROUPS = 8;
export const RECOVERY_CODE_GROUP_LENGTH = 5;
export const RECOVERY_CODE_BASE32_LENGTH = 40;
export const RECOVERY_KDF_CONTEXT = "WPSRREC1";
export const RECOVERY_KDF_SUBKEY_ID = 1;

export async function generateRecoveryCode(): Promise<{ code: string; bytes: Uint8Array }> {
  const s = await getSodium();
  const bytes = s.randombytes_buf(RECOVERY_CODE_BYTES);
  return { code: formatRecoveryCode(bytes), bytes };
}

export function formatRecoveryCode(bytes: Uint8Array): string {
  if (!(bytes instanceof Uint8Array) || bytes.length !== RECOVERY_CODE_BYTES) {
    throw new SecureRoomsCryptoError(
      "INVALID_INPUT",
      `recovery code bytes must be a ${RECOVERY_CODE_BYTES}-byte Uint8Array`,
    );
  }
  const b32 = base32Encode(bytes);
  const groups = b32.match(/.{5}/g);
  if (!groups || groups.length !== RECOVERY_CODE_GROUPS) {
    throw new SecureRoomsCryptoError("INVALID_FORMAT", "unexpected base32 length");
  }
  return groups.join("-");
}

/** Case-insensitive; hyphens/spaces optional. */
export function parseRecoveryCode(code: string): Uint8Array {
  if (typeof code !== "string") {
    throw new SecureRoomsCryptoError("INVALID_RECOVERY_CODE", "recovery code must be a string");
  }
  const clean = code.toUpperCase().replace(/[\s-]+/g, "");
  if (!new RegExp(`^[A-Z2-7]{${RECOVERY_CODE_BASE32_LENGTH}}$`).test(clean)) {
    throw new SecureRoomsCryptoError(
      "INVALID_RECOVERY_CODE",
      "recovery code must be 8 groups of 5 Base32 characters",
    );
  }
  const bytes = base32Decode(clean);
  if (bytes.length !== RECOVERY_CODE_BYTES) {
    throw new SecureRoomsCryptoError("INVALID_RECOVERY_CODE", "recovery code decodes to wrong length");
  }
  return bytes;
}

/** BLAKE2b master then crypto_kdf_derive_from_key (ctx WPSRREC1). */
export async function deriveRecoveryKey(codeBytes: Uint8Array): Promise<Uint8Array> {
  if (!(codeBytes instanceof Uint8Array) || codeBytes.length !== RECOVERY_CODE_BYTES) {
    throw new SecureRoomsCryptoError(
      "INVALID_INPUT",
      `recovery code bytes must be a ${RECOVERY_CODE_BYTES}-byte Uint8Array`,
    );
  }
  const s = await getSodium();
  const master = s.crypto_generichash(s.crypto_kdf_KEYBYTES, codeBytes, null);
  return s.crypto_kdf_derive_from_key(
    32,
    RECOVERY_KDF_SUBKEY_ID,
    RECOVERY_KDF_CONTEXT,
    master,
  );
}
