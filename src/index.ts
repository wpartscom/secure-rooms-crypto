// E2EE primitives for WParts Secure Rooms. See SPEC.md and THREAT-MODEL.md.

export { initSodium, isSodiumReady } from "./sodium";
export { SecureRoomsCryptoError, type CryptoErrorCode } from "./errors";
export { LIB_VERSION, LIB_BUILD_HASH } from "./version";

export {
  generateIdentity,
  fingerprint,
  validateIdentity,
  type IdentityKeyPair,
  X25519_PUBLIC_KEY_BYTES,
  X25519_PRIVATE_KEY_BYTES,
  ED25519_PUBLIC_KEY_BYTES,
  ED25519_PRIVATE_KEY_BYTES,
  FINGERPRINT_BYTES,
} from "./identity";

export {
  deriveMasterKey,
  MASTER_KEY_BYTES,
  PWHASH_SALT_BYTES,
  PWHASH_OPSLIMIT_MODERATE,
  PWHASH_MEMLIMIT_MODERATE,
  MIN_PASSPHRASE_LENGTH,
} from "./masterkey";

export {
  generateRecoveryCode,
  formatRecoveryCode,
  parseRecoveryCode,
  deriveRecoveryKey,
  RECOVERY_CODE_BYTES,
  RECOVERY_CODE_GROUPS,
  RECOVERY_CODE_GROUP_LENGTH,
  RECOVERY_KDF_CONTEXT,
  RECOVERY_KDF_SUBKEY_ID,
} from "./recovery";

export {
  wrapIdentity,
  wrapIdentityWithRecoveryCode,
  unwrapIdentity,
  unwrapIdentityWithRecoveryCode,
  BACKUP_FORMAT_VERSION,
  BACKUP_KIND_PASSPHRASE,
  BACKUP_KIND_RECOVERY,
  type WrapIdentityOptions,
} from "./backup";

export {
  createRoomKey,
  sealRoomKeyFor,
  openRoomKey,
  ROOM_KEY_BYTES,
  SEALED_ROOM_KEY_BYTES,
  SIGNATURE_BYTES,
  type SealRoomKeyParams,
  type SealedRoomKey,
  type OpenRoomKeyParams,
} from "./room";

export {
  encryptMessage,
  decryptMessage,
  MESSAGE_NONCE_BYTES,
  type EncryptMessageParams,
  type EncryptedMessage,
  type DecryptMessageParams,
} from "./messages";

export {
  createStreamEncryptor,
  createStreamDecryptor,
  encryptStream,
  decryptStream,
  STREAM_CHUNK_SIZE,
  STREAM_KEY_BYTES,
  STREAM_HEADER_BYTES,
  STREAM_ABYTES,
  STREAM_TAG_MESSAGE,
  STREAM_TAG_FINAL,
  type StreamEncryptor,
  type StreamDecryptor,
  type EncryptedStream,
} from "./stream";

export {
  toBase64,
  fromBase64,
  toHex,
  fromHex,
  base32Encode,
  base32Decode,
  buildKeyWrapSigningInput,
  buildMessageAAD,
} from "./encoding";
