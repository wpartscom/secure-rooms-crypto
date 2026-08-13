import { getSodium } from "./sodium";
import { SecureRoomsCryptoError } from "./errors";
import { concat, readU64le, u64le, utf8 } from "./encoding";
import { validateIdentity, type IdentityKeyPair } from "./identity";
import { deriveMasterKey } from "./masterkey";
import {
  deriveRecoveryKey,
  parseRecoveryCode,
  RECOVERY_KDF_CONTEXT,
  RECOVERY_KDF_SUBKEY_ID,
} from "./recovery";

// Backup blob v1 layout: see SPEC.md section 4.

const MAGIC = new Uint8Array([0x57, 0x50, 0x53, 0x52]); // "WPSR"
export const BACKUP_FORMAT_VERSION = 1;
export const BACKUP_KIND_PASSPHRASE = 1;
export const BACKUP_KIND_RECOVERY = 2;
const KDF_ALG_ARGON2ID13 = 1;
const KDF_ALG_KDF_CHAIN = 2;
const PAYLOAD_VERSION = 1;
const PAYLOAD_BYTES = 1 + 32 + 32 + 64 + 32; // 161
const HEADER_LEN_PASSPHRASE = 23 + 16 + 24; // 63
const HEADER_LEN_RECOVERY = 23 + 24; // 47
const AEAD_TAG_BYTES = 16;

export interface WrapIdentityOptions {
  /** Fixed salt for tests only. */
  salt?: Uint8Array;
  /** Fixed nonce for tests only. */
  nonce?: Uint8Array;
}

function encodePayload(identity: IdentityKeyPair): Uint8Array {
  validateIdentity(identity);
  const payload = new Uint8Array(PAYLOAD_BYTES);
  payload[0] = PAYLOAD_VERSION;
  payload.set(identity.x25519PrivateKey, 1);
  payload.set(identity.x25519PublicKey, 33);
  payload.set(identity.ed25519PrivateKey, 65);
  payload.set(identity.ed25519PublicKey, 129);
  return payload;
}

function decodePayload(payload: Uint8Array): IdentityKeyPair {
  if (payload.length !== PAYLOAD_BYTES) {
    throw new SecureRoomsCryptoError("INVALID_FORMAT", "identity payload has wrong length");
  }
  if (payload[0] !== PAYLOAD_VERSION) {
    throw new SecureRoomsCryptoError(
      "UNSUPPORTED_VERSION",
      `unsupported identity payload version ${payload[0]}`,
    );
  }
  return {
    x25519PrivateKey: payload.slice(1, 33),
    x25519PublicKey: payload.slice(33, 65),
    ed25519PrivateKey: payload.slice(65, 129),
    ed25519PublicKey: payload.slice(129, 161),
  };
}

/** Backup blob v1, kind=passphrase (Argon2id). */
export async function wrapIdentity(
  identity: IdentityKeyPair,
  passphrase: string,
  options: WrapIdentityOptions = {},
): Promise<Uint8Array> {
  const s = await getSodium();
  const salt = options.salt ?? s.randombytes_buf(s.crypto_pwhash_SALTBYTES);
  const nonce =
    options.nonce ?? s.randombytes_buf(s.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);
  const opslimit = s.crypto_pwhash_OPSLIMIT_MODERATE;
  const memlimit = s.crypto_pwhash_MEMLIMIT_MODERATE;
  const masterKey = await deriveMasterKey(passphrase, salt);
  const ciphertext = s.crypto_aead_xchacha20poly1305_ietf_encrypt(
    encodePayload(identity),
    null,
    null,
    nonce,
    masterKey,
  );
  return concat(
    MAGIC,
    new Uint8Array([BACKUP_FORMAT_VERSION, BACKUP_KIND_PASSPHRASE, KDF_ALG_ARGON2ID13]),
    u64le(BigInt(opslimit)),
    u64le(BigInt(memlimit)),
    salt,
    nonce,
    ciphertext,
  );
}

/** Backup blob v1, kind=recovery. */
export async function wrapIdentityWithRecoveryCode(
  identity: IdentityKeyPair,
  recoveryCode: string | Uint8Array,
  options: { nonce?: Uint8Array } = {},
): Promise<Uint8Array> {
  const s = await getSodium();
  const codeBytes =
    typeof recoveryCode === "string" ? parseRecoveryCode(recoveryCode) : recoveryCode;
  const key = await deriveRecoveryKey(codeBytes);
  const nonce =
    options.nonce ?? s.randombytes_buf(s.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);
  const ciphertext = s.crypto_aead_xchacha20poly1305_ietf_encrypt(
    encodePayload(identity),
    null,
    null,
    nonce,
    key,
  );
  const context = utf8(RECOVERY_KDF_CONTEXT);
  return concat(
    MAGIC,
    new Uint8Array([BACKUP_FORMAT_VERSION, BACKUP_KIND_RECOVERY, KDF_ALG_KDF_CHAIN]),
    u64le(BigInt(RECOVERY_KDF_SUBKEY_ID)),
    context,
    nonce,
    ciphertext,
  );
}

interface ParsedBackupHeader {
  kind: number;
  headerLen: number;
  opslimit: number;
  memlimit: number;
  subkeyId: number;
  salt: Uint8Array | null;
  nonce: Uint8Array;
  ciphertext: Uint8Array;
}

function parseBackup(blob: Uint8Array): ParsedBackupHeader {
  if (!(blob instanceof Uint8Array) || blob.length < HEADER_LEN_RECOVERY + AEAD_TAG_BYTES) {
    throw new SecureRoomsCryptoError("INVALID_FORMAT", "backup blob is too short");
  }
  for (let i = 0; i < 4; i++) {
    if (blob[i] !== MAGIC[i]) {
      throw new SecureRoomsCryptoError("INVALID_FORMAT", "bad magic, not a WPSR backup blob");
    }
  }
  const version = blob[4];
  if (version !== BACKUP_FORMAT_VERSION) {
    throw new SecureRoomsCryptoError(
      "UNSUPPORTED_VERSION",
      `unsupported backup format version ${version}`,
    );
  }
  const kind = blob[5];
  const kdfAlg = blob[6];
  if (kind === BACKUP_KIND_PASSPHRASE) {
    if (kdfAlg !== KDF_ALG_ARGON2ID13) {
      throw new SecureRoomsCryptoError("INVALID_FORMAT", `unknown kdf_alg ${kdfAlg}`);
    }
    if (blob.length < HEADER_LEN_PASSPHRASE + AEAD_TAG_BYTES) {
      throw new SecureRoomsCryptoError("INVALID_FORMAT", "backup blob is too short");
    }
    return {
      kind,
      headerLen: HEADER_LEN_PASSPHRASE,
      opslimit: Number(readU64le(blob, 7)),
      memlimit: Number(readU64le(blob, 15)),
      subkeyId: 0,
      salt: blob.slice(23, 39),
      nonce: blob.slice(39, 63),
      ciphertext: blob.slice(HEADER_LEN_PASSPHRASE),
    };
  }
  if (kind === BACKUP_KIND_RECOVERY) {
    if (kdfAlg !== KDF_ALG_KDF_CHAIN) {
      throw new SecureRoomsCryptoError("INVALID_FORMAT", `unknown kdf_alg ${kdfAlg}`);
    }
    return {
      kind,
      headerLen: HEADER_LEN_RECOVERY,
      opslimit: 0,
      memlimit: 0,
      subkeyId: Number(readU64le(blob, 7)),
      salt: null,
      nonce: blob.slice(23, 47),
      ciphertext: blob.slice(HEADER_LEN_RECOVERY),
    };
  }
  throw new SecureRoomsCryptoError("INVALID_FORMAT", `unknown backup kind ${kind}`);
}

async function decryptParsed(parsed: ParsedBackupHeader, key: Uint8Array): Promise<IdentityKeyPair> {
  const s = await getSodium();
  let payload: Uint8Array;
  try {
    payload = s.crypto_aead_xchacha20poly1305_ietf_decrypt(
      null,
      parsed.ciphertext,
      null,
      parsed.nonce,
      key,
    );
  } catch {
    throw new SecureRoomsCryptoError(
      "DECRYPT_FAILED",
      "could not decrypt identity backup (wrong passphrase/code or corrupted blob)",
    );
  }
  return decodePayload(payload);
}

/** Open a backup blob; `secret` is passphrase or recovery code depending on kind. */
export async function unwrapIdentity(
  blob: Uint8Array,
  secret: string,
): Promise<IdentityKeyPair> {
  const parsed = parseBackup(blob);
  if (parsed.kind === BACKUP_KIND_PASSPHRASE) {
    const s = await getSodium();
    const masterKey = s.crypto_pwhash(
      32,
      secret,
      parsed.salt!,
      parsed.opslimit,
      parsed.memlimit,
      s.crypto_pwhash_ALG_ARGON2ID13,
    );
    return decryptParsed(parsed, masterKey);
  }
  const codeBytes = parseRecoveryCode(secret);
  const key = await deriveRecoveryKey(codeBytes);
  return decryptParsed(parsed, key);
}

/** Same as unwrapIdentity but requires kind=recovery. */
export async function unwrapIdentityWithRecoveryCode(
  blob: Uint8Array,
  recoveryCode: string,
): Promise<IdentityKeyPair> {
  const parsed = parseBackup(blob);
  if (parsed.kind !== BACKUP_KIND_RECOVERY) {
    throw new SecureRoomsCryptoError("WRONG_KIND", "blob is not a recovery backup");
  }
  const codeBytes = parseRecoveryCode(recoveryCode);
  const key = await deriveRecoveryKey(codeBytes);
  return decryptParsed(parsed, key);
}
