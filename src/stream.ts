import { getSodium } from "./sodium";
import { SecureRoomsCryptoError } from "./errors";
import { concat } from "./encoding";

// secretstream, 1 MiB chunks (SPEC.md section 7)
export const STREAM_CHUNK_SIZE = 1024 * 1024;
export const STREAM_KEY_BYTES = 32;
export const STREAM_HEADER_BYTES = 24;
export const STREAM_ABYTES = 17;

export const STREAM_TAG_MESSAGE = 0;
export const STREAM_TAG_FINAL = 3;

export interface StreamEncryptor {
  /** Store in message metadata. */
  readonly header: Uint8Array;
  push(chunk: Uint8Array, tag?: number): Uint8Array;
}

export async function createStreamEncryptor(key: Uint8Array): Promise<StreamEncryptor> {
  const s = await getSodium();
  if (key.length !== STREAM_KEY_BYTES) {
    throw new SecureRoomsCryptoError("INVALID_INPUT", "stream key must be 32 bytes");
  }
  const { state, header } = s.crypto_secretstream_xchacha20poly1305_init_push(key);
  return {
    header,
    push(chunk: Uint8Array, tag: number = STREAM_TAG_MESSAGE): Uint8Array {
      return s.crypto_secretstream_xchacha20poly1305_push(state, chunk, null, tag);
    },
  };
}

export interface StreamDecryptor {
  pull(ciphertext: Uint8Array): { plaintext: Uint8Array; tag: number };
}

export async function createStreamDecryptor(
  key: Uint8Array,
  header: Uint8Array,
): Promise<StreamDecryptor> {
  const s = await getSodium();
  if (key.length !== STREAM_KEY_BYTES) {
    throw new SecureRoomsCryptoError("INVALID_INPUT", "stream key must be 32 bytes");
  }
  if (header.length !== STREAM_HEADER_BYTES) {
    throw new SecureRoomsCryptoError("INVALID_INPUT", "stream header must be 24 bytes");
  }
  const state = s.crypto_secretstream_xchacha20poly1305_init_pull(header, key);
  return {
    pull(ciphertext: Uint8Array): { plaintext: Uint8Array; tag: number } {
      let result: { message: Uint8Array; tag: number } | false;
      try {
        result = s.crypto_secretstream_xchacha20poly1305_pull(state, ciphertext, null);
      } catch {
        result = false;
      }
      if (!result) {
        throw new SecureRoomsCryptoError(
          "DECRYPT_FAILED",
          "stream chunk authentication failed (tampered or out-of-order ciphertext)",
        );
      }
      return { plaintext: result.message, tag: result.tag };
    },
  };
}

export interface EncryptedStream {
  header: Uint8Array;
  chunks: Uint8Array[];
}

export async function encryptStream(
  key: Uint8Array,
  data: Uint8Array,
  chunkSize: number = STREAM_CHUNK_SIZE,
): Promise<EncryptedStream> {
  if (chunkSize <= 0 || !Number.isInteger(chunkSize)) {
    throw new SecureRoomsCryptoError("INVALID_INPUT", "chunkSize must be a positive integer");
  }
  const encryptor = await createStreamEncryptor(key);
  const chunks: Uint8Array[] = [];
  if (data.length === 0) {
    chunks.push(encryptor.push(new Uint8Array(0), STREAM_TAG_FINAL));
    return { header: encryptor.header, chunks };
  }
  for (let offset = 0; offset < data.length; offset += chunkSize) {
    const chunk = data.subarray(offset, Math.min(offset + chunkSize, data.length));
    const isLast = offset + chunkSize >= data.length;
    chunks.push(encryptor.push(chunk, isLast ? STREAM_TAG_FINAL : STREAM_TAG_MESSAGE));
  }
  return { header: encryptor.header, chunks };
}

export async function decryptStream(
  key: Uint8Array,
  header: Uint8Array,
  chunks: Uint8Array[],
): Promise<Uint8Array> {
  if (chunks.length === 0) {
    throw new SecureRoomsCryptoError("STREAM_ERROR", "stream has no chunks");
  }
  const decryptor = await createStreamDecryptor(key, header);
  const plaintexts: Uint8Array[] = [];
  let lastTag = -1;
  for (const chunk of chunks) {
    const { plaintext, tag } = decryptor.pull(chunk);
    plaintexts.push(plaintext);
    lastTag = tag;
  }
  if (lastTag !== STREAM_TAG_FINAL) {
    throw new SecureRoomsCryptoError("STREAM_ERROR", "stream is truncated: missing final tag");
  }
  return concat(...plaintexts);
}
