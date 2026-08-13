// Writes tests/fixtures.ts. Run after build: node scripts/generate-fixtures.mjs
// Do not re-run after a release; vectors pin v1.
import { writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import sodium from "libsodium-wrappers-sumo";
import {
  wrapIdentity,
  wrapIdentityWithRecoveryCode,
  deriveMasterKey,
  deriveRecoveryKey,
  formatRecoveryCode,
  fingerprint,
  sealRoomKeyFor,
  encryptMessage,
  encryptStream,
  buildMessageAAD,
  buildKeyWrapSigningInput,
  toHex,
} from "../dist/index.js";

const here = dirname(fileURLToPath(import.meta.url));

const seq = (start, len) =>
  Uint8Array.from({ length: len }, (_, i) => (start + i) & 0xff);

await sodium.ready;

// --- fixed identity ----------------------------------------------------------
const x25519PrivateKey = seq(0x10, 32);
const x25519PublicKey = sodium.crypto_scalarmult_base(x25519PrivateKey);
const ed25519Seed = seq(0x40, 32);
const sign = sodium.crypto_sign_seed_keypair(ed25519Seed);
const identity = {
  x25519PublicKey,
  x25519PrivateKey,
  ed25519PublicKey: sign.publicKey,
  ed25519PrivateKey: sign.privateKey,
};

// --- fixed wrapper (a second party that seals the room key) ------------------
const wrapperSign = sodium.crypto_sign_seed_keypair(seq(0x60, 32));

// --- master key ---------------------------------------------------------------
const PASSPHRASE = "correct horse battery staple";
const SALT = seq(0x00, 16);
const masterKey = await deriveMasterKey(PASSPHRASE, SALT);

// --- recovery code ------------------------------------------------------------
const RECOVERY_BYTES = seq(0x00, 25);
const RECOVERY_CODE = formatRecoveryCode(RECOVERY_BYTES);
const recoveryKey = await deriveRecoveryKey(RECOVERY_BYTES);

// --- backup blobs (deterministic: fixed salt + nonces) ------------------------
const NONCE_BACKUP_PASS = seq(0x20, 24);
const NONCE_BACKUP_REC = seq(0x50, 24);
const backupPassphraseBlob = await wrapIdentity(identity, PASSPHRASE, {
  salt: SALT,
  nonce: NONCE_BACKUP_PASS,
});
const backupRecoveryBlob = await wrapIdentityWithRecoveryCode(identity, RECOVERY_BYTES, {
  nonce: NONCE_BACKUP_REC,
});

// --- room key distribution ------------------------------------------------------
const ROOM_ID = "018e8f9a-7c2b-4d3e-9f1a-2b3c4d5e6f70";
const EPOCH = 7;
const RECIPIENT_ID = "user-42";
const SENDER_ID = "user-17";
const CLIENT_MSG_ID = "018e8f9b-0000-7000-8000-000000000001";
const ROOM_KEY = seq(0xa0, 32);

const { sealedKey, signature: sealedSig } = await sealRoomKeyFor({
  roomKey: ROOM_KEY,
  roomId: ROOM_ID,
  epoch: EPOCH,
  recipientId: RECIPIENT_ID,
  recipientX25519PublicKey: identity.x25519PublicKey,
  signerEd25519PrivateKey: wrapperSign.privateKey,
});
const keywrapTuple = buildKeyWrapSigningInput(ROOM_ID, EPOCH, RECIPIENT_ID, sealedKey);

// --- message (deterministic: fixed nonce; Ed25519 is deterministic) -------------
const MESSAGE_NONCE = seq(0x80, 24);
const PLAINTEXT =
  '{"v":1,"body":"Hello, secure room!","reply_to":null,"attachments":[],"sent_at":"2026-01-01T00:00:00.000Z"}';
const aad = buildMessageAAD(ROOM_ID, EPOCH, SENDER_ID, CLIENT_MSG_ID);
const message = await encryptMessage({
  roomKey: ROOM_KEY,
  roomId: ROOM_ID,
  epoch: EPOCH,
  senderUserId: SENDER_ID,
  clientMsgId: CLIENT_MSG_ID,
  plaintext: PLAINTEXT,
  signerEd25519PrivateKey: identity.ed25519PrivateKey,
  nonce: MESSAGE_NONCE,
});

// --- stream (header is random; we freeze whatever we get) ---
const STREAM_KEY = seq(0xc0, 32);
const STREAM_DATA = Uint8Array.from({ length: 300 }, (_, i) => (i * 7) & 0xff);
const stream = await encryptStream(STREAM_KEY, STREAM_DATA, 100);

const fp = await fingerprint(identity.x25519PublicKey, identity.ed25519PublicKey);

const out = `// Frozen v1 vectors from scripts/generate-fixtures.mjs.
// Do not regenerate; changing outputs is a format break (bump v).
import { fromHex } from "../src/encoding";
import type { IdentityKeyPair } from "../src/identity";

export const PASSPHRASE = ${JSON.stringify(PASSPHRASE)};
export const SALT_HEX = "${toHex(SALT)}";
export const MASTER_KEY_HEX = "${toHex(masterKey)}";

export const IDENTITY_X25519_SK_HEX = "${toHex(identity.x25519PrivateKey)}";
export const IDENTITY_X25519_PK_HEX = "${toHex(identity.x25519PublicKey)}";
export const IDENTITY_ED25519_SK_HEX = "${toHex(identity.ed25519PrivateKey)}";
export const IDENTITY_ED25519_PK_HEX = "${toHex(identity.ed25519PublicKey)}";
export const FINGERPRINT = "${fp}";

export const WRAPPER_ED25519_SK_HEX = "${toHex(wrapperSign.privateKey)}";
export const WRAPPER_ED25519_PK_HEX = "${toHex(wrapperSign.publicKey)}";

export const RECOVERY_BYTES_HEX = "${toHex(RECOVERY_BYTES)}";
export const RECOVERY_CODE = "${RECOVERY_CODE}";
export const RECOVERY_KEY_HEX = "${toHex(recoveryKey)}";

export const BACKUP_PASSPHRASE_BLOB_HEX = "${toHex(backupPassphraseBlob)}";
export const BACKUP_RECOVERY_BLOB_HEX = "${toHex(backupRecoveryBlob)}";

export const ROOM_ID = "${ROOM_ID}";
export const EPOCH = ${EPOCH};
export const RECIPIENT_ID = "${RECIPIENT_ID}";
export const SENDER_ID = "${SENDER_ID}";
export const CLIENT_MSG_ID = "${CLIENT_MSG_ID}";
export const ROOM_KEY_HEX = "${toHex(ROOM_KEY)}";
export const SEALED_KEY_HEX = "${toHex(sealedKey)}";
export const SEALED_SIG_HEX = "${toHex(sealedSig)}";
export const KEYWRAP_TUPLE_HEX = "${toHex(keywrapTuple)}";

export const MESSAGE_NONCE_HEX = "${toHex(MESSAGE_NONCE)}";
export const MESSAGE_PLAINTEXT = ${JSON.stringify(PLAINTEXT)};
export const MESSAGE_AAD_HEX = "${toHex(aad)}";
export const MESSAGE_CIPHERTEXT_HEX = "${toHex(message.ciphertext)}";
export const MESSAGE_SIGNATURE_HEX = "${toHex(message.signature)}";

export const STREAM_KEY_HEX = "${toHex(STREAM_KEY)}";
export const STREAM_CHUNK_SIZE_USED = 100;
export const STREAM_DATA_HEX = "${toHex(STREAM_DATA)}";
export const STREAM_HEADER_HEX = "${toHex(stream.header)}";
export const STREAM_CHUNKS_HEX = [
${stream.chunks.map((c) => `  "${toHex(c)}",`).join("\n")}
];

export function fixtureIdentity(): IdentityKeyPair {
  return {
    x25519PublicKey: fromHex(IDENTITY_X25519_PK_HEX),
    x25519PrivateKey: fromHex(IDENTITY_X25519_SK_HEX),
    ed25519PublicKey: fromHex(IDENTITY_ED25519_PK_HEX),
    ed25519PrivateKey: fromHex(IDENTITY_ED25519_SK_HEX),
  };
}
`;

writeFileSync(join(here, "..", "tests", "fixtures.ts"), out);
console.log("tests/fixtures.ts written");
console.log("fingerprint:", fp);
console.log("recovery code:", RECOVERY_CODE);
