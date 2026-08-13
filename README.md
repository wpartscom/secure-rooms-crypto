# @wparts/secure-rooms-crypto

E2EE helpers for WParts Secure Rooms. Server only stores/relays ciphertext.
Uses [libsodium](https://libsodium.gitbook.io/) (`libsodium-wrappers-sumo`):
Argon2id, XChaCha20-Poly1305, sealed boxes, secretstream, Ed25519, BLAKE2b.

No HTTP or framework glue. Public APIs call `initSodium()` themselves, so they
are fine from a Web Worker.

- Formats: [SPEC.md](SPEC.md)
- Threat model: [THREAT-MODEL.md](THREAT-MODEL.md)
- License: [MIT](LICENSE)

## Install

```bash
pnpm add @wparts/secure-rooms-crypto
```

## Usage

```ts
import {
  generateIdentity,
  generateRecoveryCode,
  wrapIdentity,
  wrapIdentityWithRecoveryCode,
  unwrapIdentity,
  createRoomKey,
  sealRoomKeyFor,
  openRoomKey,
  encryptMessage,
  decryptMessage,
  encryptStream,
  decryptStream,
  fingerprint,
  LIB_VERSION,
  LIB_BUILD_HASH,
} from "@wparts/secure-rooms-crypto";

// identity once per user
const identity = await generateIdentity();
console.log(await fingerprint(identity.x25519PublicKey, identity.ed25519PublicKey));

// two encrypted backups for the server
const passphraseBlob = await wrapIdentity(identity, userPassphrase);
const { code } = await generateRecoveryCode(); // show once: "ABCDE-..."
const recoveryBlob = await wrapIdentityWithRecoveryCode(identity, code);
const restored = await unwrapIdentity(passphraseBlob, userPassphrase);

// room key per epoch, per recipient
const roomKey = await createRoomKey();
const { sealedKey, signature } = await sealRoomKeyFor({
  roomKey, roomId, epoch, recipientId,
  recipientX25519PublicKey: recipient.x25519PublicKey,
  signerEd25519PrivateKey: identity.ed25519PrivateKey,
});
const rk = await openRoomKey({
  sealedKey, signature, roomId, epoch, recipientId,
  signerEd25519PublicKey: wrapperPublicKey, // pin this key
  recipientX25519PrivateKey: identity.x25519PrivateKey,
});

// messages: AAD = room_id | epoch | sender | client_msg_id
const enc = await encryptMessage({
  roomKey: rk, roomId, epoch, senderUserId, clientMsgId,
  plaintext: JSON.stringify({ v: 1, body: "hello", reply_to: null, attachments: [], sent_at: new Date().toISOString() }),
  signerEd25519PrivateKey: identity.ed25519PrivateKey,
});
const plain = await decryptMessage({
  roomKey: rk, roomId, epoch, senderUserId, clientMsgId,
  ciphertext: enc.ciphertext, nonce: enc.nonce, signature: enc.signature,
  signerEd25519PublicKey: senderPublicKey,
});

// attachments: secretstream, 1 MiB chunks; keep `header` in message metadata
const { header, chunks } = await encryptStream(fileKey, fileBytes);
const fileBytesBack = await decryptStream(fileKey, header, chunks);
```

Failures throw `SecureRoomsCryptoError` with a stable `code`
(`BAD_SIGNATURE`, `DECRYPT_FAILED`, `UNSUPPORTED_VERSION`, ...). Match on
`code`, not the message text. See SPEC.md section 10.

## Reproducible build

GitHub Actions builds from the tagged commit (frozen lockfile), publishes to
npm with provenance, and attaches `sha256sums.txt` to the release.

```bash
git clone https://github.com/wpartscom/secure-rooms-crypto.git
cd secure-rooms-crypto
git checkout v0.1.0
corepack enable && corepack pnpm install --frozen-lockfile
BUILD_HASH=$(git rev-parse HEAD) pnpm build
sha256sum dist/index.js dist/index.d.ts
# compare with sha256sums.txt from the GitHub Release
```

Show `LIB_VERSION` / `LIB_BUILD_HASH` in the client and load the chunk with
SRI if you can. That helps against a bad frontend build; it does not fully
stop one. Details in THREAT-MODEL.md.

## Development

```bash
corepack pnpm install --frozen-lockfile
corepack pnpm test
corepack pnpm build
```

`tests/fixtures.ts` is frozen v1 vectors from `scripts/generate-fixtures.mjs`.
If outputs change, bump the format version and keep v1 readable.
