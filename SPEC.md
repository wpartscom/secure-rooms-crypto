# SPEC: WParts Secure Rooms crypto (format v1)

Wire formats for `@wparts/secure-rooms-crypto`. Multi-byte ints are little-endian.
`lp(s)` = length-prefixed UTF-8: `u16le byte_length || utf8(s)`, max 65535 bytes.

Crypto via `libsodium-wrappers-sumo` (pinned in package.json / lockfile).
This package does not know about HTTP, backends, or your app schema.

## 1. Identity

Per user:

- X25519 (`crypto_box_keypair`) for room key wrapping
- Ed25519 (`crypto_sign_keypair`) for message and key-wrapper signatures.
  Private key is libsodium's 64-byte form (`seed || public`).

App publishes public keys. Private keys leave the client only inside a backup
blob (section 4).

## 2. KDF parameters

### 2.1 Master key (passphrase backups)

```
MK = crypto_pwhash(32, passphrase_utf8, salt,
                   OPSLIMIT_MODERATE (= 3),
                   MEMLIMIT_MODERATE (= 67108864, 64 MiB),
                   ALG_ARGON2ID13)
```

- salt: 16 bytes (`crypto_pwhash_SALTBYTES`), random per backup, stored in the blob.
- Passphrase policy is the app's job (min 12 chars, not the account password).
  The lib only exports `MIN_PASSPHRASE_LENGTH` as a hint.

### 2.2 Recovery key (recovery-code backups)

25 bytes (200 bits) entropy, shown as Base32 (RFC 4648, `A-Z2-7`, no padding)
in 8 groups of 5 chars with hyphens, e.g.
`AAAQE-AYEAU-DAOCA-JBIFQ-YDIOB-4IBCE-QTCQK-RMFYY`.
Parse case-insensitive; hyphens/spaces optional.

Enough entropy, so fast KDF instead of Argon2id:

```
master = crypto_generichash(32, code_bytes, key = NULL)   // BLAKE2b-256
RCK    = crypto_kdf_derive_from_key(32, subkey_id = 1, ctx = "WPSRREC1", master)
```

## 3. Framing

Key-wrap signing input (section 5):

```
keywrap_tuple = lp(room_id) || epoch u32le || lp(recipient_id) || sealed_key
```

Message AAD (section 6):

```
aad = lp(room_id) || epoch u32le || lp(sender_user_id) || lp(client_msg_id)
```

Binds ciphertext to room, epoch, and identities so you cannot move or
re-attribute messages at the AEAD layer.

## 4. Backup blob format (v:1)

`wrapIdentity` / `wrapIdentityWithRecoveryCode` return an opaque blob for the
server. Layout:

```
offset  size  field
0       4     magic "WPSR" (0x57 0x50 0x53 0x52)
4       1     format version = 1
5       1     kind: 1 = passphrase, 2 = recovery
6       1     kdf_alg: 1 = Argon2id13 (kind 1), 2 = kdf chain (kind 2)
7       8     kind 1: opslimit u64le | kind 2: kdf subkey_id u64le
15      8     kind 1: memlimit u64le | kind 2: kdf context, 8 ASCII bytes
23      16    kind 1 only: pwhash salt
23|39   24    XChaCha20-Poly1305 nonce (offset 39 for kind 1, 23 for kind 2)
...     *     ciphertext = crypto_aead_xchacha20poly1305_ietf(payload), AAD = NULL
```

Header: 63 bytes (kind 1) or 47 (kind 2). Libsodium appends the 16-byte AEAD tag.

Inner plaintext (identity payload, 161 bytes):

```
offset  size  field
0       1     payload version = 1
1       32    x25519 private key
33      32    x25519 public key
65      64    ed25519 private key (libsodium format)
129     32    ed25519 public key
```

Kind 1: Argon2id from passphrase. Kind 2: recovery code (section 2.2).
Bad magic -> `INVALID_FORMAT`, bad version -> `UNSUPPORTED_VERSION`, AEAD fail
-> `DECRYPT_FAILED`. Reject unknown `kdf_alg`. Later releases must still open
v1 blobs (`tests/compat.test.ts`).

## 5. Room keys and epochs

- `RK`: 32 random bytes (`createRoomKey`) for messages and room name/topic.
- `epoch`: u32 key version. App bumps it on create, member change, or rotate.
  Forward secrecy is only between epochs.

For each (epoch, recipient), an online member does:

```
sealed_key = crypto_box_seal(RK, recipient_x25519_public)      // 80 bytes
signature  = crypto_sign_detached(keywrap_tuple,               // Ed25519, 64 bytes
                                  wrapper_ed25519_private)
```

Recipient checks `signature` against the wrapper's pinned Ed25519 key first
(`openRoomKey` -> `BAD_SIGNATURE` on mismatch), then `crypto_box_seal_open`
(`DECRYPT_FAILED` if it fails). Recipient X25519 pub comes from
`crypto_scalarmult_base` on their private key.

Which epochs a new member gets is app policy (`from_join` vs `full`).
Moderators on a report get all epochs; no new epoch for them.

## 6. Messages

App plaintext is JSON `{ v: 1, body, reply_to, attachments, sent_at }`.
This lib encrypts bytes; serialization is yours.

```
nonce      = randombytes_buf(24)
ciphertext = crypto_aead_xchacha20poly1305_ietf_encrypt(plaintext, aad, NULL, nonce, RK)
signature  = crypto_sign_detached(ciphertext, sender_ed25519_private)
```

`decryptMessage`: verify Ed25519 first (`BAD_SIGNATURE`), then decrypt with the
same AAD (`DECRYPT_FAILED` on AAD/ciphertext/key mismatch).

Room name/topic use the same construction under RK. System events are encrypted
messages with app-level `kind = 'system'`.

## 7. Attachments (secretstream)

- `FK`: 32 random bytes per file.
- `crypto_secretstream_xchacha20poly1305`, 1 MiB chunks (`STREAM_CHUNK_SIZE`).
  Last chunk gets `TAG_FINAL`; empty file = one empty final chunk.
- Keep the 24-byte `header` from `encryptStream` / `createStreamEncryptor` in
  encrypted message metadata.
- Chunk overhead 17 bytes; chunk count = `ceil(size / 1 MiB)` (min 1).
- Tamper/reorder -> `DECRYPT_FAILED`; missing final tag -> `STREAM_ERROR`.
- Previews use the same FK as another secretstream. FK, filename, MIME, size
  live in the encrypted message body. Server keeps object key, ciphertext size,
  chunk count.

## 8. Fingerprint

```
fp_raw = crypto_generichash(16, x25519_public || ed25519_public, NULL)  // BLAKE2b-128
fp     = uppercase hex of fp_raw, grouped by 4 chars, space-separated
```

Example: `48A8 B0A3 CAA4 89FD 3B81 7A63 D22B EFA6`. Safety number for TOFU.

## 9. Encodings

- On the wire: Base64 URL-safe, no padding (`toBase64` / `fromBase64`).
- Recovery codes: Base32 RFC 4648, no padding, 8 x 5 groups (section 2.2).
- Tests/diagnostics: lowercase hex.

## 10. Errors

`SecureRoomsCryptoError` with `code`:
`INVALID_INPUT`, `INVALID_FORMAT`, `UNSUPPORTED_VERSION`, `WRONG_KIND`,
`DECRYPT_FAILED`, `BAD_SIGNATURE`, `INVALID_RECOVERY_CODE`, `STREAM_ERROR`.
Switch on `code`, not message text.

## 11. Versions

`LIB_VERSION` = package semver. `LIB_BUILD_HASH` comes from `BUILD_HASH` at
build time (release workflow sets the tag commit SHA), else `"dev"`.
