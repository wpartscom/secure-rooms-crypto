# Threat model: WParts Secure Rooms

Private rooms with E2EE. Keys stay in clients. Server stores and relays
ciphertext. Admins see metadata only, unless a member reports a room and
opts in to share content with a moderator (that member wraps all epoch keys
for the moderator).

## Protected

- **Message and file content.** Server, DB backups, object storage, logs, and
  admins get ciphertext. Message AEAD AAD binds room id, epoch, sender id, and
  client message id (no relocating / re-attributing).
- **Room names/topics.** Encrypted under the room key.
- **Private keys on the server.** Backup blob under Argon2id (MODERATE) from a
  dedicated passphrase, or from a 200-bit recovery code. Offline cracking is
  limited by Argon2id (and by backup fetch throttling on the backend).
- **Server swapping room keys.** Wrapped keys are Ed25519-signed over
  `room_id | epoch | recipient_id | sealed_key`; bad pin -> `BAD_SIGNATURE`.
- **Authorship.** Sender signs ciphertext; peers check the pinned Ed25519 key.
- **File integrity.** Secretstream checks chunks and order; missing final tag
  means truncation.

## Not protected

Called out in product UI/docs too:

- **Malicious frontend from the platform.** Bad JS can steal keys after unlock.
  Mitigations (not a full fix): public repo, reproducible build, separate chunk
  + SRI, `sha256sums.txt` on releases, show `LIB_VERSION` / `LIB_BUILD_HASH`.
- **Per-message forward secrecy.** No Double Ratchet / MLS in v1. Leaking a
  room key leaks that whole epoch. New epoch only on remove/rotate.
- **Metadata.** Who is in which room, when, message/file sizes.
- **Screenshots / copy / forward by a legit member.**
- **Cached history after leave.** Removed members (and closed-report moderators)
  keep what they already decrypted. New epoch only blocks future content.
- **Endpoint compromise / XSS.** Unlocked keys in a bad renderer can decrypt
  (export is harder if the app wraps with non-extractable WebCrypto).
- **Availability / selective drop.** Server can withhold messages/wrappers/
  backups. Signatures catch swaps, not omission.
- **Weak passphrases.** Lib does not enforce policy (app: >= 12 chars, not the
  account password).

## Trust

- Devices and published keys (TOFU + BLAKE2b-128 safety numbers).
- Server is trusted for storage/relay, not for key distribution (wrapper
  signatures) or ciphertext routing (AAD).
- Moderator access is consent-based, visible (banner + encrypted system
  message), auditable. This package only supplies the wrap primitives.

## Reporting

Mail maintainers privately before public disclosure. Do not open public issues
for exploitable bugs.
