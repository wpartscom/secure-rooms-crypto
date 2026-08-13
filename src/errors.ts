export type CryptoErrorCode =
  | "INVALID_INPUT"
  | "INVALID_FORMAT"
  | "UNSUPPORTED_VERSION"
  | "WRONG_KIND"
  | "DECRYPT_FAILED"
  | "BAD_SIGNATURE"
  | "INVALID_RECOVERY_CODE"
  | "STREAM_ERROR";

export class SecureRoomsCryptoError extends Error {
  readonly code: CryptoErrorCode;

  constructor(code: CryptoErrorCode, message: string) {
    super(message);
    this.name = "SecureRoomsCryptoError";
    this.code = code;
  }
}
