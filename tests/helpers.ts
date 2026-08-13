export * from "../src/index";

export function utf8RoundTripCheck(bytes: Uint8Array): string {
  return new TextDecoder().decode(bytes);
}
