import sodium from "libsodium-wrappers-sumo";

let ready = false;
let readyPromise: Promise<void> | null = null;

/** Load libsodium WASM. Public APIs call this for you. */
export function initSodium(): Promise<void> {
  if (!readyPromise) {
    readyPromise = sodium.ready.then(() => {
      ready = true;
    });
  }
  return readyPromise;
}

export function isSodiumReady(): boolean {
  return ready;
}

export type Sodium = typeof sodium;

export async function getSodium(): Promise<Sodium> {
  await initSodium();
  return sodium;
}
