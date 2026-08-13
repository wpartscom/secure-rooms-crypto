import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    environment: "node",
    // Argon2id with MODERATE limits takes ~1s per derivation.
    testTimeout: 180_000,
    hookTimeout: 120_000,
  },
});
