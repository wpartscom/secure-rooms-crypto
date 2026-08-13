import { defineConfig } from "tsup";

export default defineConfig({
  entry: ["src/index.ts"],
  format: ["esm"],
  dts: true,
  sourcemap: false,
  clean: true,
  minify: false,
  target: "es2021",
  outDir: "dist",
  define: {
    // BUILD_HASH from env (release sets commit SHA), else "dev"
    __LIB_BUILD_HASH__: JSON.stringify(process.env.BUILD_HASH ?? "dev"),
  },
});
