export const LIB_VERSION = "0.1.0";

// tsup define: BUILD_HASH env, else "dev"
declare const __LIB_BUILD_HASH__: string | undefined;

export const LIB_BUILD_HASH: string =
  typeof __LIB_BUILD_HASH__ === "string" ? __LIB_BUILD_HASH__ : "dev";
