import { defineConfig } from "tsup";

export default defineConfig([
  {
    entry: ["src/index.ts"],
    format: ["esm", "cjs"],
    dts: true,
    sourcemap: true,
    clean: true,
    target: "es2022",
    splitting: false,
  },
  {
    entry: { vault: "src/vault/index.ts" },
    format: ["esm"],
    dts: true,
    sourcemap: true,
    target: "es2022",
    platform: "browser",
    splitting: false,
  },
]);
