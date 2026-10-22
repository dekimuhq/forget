import { defineConfig } from "vitest/config";

// RSA-4096 keypair generation (`generateKeypair`) is inherently slow, and
// several tests in this package generate TWO pairs (e.g. workspace-key.test.ts
// "swapping kid for another valid-looking one fails the tag check", which calls
// generateKeypair() twice). On a loaded CI runner a single such test can exceed
// vitest's 5s default and flake, while passing every time locally.
//
// 30s is ample headroom for two RSA-4096 keygens under load without masking a
// genuine hang (a real deadlock still trips the ceiling).
export default defineConfig({
  test: {
    testTimeout: 30_000,
    hookTimeout: 30_000,
  },
});
