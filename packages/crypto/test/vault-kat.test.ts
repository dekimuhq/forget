import { describe, it, expect } from "vitest";
import { createHash } from "node:crypto";
import {
  deriveKey,
  generateSalt,
  generateVaultKey,
  encryptVaultKey,
  decryptVaultKey,
  generateRecoveryPhrase,
  recoverVaultKey,
  validateRecoveryPhrase,
} from "../src/vault/index";
import {
  exportVaultKeyRaw,
  importVaultKeyRaw,
} from "../src/vault/derive";
import { BIP39_ENGLISH } from "../src/vault/wordlist";
import { KDF_ITERATIONS, SALT_BYTES, IV_BYTES, KID_BYTES, RSA_MODULUS_LENGTH } from "../src/vault/types";

/**
 * Known-answer vectors + integrity pins for the vault recovery path.
 * Catastrophic-if-wrong code: a silent bit-packing or wordlist regression
 * would mint recovery phrases that cannot recover the vault key. These
 * tests pin the implementation to the BIP39 spec, not to itself.
 */

function hexToBytes(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}

function bytesToHex(bytes: Uint8Array): string {
  return [...bytes].map((b) => b.toString(16).padStart(2, "0")).join("");
}

// ── BIP39 official test vectors (256-bit entropy, Trezor reference set) ──

const BIP39_VECTORS: ReadonlyArray<{ entropyHex: string; mnemonic: string }> = [
  {
    entropyHex: "00".repeat(32),
    mnemonic: `${"abandon ".repeat(23)}art`,
  },
  {
    entropyHex: "7f".repeat(32),
    mnemonic:
      "legal winner thank year wave sausage worth useful legal winner thank year " +
      "wave sausage worth useful legal winner thank year wave sausage worth title",
  },
  {
    entropyHex: "80".repeat(32),
    mnemonic:
      "letter advice cage absurd amount doctor acoustic avoid letter advice cage " +
      "absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic bless",
  },
  {
    entropyHex: "ff".repeat(32),
    mnemonic: `${"zoo ".repeat(23)}vote`,
  },
  {
    entropyHex: "f585c11aec520db57dd353c69554b21a89b20fb0650966fa0a9d6f74fd989d8f",
    mnemonic:
      "void come effort suffer camp survey warrior heavy shoot primary clutch crush " +
      "open amazing screen patrol group space point ten exist slush involve unfold",
  },
];

describe("BIP39 known-answer vectors (entropy → 24-word mnemonic)", () => {
  for (const { entropyHex, mnemonic } of BIP39_VECTORS) {
    it(`encodes ${entropyHex.slice(0, 8)}… to the spec mnemonic`, async () => {
      const key = await importVaultKeyRaw(hexToBytes(entropyHex));
      const rp = await generateRecoveryPhrase(key);
      expect(rp.phrase).toBe(mnemonic);
      expect([...rp.words]).toEqual(mnemonic.split(" "));
    });

    it(`decodes the spec mnemonic back to ${entropyHex.slice(0, 8)}…`, async () => {
      const recovered = await recoverVaultKey(mnemonic);
      expect(bytesToHex(await exportVaultKeyRaw(recovered))).toBe(entropyHex);
    });
  }
});

describe("recovery phrase — adversarial inputs", () => {
  it("rejects the all-abandon phrase (valid words, wrong checksum)", async () => {
    // Correct final word for zero entropy is "art"; "abandon" fails the checksum.
    const phrase = Array(24).fill("abandon").join(" ");
    await expect(recoverVaultKey(phrase)).rejects.toThrow(/checksum mismatch/);
    expect(await validateRecoveryPhrase(phrase)).toBe(false);
  });

  it("rejects the all-zoo phrase (valid words, wrong checksum)", async () => {
    await expect(recoverVaultKey(Array(24).fill("zoo").join(" "))).rejects.toThrow(
      /checksum mismatch/,
    );
  });

  it("rejects a phrase where two words are swapped", async () => {
    // Deterministic: swap words 0 and 12 of the "legal winner…" vector —
    // entropy changes, checksum byte no longer matches.
    const words = BIP39_VECTORS[1]!.mnemonic.split(" ");
    [words[0], words[12]] = [words[12]!, words[0]!];
    await expect(recoverVaultKey(words.join(" "))).rejects.toThrow(/checksum mismatch/);
  });

  it("rejects 23- and 25-word phrases", async () => {
    const good = BIP39_VECTORS[0]!.mnemonic.split(" ");
    await expect(recoverVaultKey(good.slice(0, 23).join(" "))).rejects.toThrow(
      /exactly 24 words/,
    );
    await expect(recoverVaultKey([...good, "art"].join(" "))).rejects.toThrow(
      /exactly 24 words/,
    );
  });

  it("normalizes case and irregular whitespace before decoding", async () => {
    const sloppy = `  ${"ABANDON  ".repeat(23)}  Art \n`;
    const recovered = await recoverVaultKey(sloppy);
    expect(bytesToHex(await exportVaultKeyRaw(recovered))).toBe("00".repeat(32));
  });

  it("rejects an empty phrase", async () => {
    await expect(recoverVaultKey("")).rejects.toThrow();
    expect(await validateRecoveryPhrase("")).toBe(false);
  });
});

describe("generate → recover round-trip (randomized)", () => {
  it("survives 20 random vault keys bit-for-bit", async () => {
    for (let i = 0; i < 20; i++) {
      const key = await generateVaultKey();
      const rp = await generateRecoveryPhrase(key);
      const recovered = await recoverVaultKey(rp.phrase);
      expect(bytesToHex(await exportVaultKeyRaw(recovered))).toBe(
        bytesToHex(await exportVaultKeyRaw(key)),
      );
    }
  });
});

describe("derive.ts — KDF contract", () => {
  it("pins the KDF parameters (OWASP 2023 floor)", () => {
    expect(KDF_ITERATIONS).toBe(600_000);
    expect(SALT_BYTES).toBe(32);
    expect(IV_BYTES).toBe(12);
    expect(RSA_MODULUS_LENGTH).toBe(4096);
    // Changing this silently re-keys every kid in the corpus: existing blobs
    // would carry ids no longer derivable from their key, so the migration's
    // idempotence predicate would misread the whole estate at once.
    expect(KID_BYTES).toBe(16);
  });

  it("derived master keys are non-extractable and wrap/unwrap-only", async () => {
    const key = await deriveKey("password", generateSalt());
    expect(key.extractable).toBe(false);
    expect([...key.usages].sort()).toEqual(["unwrapKey", "wrapKey"]);
  });

  it("same password with a DIFFERENT salt cannot unwrap the vault key", async () => {
    const vaultKey = await generateVaultKey();
    const master = await deriveKey("password", generateSalt());
    const blob = await encryptVaultKey(vaultKey, master);
    const otherSalt = await deriveKey("password", generateSalt());
    await expect(decryptVaultKey(blob, otherSalt)).rejects.toThrow();
  });
});

describe("wordlist.ts — BIP39 English list integrity", () => {
  it("matches the official english.txt SHA-256", () => {
    // sha256 of https://github.com/bitcoin/bips/blob/master/bip-0039/english.txt
    // (one word per line, trailing newline).
    const digest = createHash("sha256")
      .update(BIP39_ENGLISH.join("\n") + "\n")
      .digest("hex");
    expect(digest).toBe(
      "2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda",
    );
  });

  it("has exactly 2048 unique, sorted, lowercase words", () => {
    expect(BIP39_ENGLISH.length).toBe(2048);
    expect(new Set(BIP39_ENGLISH).size).toBe(2048);
    expect([...BIP39_ENGLISH]).toEqual([...BIP39_ENGLISH].sort());
    for (const word of BIP39_ENGLISH) {
      expect(word).toMatch(/^[a-z]{3,8}$/);
    }
  });

  it("first four letters of every word are unique (BIP39 prefix property)", () => {
    expect(new Set(BIP39_ENGLISH.map((w) => w.slice(0, 4))).size).toBe(2048);
  });

  it("pins the boundary words", () => {
    expect(BIP39_ENGLISH[0]).toBe("abandon");
    expect(BIP39_ENGLISH[2047]).toBe("zoo");
    expect(BIP39_ENGLISH[1019]).toBe("legal"); // 0x7f7f… vector's first 11 bits = 0b01111111011
  });
});
