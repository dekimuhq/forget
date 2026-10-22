import { describe, it, expect } from "vitest";
import {
  provisionVault,
  unlockVault,
  unlockVaultWithRecovery,
  changePassword,
  resetPasswordWithRecovery,
  encryptContent,
  decryptContent,
  validateRecoveryPhrase,
  generateSalt,
  deriveKey,
  generateVaultKey,
  generateKeypair,
  exportPublicKey,
  importPublicKey,
  encryptPrivateKey,
  decryptPrivateKey,
  encryptVaultKey,
  decryptVaultKey,
  generateRecoveryPhrase,
  recoverVaultKey,
  VAULT_VERSION,
} from "../src/vault/index";

// ── Key derivation ────────────────────────────────────────────────

describe("key derivation", () => {
  it("generates a 32-byte salt", () => {
    const salt = generateSalt();
    expect(salt).toBeInstanceOf(Uint8Array);
    expect(salt.length).toBe(32);
  });

  it("produces different salts each time", () => {
    const a = generateSalt();
    const b = generateSalt();
    expect(Buffer.from(a).equals(Buffer.from(b))).toBe(false);
  });

  it("derives a CryptoKey from password + salt", async () => {
    const salt = generateSalt();
    const key = await deriveKey("test-password", salt);
    expect(key).toBeDefined();
    expect(key.type).toBe("secret");
    expect(key.algorithm.name).toBe("AES-GCM");
  });

  it("same password + salt → same key (verified via vault key round-trip)", async () => {
    const salt = generateSalt();
    const vaultKey = await generateVaultKey();

    const masterKey1 = await deriveKey("same-pass", salt);
    const blob = await encryptVaultKey(vaultKey, masterKey1);

    const masterKey2 = await deriveKey("same-pass", salt);
    const recovered = await decryptVaultKey(blob, masterKey2);

    const origRaw = await crypto.subtle.exportKey("raw", vaultKey);
    const recRaw = await crypto.subtle.exportKey("raw", recovered);
    expect(Buffer.from(origRaw).equals(Buffer.from(recRaw))).toBe(true);
  });

  it("different password → different key (via vault unlock failure)", async () => {
    const salt = generateSalt();
    const vaultKey = await generateVaultKey();
    const masterKey = await deriveKey("correct", salt);
    const blob = await encryptVaultKey(vaultKey, masterKey);

    const wrongKey = await deriveKey("wrong", salt);
    await expect(decryptVaultKey(blob, wrongKey)).rejects.toThrow();
  });
});

// ── Vault key ──────────────────────────────────────────────────────

describe("vault key", () => {
  it("generates an extractable AES-256 key", async () => {
    const key = await generateVaultKey();
    expect(key.type).toBe("secret");
    expect(key.extractable).toBe(true);
    const raw = await crypto.subtle.exportKey("raw", key);
    expect(new Uint8Array(raw).length).toBe(32);
  });

  it("encrypts and decrypts with master key round-trip", async () => {
    const salt = generateSalt();
    const masterKey = await deriveKey("password", salt);
    const vaultKey = await generateVaultKey();

    const blob = await encryptVaultKey(vaultKey, masterKey);
    expect(blob.v).toBe(VAULT_VERSION);

    const recovered = await decryptVaultKey(blob, masterKey);
    const origRaw = await crypto.subtle.exportKey("raw", vaultKey);
    const recRaw = await crypto.subtle.exportKey("raw", recovered);
    expect(
      Buffer.from(origRaw).equals(Buffer.from(recRaw)),
    ).toBe(true);
  });
});

// ── RSA keypair ───────────────────────────────────────────────────

describe("RSA keypair", () => {
  it("generates RSA-OAEP-4096 keypair", async () => {
    const kp = await generateKeypair();
    expect(kp.publicKey.algorithm.name).toBe("RSA-OAEP");
    expect(kp.privateKey.algorithm.name).toBe("RSA-OAEP");
    expect(
      (kp.publicKey.algorithm as RsaHashedKeyAlgorithm).modulusLength,
    ).toBe(4096);
  });

  it("exports and imports public key round-trip", async () => {
    const kp = await generateKeypair();
    const exported = await exportPublicKey(kp.publicKey);
    expect(exported.v).toBe(VAULT_VERSION);

    const imported = await importPublicKey(exported);
    expect(imported.algorithm.name).toBe("RSA-OAEP");
  });

  it("encrypts and decrypts private key with vault key", async () => {
    const kp = await generateKeypair();
    const vaultKey = await generateVaultKey();

    const blob = await encryptPrivateKey(kp.privateKey, vaultKey);
    expect(blob.v).toBe(VAULT_VERSION);

    const recovered = await decryptPrivateKey(blob, vaultKey);
    expect(recovered.algorithm.name).toBe("RSA-OAEP");
    expect(recovered.type).toBe("private");
  });
});

// ── Content encryption ────────────────────────────────────────────

describe("content encryption", () => {
  it("round-trips ASCII content", async () => {
    const kp = await generateKeypair();
    const enc = await encryptContent("hello world", kp.publicKey);
    expect(enc.v).toBe(VAULT_VERSION);

    const dec = await decryptContent(enc, kp.privateKey);
    expect(dec).toBe("hello world");
  });

  it("round-trips UTF-8 (emoji + accents + CJK)", async () => {
    const kp = await generateKeypair();
    const plain = "factura · héllo · 世界 · 🔒💰";
    const enc = await encryptContent(plain, kp.publicKey);
    const dec = await decryptContent(enc, kp.privateKey);
    expect(dec).toBe(plain);
  });

  it("round-trips large content (10KB)", async () => {
    const kp = await generateKeypair();
    const plain = "x".repeat(10_000);
    const enc = await encryptContent(plain, kp.publicKey);
    const dec = await decryptContent(enc, kp.privateKey);
    expect(dec).toBe(plain);
  });

  it("produces different ciphertext each time (random content key)", async () => {
    const kp = await generateKeypair();
    const a = await encryptContent("same", kp.publicKey);
    const b = await encryptContent("same", kp.publicKey);
    expect(a.data).not.toBe(b.data);
    expect(a.key).not.toBe(b.key);
  });

  it("fails decryption with wrong private key", async () => {
    const kp1 = await generateKeypair();
    const kp2 = await generateKeypair();
    const enc = await encryptContent("secret", kp1.publicKey);
    await expect(decryptContent(enc, kp2.privateKey)).rejects.toThrow();
  });
});

// ── Recovery phrase ───────────────────────────────────────────────

describe("recovery phrase", () => {
  it("generates a 24-word phrase", async () => {
    const vaultKey = await generateVaultKey();
    const rp = await generateRecoveryPhrase(vaultKey);
    expect(rp.words.length).toBe(24);
    expect(rp.phrase.split(" ").length).toBe(24);
  });

  it("all words are from the BIP39 English wordlist", async () => {
    const { BIP39_ENGLISH } = await import("../src/vault/wordlist");
    const vaultKey = await generateVaultKey();
    const rp = await generateRecoveryPhrase(vaultKey);
    for (const word of rp.words) {
      expect(BIP39_ENGLISH).toContain(word);
    }
  });

  it("recovers the exact same vault key", async () => {
    const vaultKey = await generateVaultKey();
    const rp = await generateRecoveryPhrase(vaultKey);
    const recovered = await recoverVaultKey(rp.phrase);

    const origRaw = await crypto.subtle.exportKey("raw", vaultKey);
    const recRaw = await crypto.subtle.exportKey("raw", recovered);
    expect(
      Buffer.from(origRaw).equals(Buffer.from(recRaw)),
    ).toBe(true);
  });

  it("validates a correct phrase", async () => {
    const vaultKey = await generateVaultKey();
    const rp = await generateRecoveryPhrase(vaultKey);
    expect(await validateRecoveryPhrase(rp.phrase)).toBe(true);
  });

  it("rejects a tampered phrase (wrong word)", async () => {
    const vaultKey = await generateVaultKey();
    const rp = await generateRecoveryPhrase(vaultKey);
    const words = rp.phrase.split(" ");
    words[0] = words[0] === "abandon" ? "ability" : "abandon";
    expect(await validateRecoveryPhrase(words.join(" "))).toBe(false);
  });

  it("rejects a phrase with wrong word count", async () => {
    await expect(recoverVaultKey("abandon ability able")).rejects.toThrow(
      "exactly 24 words",
    );
  });

  it("rejects a phrase with unknown words", async () => {
    const fakePhrase = Array(24).fill("notaword").join(" ");
    await expect(recoverVaultKey(fakePhrase)).rejects.toThrow("unknown word");
  });
});

// ── High-level flows ──────────────────────────────────────────────

describe("provisionVault", () => {
  it("produces a complete vault bundle + recovery phrase", async () => {
    const result = await provisionVault("my-password-123");

    expect(result.bundle.encryptedVaultKey.v).toBe(VAULT_VERSION);
    expect(result.bundle.encryptedPrivateKey.v).toBe(VAULT_VERSION);
    expect(result.bundle.publicKey.v).toBe(VAULT_VERSION);
    expect(result.bundle.salt).toBeTruthy();
    expect(result.recoveryPhrase.words.length).toBe(24);
    expect(result.privateKey.type).toBe("private");
    expect(result.publicKey.type).toBe("public");
  });
});

describe("unlockVault", () => {
  it("unlocks with the correct password", async () => {
    const { bundle } = await provisionVault("correct-horse-battery-staple");
    const unlocked = await unlockVault(
      "correct-horse-battery-staple",
      bundle,
    );
    expect(unlocked.privateKey.type).toBe("private");
    expect(unlocked.publicKey.type).toBe("public");
  });

  it("fails with wrong password", async () => {
    const { bundle } = await provisionVault("correct");
    await expect(unlockVault("wrong", bundle)).rejects.toThrow();
  });
});

describe("unlockVaultWithRecovery", () => {
  it("unlocks with the recovery phrase", async () => {
    const { bundle, recoveryPhrase } = await provisionVault("password");
    const unlocked = await unlockVaultWithRecovery(
      recoveryPhrase.phrase,
      bundle,
    );
    expect(unlocked.privateKey.type).toBe("private");
    expect(unlocked.publicKey.type).toBe("public");
  });
});

describe("changePassword", () => {
  it("re-encrypts vault key with new password", async () => {
    const { bundle } = await provisionVault("old-pass");
    const newBundle = await changePassword("old-pass", "new-pass", bundle);

    // Old password no longer works
    await expect(unlockVault("old-pass", newBundle)).rejects.toThrow();

    // New password works
    const unlocked = await unlockVault("new-pass", newBundle);
    expect(unlocked.privateKey.type).toBe("private");
  });

  it("recovery phrase still works after password change", async () => {
    const { bundle, recoveryPhrase } = await provisionVault("old-pass");
    const newBundle = await changePassword("old-pass", "new-pass", bundle);

    const unlocked = await unlockVaultWithRecovery(
      recoveryPhrase.phrase,
      newBundle,
    );
    expect(unlocked.privateKey.type).toBe("private");
  });
});

describe("resetPasswordWithRecovery", () => {
  it("resets password using recovery phrase", async () => {
    const { bundle, recoveryPhrase } = await provisionVault("old-pass");
    const newBundle = await resetPasswordWithRecovery(
      recoveryPhrase.phrase,
      "new-pass",
      bundle,
    );

    // Old password no longer works
    await expect(unlockVault("old-pass", newBundle)).rejects.toThrow();

    // New password works
    const unlocked = await unlockVault("new-pass", newBundle);
    expect(unlocked.privateKey.type).toBe("private");
  });

  it("recovery phrase still works after reset", async () => {
    const { bundle, recoveryPhrase } = await provisionVault("old-pass");
    const newBundle = await resetPasswordWithRecovery(
      recoveryPhrase.phrase,
      "new-pass",
      bundle,
    );

    const unlocked = await unlockVaultWithRecovery(
      recoveryPhrase.phrase,
      newBundle,
    );
    expect(unlocked.privateKey.type).toBe("private");
  });

  it("rejects invalid recovery phrase", async () => {
    const { bundle } = await provisionVault("password");
    await expect(
      resetPasswordWithRecovery("abandon ".repeat(24).trim(), "new", bundle),
    ).rejects.toThrow();
  });
});

describe("end-to-end: provision → unlock → encrypt → decrypt", () => {
  it("full lifecycle", async () => {
    // Signup
    const { bundle, recoveryPhrase } = await provisionVault("my-password");

    // Login
    const { privateKey, publicKey } = await unlockVault(
      "my-password",
      bundle,
    );

    // Encrypt business content
    const invoiceData = JSON.stringify({
      client: "ACME Corp",
      amount: 15000,
      description: "Consulting services Q2 2026",
      vat: "B12345678",
    });

    const encrypted = await encryptContent(invoiceData, publicKey);

    // Server stores `encrypted` — cannot read it
    expect(encrypted.v).toBe(VAULT_VERSION);
    expect(encrypted.data).not.toContain("ACME");
    expect(encrypted.data).not.toContain("Consulting");

    // Client decrypts
    const decrypted = await decryptContent(encrypted, privateKey);
    expect(JSON.parse(decrypted)).toEqual({
      client: "ACME Corp",
      amount: 15000,
      description: "Consulting services Q2 2026",
      vat: "B12345678",
    });
  });

  it("recovery after password loss", async () => {
    const { bundle, recoveryPhrase, publicKey } =
      await provisionVault("forgotten-password");

    // Encrypt some content
    const encrypted = await encryptContent(
      "important business data",
      publicKey,
    );

    // User forgets password, uses recovery phrase
    const { privateKey } = await unlockVaultWithRecovery(
      recoveryPhrase.phrase,
      bundle,
    );

    // Still can decrypt
    const decrypted = await decryptContent(encrypted, privateKey);
    expect(decrypted).toBe("important business data");
  });
});
