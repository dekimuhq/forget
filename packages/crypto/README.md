# @dekimuhq/crypto

AES-256-GCM field encryption, the shared receipt `Signer` contract, and a WebCrypto end-to-end encryption module (`@dekimuhq/crypto/vault`). Part of [Proof of Forgetting](https://github.com/dekimuhq/forget): `@dekimuhq/forget-keystore` builds its per-subject crypto-shred on the field encryption here.

```bash
npm install @dekimuhq/crypto
```

Node ≥22.

## Field encryption

Encrypts string fields one at a time, with a versioned wire format so callers can detect encrypted-vs-plain values without a parallel schema:

```
enc:v1:<base64(iv || tag || ciphertext)>
```

- `iv` — 12 bytes, fresh random per encrypt
- `tag` — 16 bytes (GCM authentication tag — tamper detection)
- `ciphertext` — UTF-8 plaintext, AES-256-GCM encrypted

```ts
import { loadKey, encryptField, decryptField, encryptFields, decryptFields }
  from "@dekimuhq/crypto";

const key = loadKey(process.env.DATA_ENCRYPTION_KEY!); // 32 bytes, base64

// One-off encrypt
const ct = encryptField("ES-B12345678", key);
const pt = decryptField(ct, key); // → "ES-B12345678"

// Batch — encrypts only the listed string fields, leaves the rest untouched
const stored = encryptFields(profile, ["taxId", "paymentRef"], key);

// Reverse on read
const visible = decryptFields(stored, ["taxId", "paymentRef"], key);
```

### Key management

The package never reads environment variables. Callers pass an explicit `EncryptionKey` (via `loadKey(rawBase64)`), so test setups, key rotation, and per-tenant keys all stay in caller-side code. A typical server-side wrapper:

```ts
import { loadKey, encryptField, decryptField } from "@dekimuhq/crypto";

let cachedKey: ReturnType<typeof loadKey> | null = null;
function getKey() {
  if (cachedKey) return cachedKey;
  const raw = process.env.DATA_ENCRYPTION_KEY;
  if (!raw) throw new Error("DATA_ENCRYPTION_KEY is required");
  cachedKey = loadKey(raw);
  return cachedKey;
}

export const encrypt = (s: string) => encryptField(s, getKey());
export const decrypt = (s: string) => decryptField(s, getKey());
```

### Failure modes

- **Tampered ciphertext** — `decryptField` returns `""` rather than throwing. GCM tag mismatch is the signal; treat empty-decrypt as "the value is unrecoverable".
- **Wrong key** — same as tampered: returns `""`.
- **Missing prefix** — `decryptField` passes the input through unchanged. This makes the helpers safe to apply to mixed plain/encrypted reads during a backfill window.
- **Empty string in** — `encryptField` returns `""` (no IV is consumed, no ciphertext produced). The empty case is not encrypted; treat it as a sentinel for "field cleared".

### Key rotation

1. **Generate the new key.** `openssl rand -base64 32`. Keep both old and new in your secret store.
2. **Ship a dual-read codepath.** Try the new key first in decrypt, fall back to the old one; always encrypt with the new key. Use a new prefix (`enc:v2:`) on the new path so values are self-identifying.
3. **Backfill.** Read every encrypted record, decrypt with whichever key works, re-encrypt with the new key — in a one-shot job, never inline in a request handler.
4. **Verify** that no values under the old key remain.
5. **Drop the old key** and its decrypt branch, then retire the old secret.

The wire format is intentionally versioned: adding `enc:v2:` is a non-breaking change, and `v1` keeps decrypting for as long as its prefix stays in `decryptField`.

## Receipt `Signer`

`Signer` is the detached-signature contract shared by `@dekimuhq/forget-receipt` and `@dekimuhq/forget-roster`: a key id, an algorithm (`"Ed25519"`), and `sign(bytes)`, sync or async so a KMS/HSM can back it.

```ts
import type { Signer } from "@dekimuhq/crypto";
```

## `@dekimuhq/crypto/vault`

A WebCrypto module (browser or Node ≥22, ESM only) for end-to-end encrypted content, designed so the server that stores its outputs holds ciphertext and wrapped keys only:

- `provisionVault(password)` → a vault bundle to store (password-wrapped vault key, vault-wrapped RSA-OAEP-4096 private key, public key, salt) plus a 24-word BIP39 recovery phrase to show once.
- `unlockVault(password, bundle)`, `unlockVaultWithRecovery(phrase, bundle)`, `changePassword(...)`, `resetPasswordWithRecovery(...)`.
- `encryptContent(plaintext, recipientPublicKey, kid?)` / `decryptContent(encrypted, privateKey)` — hybrid encryption: a random AES-256-GCM content key, wrapped with RSA-OAEP. An optional `kid` (truncated SHA-256 of the recipient's SPKI, see `computeKid`) is checked against the key and bound as additional authenticated data.

Key derivation is PBKDF2-SHA-256 with 600,000 iterations. The password-derived master key is non-extractable.

```ts
import { provisionVault, unlockVault, encryptContent, decryptContent } from "@dekimuhq/crypto/vault";
```

## License

[Apache-2.0](LICENSE).
