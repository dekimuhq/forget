# @dekimuhq/crypto

## 1.4.0

### Minor Changes

- The tarball no longer includes `src/vault`. The `./vault` export has always resolved to the built `dist/vault.js`, so imports are unaffected.
- First public release, from `github.com/dekimuhq/forget`: relicensed under Apache-2.0 and published to the public npm registry. Package metadata now points at the public repository (`repository`, `homepage`, `bugs`), `engines.node` is declared as `>=22`, and every tarball ships the LICENSE, README, CHANGELOG, SECURITY and CONTRIBUTING files. No API changes.

## 1.3.0

### Minor Changes

- Add `kid` to `EncryptedContent`, `computeKid()` / `computeKidForKey()`, and
  PKCS8 private-key export/import. Enables per-workspace keypairs whose private
  key is wrapped to each member via the existing hybrid `encryptContent`.

  Additive and backward-compatible: `kid` is absent on every blob written before
  this change, and `encryptContent` omits it unless supplied. Blobs written
  without AAD still decrypt (pinned by test).

  Two properties worth knowing about if you consume this:

  - **`kid` is authenticated.** It is bound as AES-GCM additional authenticated
    data, so stripping or swapping it fails the tag check rather than silently
    changing which key a blob claims. Empty AAD is identical to omitted AAD, which
    is what keeps pre-`kid` blobs readable.
  - **A supplied `kid` is checked against the key.** `encryptContent` recomputes
    the kid of `recipientPublicKey` and throws on mismatch, instead of writing a
    blob stamped "encrypted to key K" that only some other key decrypts.

  `importPrivateKeyPkcs8` is always non-extractable — there is no `extractable`
  option, because re-wrapping a key to another member re-derives the PKCS8 from
  the caller's own wrap and never needs an exportable handle.

## 1.2.1

### Patch Changes

- Chunk `toBase64Url` (32k-element chunks) so encoding large encrypted vault payloads no longer throws `RangeError` from spreading the whole array into `String.fromCharCode`; correct the `deriveKey` doc comment (the master key is non-extractable, scoped to wrapKey/unwrapKey).
- Add a `prepack` build hook (`npm run build`) so a manual `npm publish` always rebuilds `dist` before the tarball is assembled.
- Export the receipt-signer `Signer` interface (`keyId` + `alg` + `sign(bytes)`) as the single shared declaration; `@dekimuhq/forget-receipt` and `@dekimuhq/forget-roster` re-export it, so an algorithm-agility change is one edit.

## 1.2.0

### Minor Changes

- Add `resetPasswordWithRecovery` vault flow for password recovery using a BIP39 phrase.

## 1.1.0

### Minor Changes

- Add `@dekimuhq/crypto/vault` subpath — end-to-end encryption client module (WebCrypto API, AES-256-GCM + RSA-4096, BIP39 recovery).
