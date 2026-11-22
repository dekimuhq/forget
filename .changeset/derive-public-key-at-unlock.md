---
"@dekimuhq/crypto": minor
---

`unlockVault` and `unlockVaultWithRecovery` now derive the public key from the decrypted private key and compare it with `bundle.publicKey`, throwing the new `VaultKeyMismatchError` on mismatch instead of importing the supplied value. The returned `publicKey` is always the derived key. Honest bundles behave as before; no wire-format change.

New exports from `./vault`: `unlockVaultWithVaultKey(bundle, vaultKey)` for callers that already hold the vault key, `verifyPublicKeyBinding(privateKey, claimedPublicKey, { kid? })`, `derivePublicKeyFromPrivate(privateKey)`, and `VaultKeyMismatchError`.
