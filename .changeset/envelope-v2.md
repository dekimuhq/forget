---
"@dekimuhq/crypto": minor
---

Add an authenticated, context-bound content envelope (`zkv2`) to `./vault`. No change to `zkv1`; `encryptContent` / `decryptContent` behave as before.

New exports: `encryptBlob(plaintext, keyMaterial, context)`, `decryptBlob(blob, { dataKey?, privateKey? }, expected)`, `deriveWorkspaceDataKey(privateKeyOrPkcs8, wsId, kid)`, `derivePersonalDataKey(vaultKey, userId)`, `blobAad`, `BlobContextError`, `VAULT_VERSION_V2`, and the `BlobContext`, `ExpectedBlobContext`, `DataKey`, `EncryptedContentV2`, `BlobKeys`, `DecryptedBlob` types.

- The context `{scope, kid, epoch, purpose, coll, rec, field, ver}` is bound as AES-GCM AAD in RFC 8785 form. `decryptBlob` builds the AAD from the caller's `expected` context, never from the blob.
- `cls:"member"` blobs use AES-256-GCM under a key derived with HKDF-SHA-256 (workspace: from the workspace private key, salt = workspace id, info bound to the key id; personal: from the vault key, salt = user id). A party that holds only the public key cannot produce one.
- `cls:"inbound"` blobs keep the hybrid RSA-OAEP format with AAD and are accepted only at `ver: 0`.
- `decryptBlob` opens `zkv1` blobs too, unless `expected.rejectV1` is set.
- `deriveWorkspaceDataKey` accepts the PKCS8 string because `importPrivateKeyPkcs8` returns a non-extractable key by design.
