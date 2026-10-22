# @dekimuhq/forget-keystore

Per-subject crypto-shred. Each data subject gets a random 32-byte data-encryption key (DEK); their personal data is AES-256-GCM encrypted under it; the DEK is stored wrapped under a workspace key-encryption key (KEK). Erasure destroys the wrapped DEK. Once the wrapped DEK is destroyed in every store that holds it (the live registry and any backups), no copy of that subject's ciphertext has a key this package can recover. Backups and in-memory residue are the caller's responsibility (see below).

Part of [Proof of Forgetting](https://github.com/dekimuhq/forget) (`@dekimuhq/forget-keystore` + `@dekimuhq/forget-roster` + `@dekimuhq/forget-receipt`).

```bash
npm install @dekimuhq/forget-keystore
```

```ts
import { loadKey } from "@dekimuhq/crypto";
import { Keystore, type KeyRegistry } from "@dekimuhq/forget-keystore";

const kek = loadKey(process.env.DATA_ENCRYPTION_KEY!); // 32 bytes, base64
const registry: KeyRegistry = /* your store: get/put/del by subjectKeyId */;
const ks = new Keystore(registry, kek);

ks.createSubject("subject-A");                 // provisions a DEK (no-op if one exists)
const ct = ks.encrypt("subject-A", "jane@x.com");
ks.decrypt("subject-A", ct);                   // "jane@x.com"

ks.shred("subject-A");                          // destroys the wrapped DEK
ks.decrypt("subject-A", ct);                    // throws — no key for this subject
```

> **Operational invariant (load-bearing).** Crypto-shred only works if the key registry holds the *single, non-resurrectable* copy of the wrapped DEK. **Exclude the registry store from long-window backups.** The bulky ciphertext may be backed up freely, provided no backup keeps the wrapped DEK: a backup that still holds it, together with the KEK, decrypts the data. See §7.3 of the [specification](https://github.com/dekimuhq/anchors-spec/blob/main/forget/SPEC.md).
>
> **In-memory residue.** Unwrapped DEKs live in Node Buffers that are not explicitly zeroed; they persist in the heap until garbage collection and could surface in a core dump or swap. The authoritative copy is the wrapped registry row, which `shred` destroys. Process-memory residue is transient, outside what `shred` addresses, and the caller's responsibility.
>
> **What shredding does not do.** It does not locate or delete ciphertext copies, and it says nothing about plaintext that left the system before erasure (exports, logs, third parties). It removes the key from the registry it is given; copies elsewhere and the rest of the erasure process are the caller's.

## License

[Apache-2.0](LICENSE).
