# @dekimuhq/forget-receipt

Signed receipts for [Proof of Forgetting](https://github.com/dekimuhq/forget):

- **`forget.destruction.v1`** — an Ed25519 signature over `{kind, alg, subjectKeyIdHash, kekKeyId, destroyedAt, priorRosterRoot, newRosterRoot}`. It binds a subject to BOTH the prior roster root (where the subject was present) and the new root (where it is absent).
- **`forget.model-disposition.v1`** — how the subject's data was handled in any model trained on it (`not_trained`, `retrained`, `unlearned`, `scoped_exclusion`), bound to a destruction receipt through `destructionClaimId`. `retrained` and `unlearned` carry training-set roster roots and are verified with Merkle evidence from `@dekimuhq/forget-roster`.

Verification recomputes the signed view, so any tampered field invalidates the signature.

```bash
npm install @dekimuhq/forget-receipt
```

```ts
import { createDestructionReceipt, verifyDestructionReceipt, ed25519Signer, publicKeyOf } from "@dekimuhq/forget-receipt";

const signer = ed25519Signer(seed, "sign-1");
const resolveKey = (id: string) => { if (id !== "sign-1") throw new Error("untrusted"); return publicKeyOf(seed); };

const receipt = await createDestructionReceipt({
  subjectKeyIdHash,            // = subjectValue(subjectKeyId) from @dekimuhq/forget-roster — never a raw id
  kekKeyId: "kek-prod",        // destruction authority; NEVER the destroyed DEK
  destroyedAt: new Date().toISOString(),
  priorRosterRoot,
  newRosterRoot,
}, signer);

verifyDestructionReceipt(receipt, resolveKey); // true → signed by a trusted key, no field changed
```

> **What the receipt shows, and what it does not.** `verifyDestructionReceipt` shows *"a trusted issuer signed this destruction event"* — the provenance of a deletion event, as the issuer states it. To check the issuer's current state as well, the caller must also:
> 1. verify the signed roster for `newRosterRoot` (`verifyRoot`) and the **non-inclusion** of `subjectKeyIdHash` against it (`@dekimuhq/forget-roster`); and
> 2. confirm `receipt.newRosterRoot` equals the root the non-inclusion is checked against.
>
> Skipping the non-inclusion check treats a *logged* deletion as a *checked* one. `verifyForgottenEndToEnd` runs the destruction and model-disposition checks together; the package's lifecycle test shows the full chain. Neither the receipt nor the roster shows that no copy of the data exists anywhere: see "What a bundle shows" in the [repository README](https://github.com/dekimuhq/forget#what-a-bundle-shows-and-what-it-does-not). `resolveKey` is the trust anchor; `signerKeyId`/`signature` are metadata and are intentionally not part of the signed bytes.

Wire format: [`forget/SPEC.md`](https://github.com/dekimuhq/anchors-spec/blob/main/forget/SPEC.md) in `dekimuhq/anchors-spec`.

## License

[Apache-2.0](LICENSE).
