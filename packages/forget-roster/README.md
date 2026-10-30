# @dekimuhq/forget-roster

Non-inclusion proofs for [Proof of Forgetting](https://github.com/dekimuhq/forget). An interval-leaf range-Merkle roster of active subjects with Ed25519-signed roots (`forget.roster.v1`), membership proofs and non-inclusion proofs. Each leaf commits a consecutive `(lo, hi)` pair of sorted subject values, so showing a subject is *absent* from the roster reduces to one ordinary Merkle inclusion proof plus a `lo < t < hi` check — adjacency is intrinsic to the leaf, no leaf-index trust required.

```bash
npm install @dekimuhq/forget-roster
```

```ts
import {
  buildRoster, subjectValue, signRoot, verifyRoot,
  proveNonInclusion, verifyNonInclusionSigned,
  ed25519Signer, publicKeyOf,
} from "@dekimuhq/forget-roster";

// seed: 32-byte Ed25519 seed (Uint8Array) · now: ISO-8601 string · priorRoot: previous root hex, or null for the first
const signer = ed25519Signer(seed, "roster-key-1");
const resolveKey = (id: string) => { if (id !== "roster-key-1") throw new Error("untrusted"); return publicKeyOf(seed); };

const roster = buildRoster(["alice", "carol"]);               // bob already erased
const signed = await signRoot(
  { root: roster.root, leafCount: roster.leafCount, generatedAt: now, prevRoot: priorRoot },
  signer,
);

const bob = subjectValue("bob");
const proof = proveNonInclusion(roster, bob)!;                 // null if subject is present
verifyNonInclusionSigned(bob, proof, signed, resolveKey);      // true → bob is absent from this signed roster
```

> **Verification contract (read before integrating).** `verifyNonInclusion(value, proof, root, leafCount)` does NOT authenticate the root — it trusts whatever `root`/`leafCount` you pass. The cryptographic binding of `leafCount` and the Merkle root lives in the *signature* (`verifyRoot`). **Always obtain `root`/`leafCount` from a `verifyRoot`-validated `SignedRoot`, never from a bare proof.** Prefer `verifyNonInclusionSigned` / `verifyMembershipSigned`, which run `verifyRoot` first and cannot be misused by skipping the signature check.
>
> **Interval bounds are fixed-length.** `intervalLeaf`/`internalNode` require exactly 64-hex (32-byte) operands. This is a security requirement: variable-length operands would make `sha256(0x00 ‖ lo ‖ hi)` ambiguous (`intervalLeaf("aabb","ccdd") === intervalLeaf("aa","bbccdd")`), which would let a genuine leaf be re-split to forge a non-inclusion proof for a present subject. `resolveKey` is the trust anchor — map keyId → public key only for trusted issuer keys.
>
> **Scope.** A non-inclusion proof shows the subject is absent from the roster the issuer signed. It says nothing about data the issuer never enrolled in the roster.

Wire format: [`forget/SPEC.md`](https://github.com/dekimuhq/anchors-spec/blob/main/forget/SPEC.md) in `dekimuhq/anchors-spec`.

## License

[Apache-2.0](LICENSE).
