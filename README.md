# Proof of Forgetting

TypeScript reference implementation of **Proof of Forgetting**: signed, offline-checkable records of a personal-data erasure event, built for GDPR Art. 17 erasure workflows.

A Proof of Forgetting bundle pairs two signed statements from the same issuer:

- a **destruction receipt** (`forget.destruction.v1`): "the data-encryption key for subject *S* was destroyed at time *T* under key authority *K*, moving our roster from signed root *R₀* (which contained *S*) to signed root *R₁* (which does not)";
- a **non-inclusion proof** against the signed roster `forget.roster.v1` *R₁*: "*S* is absent from the set of subjects we still hold keys for".

An optional **model-disposition receipt** (`forget.model-disposition.v1`) records how the subject's data was handled in any model trained on it (never trained on, retrained without it, machine-unlearned, or excluded by a documented filter), bound to the destruction receipt.

## What a bundle shows, and what it does not

A valid bundle is **tamper-evident**: every signed field is recomputed at verification, so any change invalidates the signature. A third party can check it offline against the issuer's public key, with no call to the issuer.

It records the **provenance of a deletion event**, as stated and signed by the issuer:

- the issuer signed a destruction event for this subject, at this time, under this key authority;
- the subject is absent from the signed roster the receipt names as "after", and was present in the one it names as "before";
- each roster root signs its leaf count and the root it replaces (`prevRoot`), so a verifier that holds the prior signed root can detect a truncated roster, or one that does not chain to it, by comparing the two. `verifyRoot` checks a root's signature only: the cross-checks of the spec's full-bundle procedure (§6.3: roots match the receipt, `prevRoot` chains, membership before and absence after) are the verifier's to run. Spotting that a *later* roster exists also needs the issuer's latest published root, obtained out of band.

It does **not** show that no copy of the data exists anywhere. Crypto-shredding destroys the wrapped key in the issuer's registry; it does not locate copies of the ciphertext or of the key. A backup that still holds the wrapped key, data that left through a third party, or data the issuer never enrolled in the roster are all outside what the receipts cover. A valid signature also says nothing about whether the signer is the authority you expect: resolve and trust issuer keys out of band. Whether a given bundle satisfies a particular legal obligation is a question for the relevant authority; nothing here is legal advice.

## Specification

The wire format (receipt shapes, canonicalisation, the interval-leaf roster, verification algorithms, security considerations) is specified, CC0, in [`dekimuhq/anchors-spec` → `forget/`](https://github.com/dekimuhq/anchors-spec/tree/main/forget). `forget.*` receipts are companion receipts to the [Anchored Receipts](https://github.com/dekimuhq/anchors) family, not an `ar.<noun>.v<N>` member.

The public verifier at [verify.dekimu.com](https://verify.dekimu.com) checks the signature of a `forget.destruction.v1` receipt. Roster non-inclusion and `forget.model-disposition.v1` checks run offline with the packages below.

## Packages

| Package | Path | What it does |
|---|---|---|
| `@dekimuhq/crypto` | [`packages/crypto`](packages/crypto) | AES-256-GCM field encryption (`enc:v1:` wire format), the shared receipt `Signer` contract, and a WebCrypto end-to-end encryption module on the `./vault` subpath. |
| `@dekimuhq/forget-keystore` | [`packages/forget-keystore`](packages/forget-keystore) | Per-subject crypto-shred: data encrypted under a per-subject key, wrapped by a workspace key; `shred` destroys the wrapped key. |
| `@dekimuhq/forget-roster` | [`packages/forget-roster`](packages/forget-roster) | Interval-leaf range-Merkle roster of active subjects, Ed25519-signed roots, membership and non-inclusion proofs. |
| `@dekimuhq/forget-receipt` | [`packages/forget-receipt`](packages/forget-receipt) | Mint and verify `forget.destruction.v1` and `forget.model-disposition.v1` receipts, plus an end-to-end check. |

## Install

```bash
npm install @dekimuhq/forget-keystore @dekimuhq/forget-roster @dekimuhq/forget-receipt
```

`@dekimuhq/crypto` comes in as a dependency; install it directly if you only need field encryption.

## Requirements

Node **≥22**. Every package declares `"engines": { "node": ">=22" }`, the oldest Node release line still maintained. (The code itself needs Node 20 or later: the `@dekimuhq/crypto/vault` subpath uses the global WebCrypto object, `globalThis.crypto`, which Node 18 does not expose to modules. CI tests Node 22 and 24.) Signatures and hashes use [`@noble/curves`](https://github.com/paulmillr/noble-curves) and [`@noble/hashes`](https://github.com/paulmillr/noble-hashes); field encryption uses `node:crypto`.

## Development

```bash
git clone https://github.com/dekimuhq/forget.git
cd forget
npm ci
npm run build       # builds every package's dist/ in dependency order
npm run typecheck
npm test
```

Build before typecheck or test: packages import each other through their built `dist/`. Tests use [Vitest](https://vitest.dev).

## Contributing, security, license

- [CONTRIBUTING.md](CONTRIBUTING.md): changesets, versioning, DCO sign-off.
- [SECURITY.md](SECURITY.md): report vulnerabilities to **security@dekimu.com**, not in a public issue.
- [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md): Contributor Covenant 2.1; reports to **conduct@dekimu.com**.
- Code: [Apache-2.0](LICENSE). Specification: CC0, in `dekimuhq/anchors-spec`.
