# Security policy — Proof of Forgetting

This is the security policy for every package in this repository: `@dekimuhq/crypto`, `@dekimuhq/forget-keystore`, `@dekimuhq/forget-roster` and `@dekimuhq/forget-receipt`. Per-package `SECURITY.md` files point here.

## Reporting a vulnerability

If you believe you have found a security vulnerability — a tampered receipt or roster root that verifies, a valid one that fails, a forged non-inclusion proof, a canonicalisation drift, a key-wrapping or crypto-shred flaw, a ciphertext that decrypts under the wrong key, a key leak, or anything analogous — please **do not open a public GitHub issue**.

Email **security@dekimu.com** with:

- A clear description of the issue.
- The affected package and source file(s), with a minimal reproducer.
- Your assessment of impact (false-verified, false-rejected, proof forgery, key exposure, plaintext exposure, denial of verify, etc.).
- Whether you intend to publish your own write-up, and on what timeline.

You should receive a human acknowledgement within **3 business days**.

## Disclosure window

This project follows a **90-day responsible-disclosure window**, starting from the day we acknowledge your report.

- Within 90 days we investigate, agree on impact, ship a fix or a specification clarification, coordinate disclosure with you, and publish a security advisory.
- After 90 days you are free to publish your findings whether or not a fix has shipped. If we need an extension we will ask before day 75; we will not extend unilaterally.
- For trivial issues (cosmetic, not exploitable) we may publish sooner, in coordination with you.

## Scope

| Package | In scope |
|---|---|
| `@dekimuhq/crypto` | `enc:v1:` field encryption and decryption, the `Signer` contract, and the `./vault` module (key derivation, key wrapping, hybrid content encryption, recovery phrases). |
| `@dekimuhq/forget-keystore` | Per-subject key generation, wrapping and unwrapping under the workspace key, `shred`. |
| `@dekimuhq/forget-roster` | Leaf and node hashing, roster construction, membership and non-inclusion proofs, root signing and verification. |
| `@dekimuhq/forget-receipt` | Minting and verification of `forget.destruction.v1` and `forget.model-disposition.v1`, rationale sanitisation, the end-to-end check. |
| Specification | Lives in [`dekimuhq/anchors-spec` → `forget/`](https://github.com/dekimuhq/anchors-spec/tree/main/forget). Any normative statement that turns out to be false or unsafe in practice; report it here as well. |

Out of scope (please use the matching channel instead):

- Operational issues with `verify.dekimu.com` (the hosted verifier): also **security@dekimu.com**, but name the hosted verifier so the report routes correctly.
- Product feedback, feature requests: open a public GitHub issue.
- Vulnerabilities in third-party dependencies: report upstream; we track and bump.

## Supported versions

Fixes land on `main` and ship as a patch release of each affected package; see each package's `CHANGELOG.md`. Security fixes target the latest published minor version of each package.

## Acknowledgements

We credit reporters in the affected packages' changelogs. Tell us in your first email whether you want to be credited, and how.

## Companion documents

- Contribution guide: [CONTRIBUTING.md](CONTRIBUTING.md).
- Code of conduct: [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) (Contributor Covenant 2.1). Reports go to **conduct@dekimu.com**.
- Security considerations for the wire format: [`forget/SPEC.md`](https://github.com/dekimuhq/anchors-spec/blob/main/forget/SPEC.md) in `dekimuhq/anchors-spec`.
