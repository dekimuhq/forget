# Contributing to Proof of Forgetting

Thanks for considering a contribution. Correctness comes before features here: a change must not alter what an existing receipt, roster root or proof verifies to. Signed bytes are recomputed at verification, so any change to canonicalisation, hashing or a signed view breaks every receipt already issued.

Changes to what verification *means* (wire shapes, the signed view, the roster construction) belong in the specification first: [`dekimuhq/anchors-spec` → `forget/`](https://github.com/dekimuhq/anchors-spec/tree/main/forget).

## Setup

```bash
git clone https://github.com/dekimuhq/forget.git
cd forget
npm ci
npm run build
npm run typecheck
npm test
```

You need Node ≥22. Packages consume each other through their built `dist/`, so run `npm run build` before typecheck or test.

## Versioning

Every source change to a publishable package **must** include a `.changeset/*.md` file. Without a changeset the change is never released.

```bash
npx changeset
```

The prompt asks which packages changed, the bump type, and a one-line summary for the changelog.

| Type | When to use |
|------|-------------|
| `patch` | Bug fixes, internal refactors, doc-only changes, metadata fixes |
| `minor` | New exports, additive API changes |
| `major` | Breaking changes to a public API or to any signed wire shape |

Releases are cut by the maintainers. Contributors only add changesets.

## DCO

Please make contributions under the [Developer Certificate of Origin v1.1](https://developercertificate.org/) and sign off every commit:

```bash
git commit --signoff -m "forget-roster: reject unsorted boundary input"
```

There is no CLA.

## Code style

- TypeScript strict mode, including `noUncheckedIndexedAccess`. Don't soften it.
- No new runtime dependencies without discussion first.
- Named exports only. No `console.log` in `src/`.
- Verifiers fail closed: malformed input returns `false`, it never throws past the public API.

## Code of conduct

This project follows the [Contributor Covenant 2.1](CODE_OF_CONDUCT.md). Reports go to **conduct@dekimu.com**.
