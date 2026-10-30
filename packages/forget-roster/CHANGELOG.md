# @dekimuhq/forget-roster

## 0.2.2

### Patch Changes

- README: document the types of `seed`, `now` and `priorRoot` in the usage example.

## 0.2.0

### Minor Changes

- First public release, from `github.com/dekimuhq/forget`: relicensed under Apache-2.0 and published to the public npm registry. Package metadata now points at the public repository (`repository`, `homepage`, `bugs`), `engines.node` is declared as `>=22`, and every tarball ships the LICENSE, README, CHANGELOG, SECURITY and CONTRIBUTING files. No API changes.

### Patch Changes

- Updated dependencies
  - @dekimuhq/crypto@1.4.0

## 0.1.2

### Patch Changes

- Add a `prepack` build hook (`npm run build`) so a manual `npm publish` always rebuilds `dist` before the tarball is assembled.
- Re-export the shared receipt-signer `Signer` interface from `@dekimuhq/crypto` instead of declaring a copy.
- Updated dependencies
  - @dekimuhq/crypto@1.2.1
