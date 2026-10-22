# @dekimuhq/forget-keystore

## 0.2.0

### Minor Changes

- First public release, from `github.com/dekimuhq/forget`: relicensed under Apache-2.0 and published to the public npm registry. Package metadata now points at the public repository (`repository`, `homepage`, `bugs`), `engines.node` is declared as `>=22`, and every tarball ships the LICENSE, README, CHANGELOG, SECURITY and CONTRIBUTING files. No API changes.

### Patch Changes

- Updated dependencies
  - @dekimuhq/crypto@1.4.0

## 0.1.1

### Patch Changes

- Add a `prepack` build hook (`npm run build`) so a manual `npm publish` always rebuilds `dist` before the tarball is assembled.
- Updated dependencies
  - @dekimuhq/crypto@1.2.1
