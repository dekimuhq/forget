#!/usr/bin/env node
// Release preflight: a package's FIRST npmjs publish cannot use trusted
// publishing — npm only lets you configure a trusted publisher for a package
// that already exists. So a release that adds a package (a new receipt kind,
// a new helper) needs a short-lived NPM_BOOTSTRAP_TOKEN, or that package fails
// mid-release after its siblings have already shipped.
//
// Exits 1 BEFORE anything is published when some publishable package is not on
// npmjs yet and no token is present (NODE_AUTH_TOKEN, which release.yml fills
// from NPM_BOOTSTRAP_TOKEN; setup-node's placeholder counts as absent).
// Unreadable npmjs also exits 1: unknown is not "exists".
import { publishablePackages, npmView, REGISTRIES } from './registry-parity.mjs';

const missing = [];
const unreadable = [];
for (const { name } of publishablePackages()) {
  const r = await npmView(name, ['name'], REGISTRIES.npmjs);
  if (r.missing) missing.push(name);
  else if (r.error) unreadable.push(`${name}: ${r.error}`);
}

if (unreadable.length) {
  for (const u of unreadable) console.error(`::error::npmjs unreadable — ${u}`);
  process.exit(1);
}
if (missing.length === 0) {
  console.log('new-package preflight: every publishable package already exists on npmjs');
  process.exit(0);
}
// setup-node (with registry-url) exports NODE_AUTH_TOKEN=XXXXX-XXXXX-XXXXX-XXXXX
// as a placeholder when no token is supplied; that is not a token.
const PLACEHOLDER = 'XXXXX-XXXXX-XXXXX-XXXXX';
const token = process.env.NODE_AUTH_TOKEN;
if (token && token !== PLACEHOLDER) {
  console.log(`new-package preflight: first publish of ${missing.join(', ')} via NPM_BOOTSTRAP_TOKEN`);
  process.exit(0);
}
console.error(`::error::${missing.length} package(s) not on npmjs yet: ${missing.join(', ')}`);
console.error(`A first publish cannot use trusted publishing. Nothing was published. To release:
  1. npmjs.com → Access Tokens → Granular, Read and write (publish and stage), scope @dekimuhq, bypass 2FA, 7 days
  2. gh secret set NPM_BOOTSTRAP_TOKEN --env release -R dekimuhq/forget
  3. re-run this workflow
  4. npm trust github <each new package> --repository dekimuhq/forget --file release.yml --environment release --allow-publish --yes --registry=https://registry.npmjs.org
  5. gh secret delete NPM_BOOTSTRAP_TOKEN --env release -R dekimuhq/forget, and delete the token on npmjs.com`);
process.exit(1);
