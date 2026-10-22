#!/usr/bin/env node
// Publish flow that cannot rebuild-race (see build-all.mjs for the race), to
// BOTH registries from the same build:
//   1. Build every package to dist once, in topological order
//      (skipped with RELEASE_SKIP_BUILD=1 when dist comes from a prior job).
//   2. `changeset publish` once per registry, with ignore-scripts, so each
//      `npm publish` ships that dist as-is.
//   3. registry-parity.mjs: every local version must be on both registries,
//      with the same tarball integrity.
//
// One `@dekimuhq` scope lives on two registries: npmjs (public) and GitHub
// Packages (a mirror for consumers that read the scope there). No package.json
// pins a publishConfig.registry; each leg picks its registry through
// `npm_config_@dekimuhq:registry`, which changesets reads for both its
// `npm info` existence check and the `npm publish` itself.
//
// npmjs goes first: it is the public, canonical registry, and the GitHub leg's
// credential is cheap to prove beforehand (release.yml runs `npm whoami`).
//
// Re-running after a partial failure resumes: changeset skips versions a
// registry already lists. One window it cannot cover: right after a publish,
// while npmjs is still promoting a staged version, changesets' `npm info` can
// miss it and npm then refuses the re-publish ("cannot publish over"). Wait a
// few minutes and re-run.
//
//   RELEASE_REGISTRIES=npmjs,github (default) | npmjs | github
//   Extra args go to `changeset publish` on the npmjs leg (e.g. --no-git-tag).
//   The github leg never creates git tags — the npmjs leg owns them.
import { execFileSync } from 'node:child_process';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { REGISTRIES } from './registry-parity.mjs';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
// Run changesets with node directly, never through `npx`: npm exec drops the
// scoped `npm_config_@dekimuhq:registry` (and `npm_config_provenance`) from the
// child's env, so every leg silently fell back to the repo .npmrc → npmjs
// (release run 39693683382: the github leg PUT to registry.npmjs.org).
const CHANGESET_BIN = path.join(root, 'node_modules/@changesets/cli/bin.js');
const legs = (process.env.RELEASE_REGISTRIES || 'npmjs,github').split(',').map((s) => s.trim());
for (const leg of legs) if (!REGISTRIES[leg]) throw new Error(`unknown registry leg "${leg}"`);

if (process.env.RELEASE_SKIP_BUILD !== '1')
  execFileSync(process.execPath, [path.join(root, 'scripts/build-all.mjs')], { cwd: root, stdio: 'inherit' });

for (const leg of legs) {
  const args = [CHANGESET_BIN, 'publish', ...(leg === 'npmjs' ? process.argv.slice(2) : ['--no-git-tag'])];
  console.log(`\n== publish → ${leg} (${REGISTRIES[leg]})`);
  const env = { ...process.env, npm_config_ignore_scripts: 'true', 'npm_config_@dekimuhq:registry': REGISTRIES[leg] };
  // Provenance needs a CI id-token, and GitHub Packages does not accept it.
  if (leg === 'npmjs' && process.env.GITHUB_ACTIONS === 'true') env.npm_config_provenance = 'true';
  execFileSync(process.execPath, args, { cwd: root, stdio: 'inherit', env });
}

if (legs.length === Object.keys(REGISTRIES).length) {
  execFileSync(process.execPath, [path.join(root, 'scripts/registry-parity.mjs'), '--wait=900'], {
    cwd: root,
    stdio: 'inherit',
  });
} else {
  console.log(`\nregistry parity NOT checked: only ${legs.join(',')} ran — run the other leg, then scripts/registry-parity.mjs`);
}
