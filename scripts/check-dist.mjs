#!/usr/bin/env node
// Every file a publishable package's manifest points at must exist: `main`,
// `module`, `types`, and every string target in the `exports` map. release.yml
// runs this after restoring the dist artifact built by the secretless job, so
// a partial artifact fails before anything is published.
//
//   node scripts/check-dist.mjs [<repo-root>]
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.resolve(process.argv[2] ?? path.join(path.dirname(fileURLToPath(import.meta.url)), '..'));
const pkgsDir = path.join(root, 'packages');
const targets = (v) => (typeof v === 'string' ? [v] : v && typeof v === 'object' ? Object.values(v).flatMap(targets) : []);
let missing = 0;
let checked = 0;
const dirs = fs.readdirSync(pkgsDir).filter((d) => fs.existsSync(path.join(pkgsDir, d, 'package.json')));
if (dirs.length === 0) throw new Error(`no packages under ${pkgsDir}`);
for (const d of dirs) {
  const pj = JSON.parse(fs.readFileSync(path.join(pkgsDir, d, 'package.json'), 'utf8'));
  if (pj.private) continue;
  const files = new Set([pj.main, pj.module, pj.types, ...targets(pj.exports)].filter(Boolean));
  for (const f of files) {
    checked++;
    if (!fs.existsSync(path.join(pkgsDir, d, f))) {
      missing++;
      console.error(`::error::${pj.name}: ${f} is missing`);
    }
  }
}
console.log(`check-dist: ${checked - missing}/${checked} manifest targets present across ${dirs.length} packages`);
process.exit(missing ? 1 : 0);
