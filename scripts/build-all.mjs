#!/usr/bin/env node
// Build every publishable package to dist in dependency (topological) order,
// so a dependent never compiles before its dependencies' dist exists.
//
// Packages import each other through their built dist/ (types included), so
// `npm run build --workspaces` in directory order would build forget-receipt
// before forget-roster and fail its declaration build on a clean tree.
//
// Why release.mjs builds once up front: each package's `prepack` rebuilds (and
// tsup cleans) its own dist. During `changeset publish` that fires per package
// in publish order and can race the dependency graph. Building everything once,
// in toposort order, and publishing with `ignore-scripts` removes the race.
import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const rootPkg = JSON.parse(fs.readFileSync(path.join(root, 'package.json'), 'utf8'));

const dirs = [];
for (const ws of rootPkg.workspaces || []) {
  if (ws.endsWith('/*')) {
    const base = path.join(root, ws.slice(0, -2));
    if (!fs.existsSync(base)) continue;
    for (const e of fs.readdirSync(base, { withFileTypes: true }))
      if (e.isDirectory()) dirs.push(path.join(base, e.name));
  } else {
    dirs.push(path.join(root, ws));
  }
}

// Buildable = has a `build` script. Edges = workspace-internal dependencies of
// any kind (tests and declaration builds read devDependencies' dist too).
const nodes = new Map(); // name -> { dir, deps:Set<string> }
for (const dir of dirs) {
  const pjPath = path.join(dir, 'package.json');
  if (!fs.existsSync(pjPath)) continue;
  const pj = JSON.parse(fs.readFileSync(pjPath, 'utf8'));
  if (!pj.name || !pj.scripts?.build) continue;
  const deps = new Set(
    ['dependencies', 'devDependencies', 'peerDependencies'].flatMap((f) => Object.keys(pj[f] || {})),
  );
  nodes.set(pj.name, { dir, deps });
}

const order = [];
const done = new Set();
const onStack = new Set();
function visit(name) {
  if (done.has(name)) return;
  if (onStack.has(name)) throw new Error(`dependency cycle through ${name} — graph must be acyclic`);
  onStack.add(name);
  for (const dep of nodes.get(name).deps) if (nodes.has(dep)) visit(dep);
  onStack.delete(name);
  done.add(name);
  order.push(name);
}
for (const name of [...nodes.keys()].sort()) visit(name);

console.log(`build-all: ${order.length} packages in topological order`);
for (const name of order) {
  process.stdout.write(`  ${name} ... `);
  execFileSync('npm', ['run', 'build'], { cwd: nodes.get(name).dir, stdio: ['ignore', 'ignore', 'inherit'] });
  console.log('ok');
}
console.log('build-all: done');
