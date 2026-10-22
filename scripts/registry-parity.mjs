#!/usr/bin/env node
// Registry parity: every publishable package's local version must exist on BOTH
// registries with the same tarball integrity, and both registries must agree on
// `latest`. Reds (exit 1) on any disagreement — a version on one side only,
// different bytes under the same version, a `latest` that differs or is
// missing, or a registry that cannot be read (auth/network) — because an
// unreadable side is not evidence of parity.
//
// Integrity is the check that matters: changesets skips any version a registry
// already lists, so a version that reached one registry by another path, with
// other contents, would otherwise pass on its version string alone.
//
// Older versions present only on GitHub Packages are expected (the mirror
// predates the public registry) and are not compared.
//
//   node scripts/registry-parity.mjs [--wait=<seconds>]
//
// --wait retries while the findings are only versions not yet visible or
// transient read errors: npm's staged publishing answers a publish with 202 and
// promotes the version a few minutes later, so a check run straight after a
// publish would red on a release that is fine.
//
// Reading GitHub Packages needs a token with read:packages in the npm
// userconfig (`//npm.pkg.github.com/:_authToken=…`).
import { execFile } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';

const run = promisify(execFile);

export const REGISTRIES = {
  npmjs: 'https://registry.npmjs.org',
  github: 'https://npm.pkg.github.com',
};

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

// Workspace entries are `dir/*` globs or bare dirs (same resolution as
// build-all.mjs). Zero packages is an error, never a vacuous pass: a parity
// check or preflight over an empty list would report success for nothing.
export function publishablePackages() {
  const rootPkg = JSON.parse(fs.readFileSync(path.join(root, 'package.json'), 'utf8'));
  const dirs = [];
  for (const ws of rootPkg.workspaces || []) {
    if (ws.endsWith('/*')) {
      const base = path.join(root, ws.slice(0, -2));
      if (!fs.existsSync(base)) continue;
      for (const e of fs.readdirSync(base, { withFileTypes: true }).sort((a, b) => a.name.localeCompare(b.name)))
        if (e.isDirectory()) dirs.push(path.join(base, e.name));
    } else {
      dirs.push(path.join(root, ws));
    }
  }
  const out = [];
  for (const dir of dirs) {
    const pj = path.join(dir, 'package.json');
    if (!fs.existsSync(pj)) continue;
    const pkg = JSON.parse(fs.readFileSync(pj, 'utf8'));
    if (!pkg.private && pkg.name) out.push({ name: pkg.name, version: pkg.version });
  }
  if (out.length === 0) throw new Error('no publishable packages found under the root workspaces');
  return out;
}

export async function npmView(spec, fields, registry) {
  try {
    const { stdout } = await run('npm', ['view', spec, ...fields, '--json', `--@dekimuhq:registry=${registry}`], {
      maxBuffer: 16 * 1024 * 1024,
    });
    return { data: stdout.trim() ? JSON.parse(stdout) : {} };
  } catch (err) {
    // npm --json prints {"error":{"code","summary"}} on stdout.
    let code, summary;
    try {
      ({ code, summary } = JSON.parse(err.stdout).error);
    } catch {
      summary = `${err.stderr ?? ''}`.trim().split('\n').pop() || err.message;
    }
    if (code === 'E404') return { missing: true };
    return { error: [code, summary].filter(Boolean).join(' ') };
  }
}

// → { versions, latest, integrity } | { missing: true } | { error }
async function side(name, version, registry) {
  const pkg = await npmView(name, ['versions', 'dist-tags'], registry);
  if (!pkg.data) return pkg;
  const versions = [].concat(pkg.data.versions ?? []);
  const latest = pkg.data['dist-tags']?.latest;
  if (!versions.includes(version)) return { versions, latest };
  const dist = await npmView(`${name}@${version}`, ['dist.integrity'], registry);
  if (!dist.data) return dist;
  return { versions, latest, integrity: typeof dist.data === 'string' ? dist.data : undefined };
}

async function pool(items, size, fn) {
  let next = 0;
  await Promise.all(
    Array.from({ length: size }, async () => {
      while (next < items.length) await fn(items[next++]);
    }),
  );
}

// One finding per problem; `pending` marks the kinds --wait may outlast.
async function check(pkgs) {
  const findings = [];
  await pool(pkgs, 8, async ({ name, version }) => {
    const sides = {};
    for (const [leg, registry] of Object.entries(REGISTRIES)) sides[leg] = await side(name, version, registry);
    let comparable = true;
    for (const [leg, s] of Object.entries(sides)) {
      if (s.error) findings.push({ name, msg: `${leg}: unreadable — ${s.error}`, pending: true });
      else if (s.missing || !s.versions.includes(version))
        findings.push({ name, msg: `${leg}: ${version} not published`, pending: true });
      else if (!s.latest) findings.push({ name, msg: `${leg}: no latest dist-tag`, pending: true });
      else continue;
      comparable = false;
    }
    if (!comparable) return;
    const { npmjs: n, github: g } = sides;
    if (n.latest !== g.latest) findings.push({ name, msg: `latest differs — npmjs ${n.latest} vs github ${g.latest}` });
    if (!n.integrity || n.integrity !== g.integrity)
      findings.push({ name, msg: `${version} tarball differs — npmjs ${n.integrity} vs github ${g.integrity}` });
  });
  return findings;
}

async function main() {
  const waitArg = process.argv.find((a) => a.startsWith('--wait='));
  const deadline = Date.now() + (waitArg ? Number(waitArg.slice(7)) * 1000 : 0);
  const pkgs = publishablePackages();
  for (;;) {
    const findings = await check(pkgs);
    if (findings.length === 0) {
      console.log(`registry parity: ${pkgs.length} packages agree on npmjs + github (version, integrity, latest)`);
      return;
    }
    if (findings.every((f) => f.pending) && Date.now() < deadline) {
      console.log(`registry parity: ${findings.length} finding(s) may be transient, retrying in 30s`);
      await new Promise((r) => setTimeout(r, 30_000));
      continue;
    }
    for (const f of findings) console.error(`::error::${f.name} — ${f.msg}`);
    console.error(`registry parity: ${findings.length} finding(s) across ${pkgs.length} packages`);
    process.exit(1);
  }
}

if (fs.realpathSync(process.argv[1]) === fileURLToPath(import.meta.url)) await main();
