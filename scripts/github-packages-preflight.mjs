#!/usr/bin/env node
// Release preflight: the GitHub Packages leg publishes with the workflow's own
// GITHUB_TOKEN, which can only reach a package whose "Manage Actions access"
// list includes this repository. Without it the GitHub leg fails AFTER the
// npmjs leg has shipped, leaving the registries out of parity.
//
// Exits 1 BEFORE anything is published when a package that already exists
// (it is on npmjs, so the mirror must have it too) cannot be read on GitHub
// Packages with the configured token. A package that is on neither registry
// is new: the workflow creates it and is granted access to it automatically.
//
// Read access is all this can prove. The Write role is still needed to
// publish; a package granted only Read fails at publish time, and a re-run
// after fixing the role resumes (changesets skips published versions).
import { publishablePackages, npmView, REGISTRIES } from './registry-parity.mjs';

const problems = [];
for (const { name } of publishablePackages()) {
  const github = await npmView(name, ['name'], REGISTRIES.github);
  if (github.data) continue;
  if (github.error) {
    problems.push(`${name}: GitHub Packages unreadable — ${github.error}`);
    continue;
  }
  const npmjs = await npmView(name, ['name'], REGISTRIES.npmjs);
  if (npmjs.missing) continue;
  problems.push(
    npmjs.error
      ? `${name}: npmjs unreadable — ${npmjs.error}`
      : `${name}: on npmjs but not readable on GitHub Packages`,
  );
}

if (problems.length === 0) {
  console.log('github-packages preflight: every existing package is readable with this token');
  process.exit(0);
}
for (const p of problems) console.error(`::error::${p}`);
console.error(`Nothing was published. Give this repository access to each package above:
  package page on GitHub → Package settings → Manage Actions access → Add repository → Role: Write`);
process.exit(1);
