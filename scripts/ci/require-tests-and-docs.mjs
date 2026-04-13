import { execSync } from 'node:child_process';

const defaultBaseRef = (() => {
  try {
    return execSync('git symbolic-ref refs/remotes/origin/HEAD', { encoding: 'utf8' }).trim().replace('refs/remotes/', '');
  } catch {
    return 'origin/main';
  }
})();

const baseRef = process.env.GITHUB_BASE_REF ? `origin/${process.env.GITHUB_BASE_REF}` : defaultBaseRef;
const changed = execSync(`git diff --name-only ${baseRef}...HEAD`, { encoding: 'utf8' })
  .split('\n')
  .map((line) => line.trim())
  .filter(Boolean);

const isProdCode = (file) => /^(src|app|server|api|lib)\//.test(file) && !/\.(test|spec)\.[cm]?[jt]sx?$/.test(file);
const isTest = (file) => /^tests\//.test(file) || /\.(test|spec)\.[cm]?[jt]sx?$/.test(file);
const isDoc = (file) => /^docs\//.test(file) || /^openapi\//.test(file) || file === 'README.md';

const prodChanged = changed.some(isProdCode);
const testsChanged = changed.some(isTest);
const docsChanged = changed.some(isDoc);

if (prodChanged && !testsChanged) {
  console.error('Policy failure: production code changed without test updates.');
  process.exit(1);
}

if (prodChanged && !docsChanged) {
  console.error('Policy failure: production code changed without docs/OpenAPI updates.');
  process.exit(1);
}

console.log('Policy checks passed.');
