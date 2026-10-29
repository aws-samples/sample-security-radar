#!/usr/bin/env node
// UI mutation verification (NEXT-STEPS B7): apply each entry of ui/mutations.txt, run its `expect` test file with
// vitest, require it to go RED, restore the file. Three outcomes, never two (touchstone mutate.py criteria ①④⑪):
//   red        — the guard is alive (good)
//   ALIVE?NO   — test stayed green: the guard is dead or unobserved
//   NOT LANDED — find matched 0 or ≥2 times / find == replace / expect collects no test / file == expect /
//                the mutated file does not compile or load (a broken file is not a live guard — 2026-10-24 review)
// "red" requires ≥1 failed ASSERTION in the vitest JSON report and no suite that failed to load/collect.
// An entry may declare `want = NOT LANDED` (self-test fixture): it passes only if it comes out exactly that.
// The source file is restored in `finally` and re-verified by sha256; SIGINT/SIGTERM also restore before exiting.
// Usage (from ui/): node scripts/mutate.mjs [--only UM03] [--registry mutations.txt]
import { readFileSync, writeFileSync, existsSync, mkdtempSync, rmSync } from 'fs';
import { tmpdir } from 'os';
import { createHash } from 'crypto';
import { spawnSync } from 'child_process';
import { resolve, dirname, join } from 'path';
import { fileURLToPath } from 'url';

const UI = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const argv = process.argv.slice(2);
const opt = k => { const i = argv.indexOf(k); return i >= 0 ? argv[i + 1] : undefined; };
const registry = resolve(UI, opt('--registry') ?? 'mutations.txt');
const only = opt('--only');
const sha = buf => createHash('sha256').update(buf).digest('hex');

/** Parse `[ID title]` sections with `key = value` lines (values verbatim, no interpolation). */
export function parseRegistry(text) {
  const out = []; let cur = null;
  for (const raw of text.split('\n')) {
    const line = raw.replace(/\r$/, '');
    if (!line.trim() || line.trimStart().startsWith('#')) continue;
    const h = line.match(/^\[(\S+)\s*(.*)\]$/);
    if (h) { cur = { id: h[1], title: h[2] }; out.push(cur); continue; }
    const kv = line.match(/^(file|find|replace|expect|want)\s*=\s?(.*)$/);
    if (!kv || !cur) throw new Error(`mutations.txt: cannot parse line: ${line}`);
    cur[kv[1]] = kv[2];
  }
  return out;
}

const vitest = args => spawnSync('npx', ['vitest', ...args], { cwd: UI, encoding: 'utf8', env: { ...process.env, CI: '1' } });

// Restore state shared with the signal handlers: a Ctrl-C mid-mutation must not leave a broken source file.
let pending = null; // { path, original }
const restore = () => { if (pending) { writeFileSync(pending.path, pending.original); pending = null; } };
for (const sig of ['SIGINT', 'SIGTERM']) process.on(sig, () => { restore(); process.exit(130); });

const LOAD_ERROR = /SyntaxError|Transform failed|Failed to load|Cannot find module|failed to resolve import/i;

/**
 * Outcome from vitest's exit code + JSON report. Only a failing assertion counts as red; a suite that failed
 * to load/collect (0 assertion results, or a transform/syntax message) means the mutation broke the file.
 */
export function judge(status, reportText) {
  if (status === 0) return ['ALIVE?NO', 'test stayed green'];
  if (!reportText) return ['NOT LANDED', `vitest rc=${status} wrote no JSON report (crash before collection)`];
  let rep;
  try { rep = JSON.parse(reportText); } catch { return ['NOT LANDED', 'vitest JSON report unparsable'] ; }
  const broken = (rep.testResults ?? []).filter(t => t.status === 'failed' && ((t.assertionResults ?? []).length === 0 || LOAD_ERROR.test(t.message ?? '')));
  if (broken.length) return ['NOT LANDED', `mutation does not compile/load: ${String(broken[0].message ?? '').split('\n')[0].slice(0, 120)}`];
  if ((rep.numFailedTests ?? 0) > 0) return ['red', `${rep.numFailedTests} assertion(s) failed`];
  return ['NOT LANDED', `vitest rc=${status} but no failed assertion (runner error)`];
}

function runOne(m) {
  if (!m.file || m.find === undefined || m.replace === undefined || !m.expect) return ['NOT LANDED', 'missing file/find/replace/expect'];
  if (m.find === m.replace) return ['NOT LANDED', 'find == replace (empty mutation)'];
  if (resolve(UI, m.file) === resolve(UI, m.expect)) return ['NOT LANDED', 'mutates its own test (judge, not code)'];
  const path = resolve(UI, m.file);
  if (!existsSync(path)) return ['NOT LANDED', `no such file ${m.file}`];
  if (!existsSync(resolve(UI, m.expect))) return ['NOT LANDED', `no such test ${m.expect}`];
  // `vitest list` exits 0 even for a path with no tests ⇒ require ≥1 listed test, or a typo would read as "red".
  const listed = vitest(['list', m.expect]);
  if (listed.status !== 0 || !listed.stdout.split('\n').some(l => l.includes(m.expect.replace(/^\.\//, '')))) {
    return ['NOT LANDED', `expect collects no test: ${m.expect}`];
  }
  const original = readFileSync(path, 'utf8');
  const n = original.split(m.find).length - 1;
  if (n !== 1) return ['NOT LANDED', `find matched ${n}× in ${m.file}`];
  const before = sha(original);
  pending = { path, original };
  try {
    writeFileSync(path, original.replace(m.find, () => m.replace)); // fn form: `$&` etc. stay literal
    const dir = mkdtempSync(join(tmpdir(), 'ui-mutate-'));
    const out = join(dir, 'report.json');
    try {
      const r = vitest(['run', m.expect, '--reporter=json', `--outputFile=${out}`]);
      return judge(r.status, existsSync(out) ? readFileSync(out, 'utf8') : null);
    } finally { rmSync(dir, { recursive: true, force: true }); }
  } finally {
    restore();
    if (sha(readFileSync(path, 'utf8')) !== before) { console.error(`RESTORE FAILED for ${m.file}`); process.exit(3); }
  }
}

// CI `parallel: N` sets CI_NODE_INDEX (1-based) / CI_NODE_TOTAL; shard k takes entries k-1, k-1+N, … (disjoint, union = all).
const total = Number(process.env.CI_NODE_TOTAL ?? 1), index = Number(process.env.CI_NODE_INDEX ?? 1);
if (!(total >= 1 && index >= 1 && index <= total)) { console.error(`bad shard ${index}/${total}`); process.exit(2); }
const entries = parseRegistry(readFileSync(registry, 'utf8'))
  .filter(m => !only || m.id === only)
  .filter((_, k) => only || k % total === index - 1);
if (entries.length === 0) { console.error(`no mutations${only ? ` matching --only ${only}` : ''} in ${registry} (shard ${index}/${total}) — refusing to report success`); process.exit(2); }
console.log(`shard ${index}/${total}: ${entries.map(m => m.id).join(' ')}`);
// Baseline must be green, otherwise every mutation "goes red" for free.
// (missing expect files are skipped here and reported per entry as NOT LANDED, not as a red baseline)
const baseFiles = [...new Set(entries.map(m => m.expect).filter(e => e && existsSync(resolve(UI, e))))];
const base = baseFiles.length ? vitest(['run', ...baseFiles]) : { status: 0 };
if (base.status !== 0) { console.error('baseline is red — fix tests before mutation verification\n' + base.stdout.slice(-2000)); process.exit(2); }

const tally = { red: 0, 'ALIVE?NO': 0, 'NOT LANDED': 0 };
let ok = 0;
for (const m of entries) {
  const [outcome, why] = runOne(m);
  const want = m.want ?? 'red';
  tally[outcome]++;
  if (outcome === want) ok++;
  console.log(`${outcome === want ? '✓' : '✗'} ${m.id} ${outcome.padEnd(10)} ${m.title} — ${why}${m.want ? ` (want ${want})` : ''}`);
}
console.log(`\n${entries.length} mutations: ${tally.red} red · ${tally['ALIVE?NO']} alive?no · ${tally['NOT LANDED']} not landed · ${ok}/${entries.length} as expected`);
process.exit(ok === entries.length ? 0 : 1);
