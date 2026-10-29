// Build gate for the scoped three.js exception (docs/design/UI-BRIEF-v3.md §0):
//  1. three.js must NOT be in the main bundle (it is lazy-loaded for #/wall only).
//  2. All lazy 3D chunks together (three-* + WallScene3D-* + wall3d*) ≤ 150 KB gzip.
// Runs after `vite build` (wired into `npm run build`). Non-zero exit fails the build.
// The rule lives in chunk-budget.mjs (pure, unit-tested, mutation-verified); this file only does I/O.
import { readdirSync, readFileSync } from 'fs';
import { gzipSync } from 'zlib';
import { join } from 'path';
import { evaluate, LIMIT_KB } from './chunk-budget.mjs';

const dir = join(process.cwd(), 'dist', 'assets');
const files = readdirSync(dir).filter(f => f.endsWith('.js')).map(name => {
  const buf = readFileSync(join(dir, name));
  return { name, text: buf.toString('utf8'), gzBytes: gzipSync(buf).length };
});
const r = evaluate(files);
for (const e of r.errors) console.error(`FAIL ${e}`);
if (r.ok) console.log(`PASS 3D chunks ${r.totalKb.toFixed(1)} KB gzip ≤ ${LIMIT_KB} KB (${r.line})`);
process.exit(r.ok ? 0 : 1);
