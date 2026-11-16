// Pure evaluation for the scoped three.js exception (docs/archive/UI-BRIEF-v3.md §0); the runner is check-chunks.mjs.
// Kept side-effect free so chunk-budget.test.mjs can pin the threshold (ui/mutations.txt UC1–UC4).
export const LIMIT_KB = 150;

/** @param {{name: string, text: string, gzBytes: number}[]} files  dist/assets/*.js */
export function evaluate(files, limitKb = LIMIT_KB) {
  const errors = [];
  for (const f of files.filter(f => f.name.startsWith('index-'))) {
    if (f.text.includes('WebGLRenderer')) errors.push(`three.js leaked into main bundle ${f.name}`);
  }
  const lazy = files.filter(f => /^(three-|WallScene3D-|wall3d)/.test(f.name));
  if (lazy.length === 0) errors.push('no lazy 3D chunk found');
  const totalKb = lazy.reduce((s, f) => s + f.gzBytes, 0) / 1024;
  const line = lazy.map(f => `${f.name}=${(f.gzBytes / 1024).toFixed(1)}KB`).join(' + ');
  if (totalKb > limitKb) errors.push(`3D chunks ${totalKb.toFixed(1)} KB gzip > ${limitKb} KB (${line})`);
  return { ok: errors.length === 0, errors, totalKb, line };
}

// R3.6: the stylesheets index.html links are render-blocking. Measured 2026-11-15: 128 KB gzip, 113 KB of it @font-face
// rules (small subsets inlined as base64). Fonts now load after first paint (styles/fonts.css); the blocking CSS is
// 12.7 KB. Budget ≈ 1.5× that: room for the app's own CSS to grow, none for fonts to come back.
export const BLOCKING_CSS_LIMIT_KB = 20;

/** @param {string} indexHtml  dist/index.html  @param {{name: string, text: string, gzBytes: number}[]} css  dist/assets/*.css */
export function evaluateCss(indexHtml, css, limitKb = BLOCKING_CSS_LIMIT_KB) {
  const errors = [];
  const linked = [...indexHtml.matchAll(/<link[^>]*rel="stylesheet"[^>]*href="[^"]*\/([^"/]+\.css)"/g)].map(m => m[1]);
  const blocking = css.filter(f => linked.includes(f.name));
  if (blocking.length === 0) errors.push('no render-blocking stylesheet found in index.html (the check would be empty)');
  for (const f of blocking) if (f.text.includes('@font-face')) errors.push(`@font-face rules are render-blocking again (${f.name})`);
  const totalKb = blocking.reduce((s, f) => s + f.gzBytes, 0) / 1024;
  if (totalKb > limitKb) errors.push(`render-blocking CSS ${totalKb.toFixed(1)} KB gzip > ${limitKb} KB`);
  return { ok: errors.length === 0, errors, totalKb };
}

// R3.6: route-level splitting (App.tsx). Measured 2026-11-15: entry 138.1 → 103.7 kB gzip as vite prints it (101.3 KiB as measured here) once ten pages became their
// own chunks. Budget ≈ 1.15× the measured entry — a page imported eagerly again (≥ 0.4 KB each, Continuum 7.5) shows
// up as a missing chunk below before it shows up here; the budget catches a heavy dependency pulled into the entry.
export const ENTRY_LIMIT_KB = 120;
export const LAZY_PAGES = ['Web3Page', 'VulnPage', 'AnnouncementsPage', 'SearchPage', 'SubscribePage', 'SourcesPage',
  'OpsPage', 'MitigatePage', 'WallPage', 'ContinuumPage'];

/** @param {{name: string, text: string, gzBytes: number}[]} files  dist/assets/*.js */
export function evaluateEntry(files, limitKb = ENTRY_LIMIT_KB) {
  const errors = [];
  const entry = files.filter(f => f.name.startsWith('index-'));
  if (entry.length !== 1) errors.push(`expected one entry chunk index-*.js, found ${entry.length}`);
  const totalKb = entry.reduce((s, f) => s + f.gzBytes, 0) / 1024;
  if (totalKb > limitKb) errors.push(`entry chunk ${totalKb.toFixed(1)} KB gzip > ${limitKb} KB`);
  for (const p of LAZY_PAGES) if (!files.some(f => f.name.startsWith(`${p}-`))) errors.push(`${p} is not its own chunk (imported eagerly again?)`);
  return { ok: errors.length === 0, errors, totalKb };
}
