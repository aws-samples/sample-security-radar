// Pure evaluation for the scoped three.js exception (docs/design/UI-BRIEF-v3.md §0); the runner is check-chunks.mjs.
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
