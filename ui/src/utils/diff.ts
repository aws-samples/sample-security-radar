/**
 * Patch-path guard + zero-dependency unified-diff parser for the "在你的环境中" patch viewer.
 * Pure functions (unit-tested in src/test/diff.test.ts, mutations registered in the test file header).
 */

/** All patch-viewer thresholds in one place (degradation-and-guards §5: no scattered magic numbers). */
export const PATCH_LIMITS = {
  /** Above this many bytes the viewer renders only the first `truncatedLines` lines. */
  maxBytes: 256 * 1024,
  truncatedLines: 400,
} as const;

/**
 * Is `p` safe to splice into `./data/${p}`? The path comes from published JSON (response.patches[].path), i.e.
 * external data: a hostile or buggy publisher must not be able to point the viewer at another origin or climb
 * out of /data. Mirrors the global pathguard rule — whole-string match (no `$`-before-newline bypass), no
 * empty / `.` / `..` segments (which also rejects a leading `/` and `//`), no scheme (`:`), no backslash.
 */
export function safeDataPath(p: unknown): p is string {
  if (typeof p !== 'string' || p.length === 0 || p.length > 512) return false;
  // JS `$` without the m flag only matches at end-of-input, but check \n/\r explicitly anyway (pathguard trap).
  if (/[\r\n]/.test(p)) return false;
  if (!/^[A-Za-z0-9._/-]+$/.test(p)) return false;
  return p.split('/').every(seg => seg !== '' && seg !== '.' && seg !== '..');
}

export type DiffLineKind = 'add' | 'del' | 'ctx' | 'hunk' | 'meta';

export interface DiffLine {
  kind: DiffLineKind;
  text: string;
  /** 1-based line number in the old / new file; null where it does not apply. */
  oldNo: number | null;
  newNo: number | null;
}

export interface DiffFile {
  /** Display path: the new path, or the old one for deletions. */
  path: string;
  oldPath: string | null;
  newPath: string | null;
  added: number;
  removed: number;
  lines: DiffLine[];
}

function stripPrefix(p: string): string | null {
  const t = p.trim().split('\t')[0];
  if (t === '/dev/null') return null;
  return t.replace(/^[ab]\//, '');
}

function newFile(oldPath: string | null = null, newPath: string | null = null): DiffFile {
  return { path: newPath ?? oldPath ?? '(unknown)', oldPath, newPath, added: 0, removed: 0, lines: [] };
}

/**
 * Parse `git diff` / unified-diff text into per-file line lists.
 * Hunk bodies are consumed by the counts in the `@@ -a,b +c,d @@` header, so a removed line whose text itself
 * starts with `-- ` (e.g. a SQL comment) is never mistaken for a new `--- file` header.
 */
export function parseUnifiedDiff(text: string): DiffFile[] {
  const files: DiffFile[] = [];
  let cur: DiffFile | null = null;
  let oldLeft = 0, newLeft = 0, oldNo = 0, newNo = 0;
  const raw = text.replace(/\r\n/g, '\n').split('\n');
  if (raw.length > 0 && raw[raw.length - 1] === '') raw.pop();

  const push = (l: DiffLine) => {
    if (!cur) { cur = newFile(); files.push(cur); }
    cur.lines.push(l);
  };

  for (const line of raw) {
    const inHunk = oldLeft > 0 || newLeft > 0;
    if (inHunk && !line.startsWith('diff --git ')) {
      const c = line.charAt(0);
      if (c === '+') { push({ kind: 'add', text: line.slice(1), oldNo: null, newNo: newNo++ }); newLeft--; cur!.added++; continue; }
      if (c === '-') { push({ kind: 'del', text: line.slice(1), oldNo: oldNo++, newNo: null }); oldLeft--; cur!.removed++; continue; }
      if (c === '\\') { push({ kind: 'meta', text: line, oldNo: null, newNo: null }); continue; }
      // ' ' context, or an empty line some tools emit for an empty context line
      push({ kind: 'ctx', text: line.slice(1), oldNo: oldNo++, newNo: newNo++ });
      oldLeft--; newLeft--;
      continue;
    }
    oldLeft = 0; newLeft = 0;
    if (line.startsWith('diff --git ')) {
      const m = line.match(/^diff --git a\/(.+?) b\/(.+)$/);
      cur = newFile(m ? m[1] : null, m ? m[2] : null);
      files.push(cur);
      continue;
    }
    if (line.startsWith('--- ')) {
      // A bare unified diff (no `diff --git` line) starts a new file at every `---` that follows a hunk.
      if (!cur || cur.lines.some(l => l.kind === 'hunk')) { cur = newFile(); files.push(cur); }
      cur.oldPath = stripPrefix(line.slice(4));
      cur.path = cur.newPath ?? cur.oldPath ?? cur.path;
      continue;
    }
    if (line.startsWith('+++ ') && cur) {
      cur.newPath = stripPrefix(line.slice(4));
      cur.path = cur.newPath ?? cur.oldPath ?? cur.path;
      continue;
    }
    const h = line.match(/^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@/);
    if (h) {
      oldNo = Number(h[1]); oldLeft = h[2] === undefined ? 1 : Number(h[2]);
      newNo = Number(h[3]); newLeft = h[4] === undefined ? 1 : Number(h[4]);
      push({ kind: 'hunk', text: line, oldNo: null, newNo: null });
      continue;
    }
    // index …, new file mode …, "\ No newline" outside a hunk, preamble text
    push({ kind: 'meta', text: line, oldNo: null, newNo: null });
  }
  return files;
}

/** Totals for the viewer header / aria-label. */
export function diffStats(files: DiffFile[]): { files: number; added: number; removed: number } {
  return files.reduce((s, f) => ({ files: s.files + 1, added: s.added + f.added, removed: s.removed + f.removed }),
    { files: 0, added: 0, removed: 0 });
}
