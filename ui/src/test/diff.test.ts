/**
 * Patch path guard + unified-diff parser (utils/diff.ts). Fixture = the real captured Security Agent patch.
 * Liveness (by hand): `safeDataPath` → `return true` ⇒ "rejects" red; drop the hunk counters in
 * parseUnifiedDiff ⇒ "a removed '-- ' line" red.
 */
import { describe, it, expect } from 'vitest';
import { readFileSync } from 'fs';
import { resolve } from 'path';
import { safeDataPath, parseUnifiedDiff, diffStats } from '@/utils/diff';

const PATCH = readFileSync(resolve(__dirname, '../../mock-data/data/continuum/patches/demo-shop-php2shell.diff'), 'utf-8');

describe('safeDataPath', () => {
  it('accepts the published patch path', () => {
    expect(safeDataPath('continuum/patches/demo-shop-php2shell.diff')).toBe(true);
  });
  it.each([
    '../../etc/passwd', 'continuum/../../x', '/abs', 'a\n', 'a\r', 'https://x', 'a\\b', '', './a', 'a//b', 'a/', '%2e%2e/x', 'a b',
  ])('rejects %j', p => {
    expect(safeDataPath(p)).toBe(false);
  });
  it('rejects non-strings', () => {
    expect(safeDataPath(null)).toBe(false);
    expect(safeDataPath(42)).toBe(false);
  });
});

describe('parseUnifiedDiff', () => {
  const files = parseUnifiedDiff(PATCH);
  it('one entry per file with +/- counts (live patch: 4 files, +4 −4)', () => {
    expect(files.map(f => f.path)).toEqual(['.gitlab-ci.yml', 'Dockerfile', 'composer.json', 'src/index.php']);
    expect(diffStats(files)).toEqual({ files: 4, added: 4, removed: 4 });
  });
  it('classifies lines and numbers them', () => {
    const docker = files[1];
    const del = docker.lines.find(l => l.kind === 'del')!;
    const add = docker.lines.find(l => l.kind === 'add')!;
    expect(del).toMatchObject({ text: 'FROM php:8.3.30-apache', oldNo: 1, newNo: null });
    expect(add).toMatchObject({ text: 'FROM php:8.3.36-apache', oldNo: null, newNo: 1 });
    expect(docker.lines.filter(l => l.kind === 'hunk')).toHaveLength(1);
    expect(docker.lines.filter(l => l.kind === 'meta').map(l => l.text)[0]).toMatch(/^index /);
  });
  it('"\\ No newline at end of file" is meta, not content', () => {
    const c = files[2];
    expect(c.lines.some(l => l.kind === 'meta' && l.text.startsWith('\\'))).toBe(true);
    expect(c.added).toBe(1);
  });
  it('a removed line whose text starts with "-- " is content, not a new file header', () => {
    const d = ['--- a/q.sql', '+++ b/q.sql', '@@ -1,2 +1,2 @@', '--- old comment', '+-- new comment', ' select 1;', ''].join('\n');
    const f = parseUnifiedDiff(d);
    expect(f).toHaveLength(1);
    expect(f[0]).toMatchObject({ path: 'q.sql', added: 1, removed: 1 });
    expect(f[0].lines.find(l => l.kind === 'del')?.text).toBe('-- old comment');
  });
  it('bare unified diff with two files, new + deleted file paths', () => {
    const d = ['--- /dev/null', '+++ b/new.txt', '@@ -0,0 +1 @@', '+hi', '--- a/old.txt', '+++ /dev/null', '@@ -1 +0,0 @@', '-bye'].join('\n');
    const f = parseUnifiedDiff(d);
    expect(f.map(x => [x.path, x.added, x.removed])).toEqual([['new.txt', 1, 0], ['old.txt', 0, 1]]);
  });
  it('CRLF and empty input', () => {
    expect(parseUnifiedDiff('')).toEqual([]);
    expect(parseUnifiedDiff(PATCH.replace(/\n/g, '\r\n')).map(f => f.added)).toEqual(files.map(f => f.added));
  });
});
