// B6 guard: the repo has exactly one screenshot directory, docs/screenshots/, and every image in it says where its
// data came from (mock-* = scripts on ui/mock-data, live-* = scripts/live-shots.sh). Before 2026-10-24 ui/screenshots/
// held 18 stale v1/v2 PNGs next to docs/screenshots/, and README pointed at an unprefixed one.
import { describe, it, expect } from 'vitest';
import { existsSync, readdirSync } from 'fs';
import { dirname, resolve } from 'path';
import { fileURLToPath } from 'url';

const ui = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const docs = resolve(ui, '..', 'docs', 'screenshots');

describe('screenshot directory (B6)', () => {
  it('ui/screenshots/ does not exist (single directory: docs/screenshots/)', () => {
    expect(existsSync(resolve(ui, 'screenshots'))).toBe(false);
  });
  it('every PNG in docs/screenshots/ is prefixed mock- or live-', () => {
    const pngs = readdirSync(docs).filter(f => f.endsWith('.png'));
    expect(pngs.length).toBeGreaterThan(0); // an emptied directory is not a pass
    expect(pngs.filter(f => !/^(mock|live)-[a-z0-9-]+\.png$/.test(f))).toEqual([]);
  });
});
