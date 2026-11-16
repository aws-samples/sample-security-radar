/** R3.1 — a cut listing says what it is out of; a whole one says nothing. */
import { describe, expect, it } from 'vitest';
import { cutNote } from '@/utils/listing';

const w = (listed: number, total: number) => ({ days: 60, total, listed, cap: 500,
  by_severity: { P0: 0, P1: 0, P2: total }, by_domain: { vuln: total, web3: 0, incident: 0 } });

describe('cut note', () => {
  it('says listed / total, the window and where the rest is', () => {
    expect(cutNote(w(500, 4348))).toBe('列出 500 / 4,348 个（60 天内）：近 24 小时有更新的都在，其余 3,848 个用搜索');
  });
  it('says nothing when nothing was cut, or when an older publisher did not say', () => {
    expect(cutNote(w(120, 120))).toBeNull();
    expect(cutNote(null)).toBeNull();
  });
});
