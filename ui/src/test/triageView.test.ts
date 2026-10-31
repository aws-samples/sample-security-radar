/** The verdict says who dispositioned the event and when; no record reads 未处置 (never a blank). */
import { describe, it, expect } from 'vitest';
import { triageLine } from '@/utils/triageView';

describe('triageLine', () => {
  it('names status, note, operator and time', () => {
    expect(triageLine({ status: 'tracking', label: '跟进中', note: '链上复盘跟进中', by: 'operator', at: '2026-10-31T03:00:00Z' }, () => '10-31 03:00'))
      .toBe('跟进中 · 链上复盘跟进中 · operator 10-31 03:00');
  });
  it('says 未处置 when nobody has dispositioned it', () => {
    expect(triageLine(null, () => '')).toBe('未处置');
    expect(triageLine(undefined, () => '')).toBe('未处置');
  });
});
