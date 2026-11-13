/** Amount measures on the event page: the loss curve never mixes in freezes or sub-amounts. */
import { describe, it, expect } from 'vitest';
import { lossPoints, measureCounts } from '@/utils/amounts';
import type { AmountPoint } from '@/types/site-data';

const p = (value: number, kind?: AmountPoint['kind']): AmountPoint => ({ value, source_id: 's', observed_at: '2026-10-29T21:00:00Z', ...(kind ? { kind } : {}) });

describe('amount measures', () => {
  const pts = [p(5.78e9, 'loss'), p(9.71e8, 'frozen'), p(1.6512e11, 'context'), p(2.5e9), p(2.35e11, 'outlier')];
  // the $235B outlier (a bank's balance sheet, live 2026-11-04) never draws the loss curve
  it('the loss curve keeps loss points and legacy points without a kind', () => {
    expect(lossPoints(pts).map(x => x.value)).toEqual([5.78e9, 2.5e9]);
  });
  it('counts every measure', () => {
    expect(measureCounts(pts)).toEqual({ loss: 2, frozen: 1, context: 1, outlier: 1 });
  });
});
