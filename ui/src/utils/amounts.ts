import type { AmountPoint } from '@/types/site-data';

/** Measure of an amount point; points published before kinds existed are losses (that is what they were treated as). */
export const kindOf = (p: AmountPoint): NonNullable<AmountPoint['kind']> => p.kind ?? 'loss';

/** Only loss points draw the loss curve; freezes and sub-amounts in the story (borrows, sales, liquidations) are not a loss
 *  estimate (live 2026-10-30, Binance: the curve jumped between $30.5M freezes and a $165B "user assets" figure). */
export function lossPoints(points: AmountPoint[]): AmountPoint[] {
  return points.filter(p => kindOf(p) === 'loss');
}

export function measureCounts(points: AmountPoint[]): Record<NonNullable<AmountPoint['kind']>, number> {
  const out = { loss: 0, frozen: 0, context: 0 };
  for (const p of points) out[kindOf(p)] += 1;
  return out;
}
