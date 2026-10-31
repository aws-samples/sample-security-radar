/** Attack flow on the event page: phases in attack order, each anchored on its earliest report; one-phase stories hide it. */
import { describe, it, expect } from 'vitest';
import { attackFlow, missingPhases, showFlow } from '@/utils/attackFlow';
import type { ItemRef } from '@/types/site-data';

const it_ = (id: string, phase: ItemRef['phase'], at: string) => ({ item_id: id, phase, published_at: at } as ItemRef);

describe('attackFlow', () => {
  const items = [it_('f2', 'freeze', '2026-10-29T21:29:00Z'), it_('d1', 'drain', '2026-10-29T20:51:00Z'),
    it_('f1', 'freeze', '2026-10-29T21:14:00Z'), it_('o', 'other', '2026-10-29T20:00:00Z'), it_('s', 'statement', '2026-10-29T22:23:00Z')];
  it('orders by attack phase, anchors each on its earliest report, drops "other"', () => {
    expect(attackFlow(items).map(s => [s.phase, s.count, s.firstItemId])).toEqual([['drain', 1, 'd1'], ['freeze', 2, 'f1'], ['statement', 1, 's']]);
  });
  it('anchors on the published evidence time, not a date-only midnight (live 2026-10-30: 转出 at 10-29 00:00)', () => {
    const db = { ...it_('db', 'drain', '2026-10-29T00:00:00Z'), evidence_at: '2026-10-29T20:51:00Z' } as ItemRef;
    const flash = { ...it_('d1', 'drain', '2026-10-29T20:51:00Z'), evidence_at: '2026-10-29T20:51:00Z' } as ItemRef;
    const [drain] = attackFlow([db, flash]);
    expect(drain.firstAt).toBe('2026-10-29T20:51:00Z');
  });
  it('a single-phase story has no flow', () => {
    expect(showFlow(attackFlow([it_('d1', 'drain', '2026-10-29T20:51:00Z')]))).toBe(false);
    expect(showFlow(attackFlow(items))).toBe(true);
  });
});

describe('web3 incidents keep the same format with one phase', () => {
  const one = attackFlow([it_('db', 'drain', '2026-10-20T00:00:00Z')]);
  it('a web3 incident shows its flow from one phase (live 2026-10-30: 136 of 141 had none), an advisory still needs two', () => {
    expect(showFlow(one, true)).toBe(true);
    expect(showFlow(one)).toBe(false);
  });
  it('lists the attack phases nobody has reported yet, in attack order', () => {
    expect(missingPhases(one)).toEqual(['洗钱', '冻结', '官方回应', '归因', '追回']);
  });
});

