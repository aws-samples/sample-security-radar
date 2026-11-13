/** Attack-tx breakdown on the event page (M4.1 E3): amounts as a reader counts them, roles named, the sender's take. */
import { describe, it, expect } from 'vitest';
import { fmtAmount, fmtUsd, senderTake, senderTakeUsd, who } from '@/utils/attackTxView';
import type { AttackTxs } from '@/types/site-data';

const tx = {
  tx: '0x3f6b', chain: 'avalanche', block: 1, t: '2026-10-28T00:00:03Z', status: 'success', sender: '0x6ff1c3ff00000000000000000000000000000001',
  target: '0xf09d', transfers: 2, tokens_total: 1,
  tokens: [{ token: '0xb97e', symbol: 'USDC', transfers: 2,
    gainer: { address: '0x6ff1c3ff00000000000000000000000000000001', role: '发起地址', amount: 1013353.611687, raw: '1013353611687' },
    loser: { address: '0xe25cb54500000000000000000000000000000002', role: null, amount: 1013353.611686, raw: '1013353611686' } },
    // a token the sender did not end up with (gainer is a pool): not part of the take
    { token: '0xaaaa', symbol: 'WAVAX', transfers: 1,
      gainer: { address: '0x9999000000000000000000000000000000000003', role: null, amount: 12, raw: '12' }, loser: null }],
} as AttackTxs['txs'][number];

describe('attackTxView', () => {
  it('formats large and small token amounts, and unknown decimals', () => {
    expect(fmtAmount(1013353.611687)).toBe('1,013,353.61');
    expect(fmtAmount(0.17360212)).toBe('0.173602');
    expect(fmtAmount(null)).toBe('—');
  });
  it('names the role the receipt gives, else the address only', () => {
    expect(who(tx.tokens[0].gainer)).toBe('发起地址 0x6ff1…0001');
    expect(who(tx.tokens[0].loser)).toBe('0xe25c…0002');
  });
  it("sums up the sender's take (the attacker's, in a typical exploit)", () => {
    expect(senderTake(tx)).toEqual(['1,013,353.61 USDC']);
  });
  it('values amounts in USD only when priced, never as $0', () => {
    expect(fmtUsd(1012690.04)).toBe('$1.01M');
    expect(fmtUsd(5_780_000_000)).toBe('$5.78B');
    expect(fmtUsd(12_345)).toBe('$12.3K');
    expect(fmtUsd(null)).toBe('');
    expect(senderTakeUsd(tx)).toBeNull();                                   // nothing priced
    const priced = { ...tx, tokens: [{ ...tx.tokens[0], gainer: { ...tx.tokens[0].gainer!, usd: 1012690.04 } }, tx.tokens[1]] };
    expect(senderTakeUsd(priced)).toEqual({ usd: 1012690.04, partial: false });   // the pool's WAVAX is not the take
    const two = { ...priced, tokens: [...priced.tokens, { ...tx.tokens[0], token: '0xbbbb', symbol: 'JUNK' }] };
    expect(senderTakeUsd(two)).toEqual({ usd: 1012690.04, partial: true });
  });
});
