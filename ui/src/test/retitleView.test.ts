/** The corrected title says so on the page: who, when, the cited source (safe links only) and the original title. */
import { describe, it, expect } from 'vitest';
import { titleFix } from '@/utils/retitleView';

const fix = { title: 'Binance CEX — Unauthorized Withdrawals', original: 'Binance CEX — Key Leaked via Infrastructure',
  source: 'https://www.euronews.com/2026/10/30/how', note: '币安官方：未发现私钥泄露', by: 'operator', at: '2026-11-02T05:00:00Z' };

describe('titleFix', () => {
  it('names the correction, its source host and keeps the original title', () => {
    const t = titleFix({ title_override: fix }, iso => iso.slice(0, 10))!;
    expect(t.text).toBe('标题已按根因修正 · operator · 2026-11-02 · 币安官方：未发现私钥泄露');
    expect(t.host).toBe('euronews.com');
    expect(t.href).toBe(fix.source);
    expect(t.original).toBe('Binance CEX — Key Leaked via Infrastructure');
  });
  it('shows nothing for a title nobody corrected, and no link for an unsafe source', () => {
    expect(titleFix({ title_override: null }, iso => iso)).toBeNull();
    expect(titleFix({ title_override: { ...fix, source: 'javascript:alert(1)' } }, iso => iso)!.href).toBeUndefined();
  });
});
