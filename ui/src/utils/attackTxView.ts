import type { AttackTxs } from '@/types/site-data';

type Tx = AttackTxs['txs'][number];
type Side = Tx['tokens'][number]['gainer'];

export const short = (a: string) => (a.length > 12 ? `${a.slice(0, 6)}…${a.slice(-4)}` : a);

/** Token units as a reader counts them: grouped integers for large amounts, up to 6 significant digits for small ones;
 *  "—" when decimals() is unknown (the raw integer is in the tooltip). */
export function fmtAmount(v: number | null | undefined): string {
  if (v === null || v === undefined) return '—';
  if (v === 0) return '0';
  if (Math.abs(v) >= 1000) return v.toLocaleString('en-US', { maximumFractionDigits: 2 });
  return Number(v.toPrecision(6)).toString();
}

/** "发起地址 0x6ff1…c3ff" — the role the receipt names, then the short address. */
export const who = (s: Side) => (s ? `${s.role ? `${s.role} ` : ''}${short(s.address)}` : '—');

export const tokenName = (t: Tx['tokens'][number]) => t.symbol ?? short(t.token);

/** One line under the card: what the sender ended up with (the attacker's take in a typical exploit). */
export function senderTake(tx: Tx): string[] {
  return tx.tokens.filter(t => t.gainer?.role === '发起地址').map(t => `${fmtAmount(t.gainer!.amount)} ${tokenName(t)}`);
}
