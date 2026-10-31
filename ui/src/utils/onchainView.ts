import type { Onchain, OnchainRow } from '@/types/site-data';

/** Explorer of each chain the station reads (radar.onchain.TOKENS); an unknown chain gets no link (not a guessed one). */
const EXPLORER: Record<string, string> = {
  ethereum: 'https://etherscan.io', arbitrum: 'https://arbiscan.io', avalanche: 'https://snowtrace.io',
  base: 'https://basescan.org', bsc: 'https://bscscan.com',
};

export function txUrl(chain: string, tx: string): string | null {
  const host = EXPLORER[chain];
  return host && /^0x[0-9a-fA-F]{64}$/.test(tx) ? `${host}/tx/${tx}` : null;
}

export const hhmmss = (t: string) => t.slice(11, 19);

/** One table line: what moved where (outflow) or who froze whom (freeze). The shortened form a report used for an
 *  address is shown beside the label so a reader can match it to the article. */
export function describe(r: OnchainRow): { kind: string; who: string } {
  const ev = (label?: string, short?: string) => `${label ?? ''}${short ? `（报道写作 ${short}）` : ''}`;
  if (r.kind === 'freeze') return { kind: `${r.issuer ?? '发行方'} 冻结`, who: ev(r.label, r.address_evidence) };
  return { kind: '转出', who: `${ev(r.from_label, r.from_evidence)} → ${ev(r.to_label, r.to_evidence)}` };
}

export interface OnchainSummary { outflow: [string, number][]; freezes: [string, number][]; delegated: number; checked: number }

export function summary(o: Onchain): OnchainSummary {
  return {
    outflow: Object.entries(o.totals.victim_outflow_by_token).sort((a, b) => b[1] - a[1]),
    freezes: Object.entries(o.totals.freezes_by_issuer).sort((a, b) => b[1] - a[1]),
    delegated: o.delegation.filter(d => d.delegate).length,
    checked: o.delegation.length,
  };
}
