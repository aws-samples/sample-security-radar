import type { EventSummary } from '@/types/site-data';

/** The wall's "Web3 损失排行": only corroborated incidents (V2+) and a name that is a name.
 *  Live 2026-11-16 the board read #1 "Is" $8.83B (a single article on BitMine's unrealised loss), #3 "Whale"
 *  $6.30B (a trader's closed position), #4 "https://t.co/…" $6.00B (a mis-read figure) — any web3 event with an
 *  amount was ranked, and the label was the title's first word. */
export const CORROBORATED: ReadonlySet<string> = new Set(['V2', 'V3', 'V4']);

export function lossBoard(events: EventSummary[], n = 6): EventSummary[] {
  return events
    .filter(e => e.domain === 'web3' && e.amount_usd_latest !== null && CORROBORATED.has(e.level))
    .sort((a, b) => (b.amount_usd_latest ?? 0) - (a.amount_usd_latest ?? 0))
    .slice(0, n);
}

/** The victim's name when the radar knows it; otherwise the headline without links, quote markers or tags. */
export function lossLabel(ev: EventSummary, max = 28): string {
  if (ev.entities[0]) return ev.entities[0];
  const t = ev.title
    .replace(/https?:\/+\S*|\bt\.co\/\S*/g, ' ')
    .replace(/(^|\s)>\s*/g, ' ')
    .replace(/#\w*Alerts?\b\s*/gi, '')
    .replace(/#(?=\w)/g, '')
    .replace(/\s+/g, ' ')
    .trim();
  if (t.length <= max) return t || '未命名事件';
  const cut = t.slice(0, max - 1);
  const sp = cut.lastIndexOf(' ');
  return `${sp > max / 2 ? cut.slice(0, sp) : cut}…`;      // at a word boundary when there is one
}
