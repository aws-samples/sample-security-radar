import type { EventSummary } from '@/types/site-data';

/** Disposition line on the verdict (radar.triage, written by scripts/triage.py — the site never writes). */
export function triageLine(t: EventSummary['triage'], at: (iso: string) => string): string {
  if (!t) return '未处置';
  return `${t.label}${t.note ? ` · ${t.note}` : ''} · ${t.by} ${at(t.at)}`;
}
