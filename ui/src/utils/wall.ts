/**
 * wall.ts — single-source view logic for the wall (#/wall): which events get NOW labels, and the L2 drawer URL.
 * Pure; tested in src/test/wall.test.ts.
 */
import type { EventSummary, NowItem } from '@/types/site-data';
import type { LeaderLabelItem } from '@/components/radar/LeaderLabels';

/**
 * NOW (backend-ranked, ≤3) → radar leader labels, rank = backend order. The old 3D labels picked "the 3 newest
 * P0" instead (spec 01 §6.4 ③), which labelled different events than the NOW board beside it.
 * A NOW id missing from the list (publisher race) gets no label — the NOW board shows it as "摘要缺失".
 */
export function nowLabels(now: NowItem[] | null | undefined, events: EventSummary[]): LeaderLabelItem[] {
  if (!now) return [];
  const byId = new Map(events.map(e => [e.event_id, e]));
  const out: LeaderLabelItem[] = [];
  now.forEach((n, i) => {
    const ev = byId.get(n.event_id);
    if (ev) out.push({ id: ev.event_id, rank: i + 1, title: ev.title, severity: ev.severity, impact: ev.impact });
  });
  return out;
}

/** Event ids are publisher-generated slugs (ev_<16 hex> today). fullmatch — `$` alone would accept "id\n". */
const SAFE_ID = /^[A-Za-z0-9_-]{1,64}$/;

/**
 * `?event=<id>` → the id the drawer should open, or null. The value comes from the URL (anyone can craft a
 * link), and it is spliced into `./data/events/<id>.json` — so anything but a plain slug is refused.
 */
export function drawerEventId(params: URLSearchParams): string | null {
  const v = params.get('event');
  if (v === null || v === '') return null;
  if (!SAFE_ID.test(v) || v.includes('\n')) {
    console.warn(`[wall] ignored unsafe ?event= value (${JSON.stringify(v.slice(0, 80))})`);
    return null;
  }
  return v;
}

/** Link target that opens the L2 drawer on the wall (refresh-safe; Back closes it). */
export function drawerHref(eventId: string): string {
  return `/wall?event=${encodeURIComponent(eventId)}`;
}
