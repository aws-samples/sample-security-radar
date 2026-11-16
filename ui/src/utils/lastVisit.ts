/** R3.4 「有什么新的」: the moment the reader last came, kept in this browser only (localStorage, no account).
 *  A visit is a session: coming back within SESSION_GAP_MS keeps the same boundary, so reloading the page does not
 *  clear the "new" marks the reader has not looked at yet. */
export const SESSION_GAP_MS = 30 * 60 * 1000;
const PREV = 'sr-visit-prev';
const NOW = 'sr-visit-now';

type Store = Pick<Storage, 'getItem' | 'setItem'>;

/** Call once per page load. Returns the boundary (ISO time of the previous visit) or null on a first visit. */
export function rollVisit(store: Store, nowMs: number): string | null {
  const last = Number(store.getItem(NOW) || 0);
  if (last && nowMs - last > SESSION_GAP_MS) store.setItem(PREV, String(last));
  store.setItem(NOW, String(nowMs));
  const prev = Number(store.getItem(PREV) || 0);
  return prev ? new Date(prev).toISOString() : null;
}

/** First seen after the previous visit. No boundary (first visit) ⇒ nothing is "new": everything would be. */
export function isNewSince(firstSeen: string | null | undefined, boundary: string | null): boolean {
  return Boolean(boundary && firstSeen && firstSeen > boundary);
}

/** R3.4 「按首见排序」: every event, newest first seen first, split at the previous visit — `fresh` arrived after it,
 *  `older` did not. Nothing is dropped or added (the filtered list is the input); ties keep the input order. An event
 *  without a first_seen sorts last and is never "fresh". No boundary (first visit) ⇒ everything is in `older`. */
export function byFirstSeen<T extends { first_seen?: string | null }>(events: T[], boundary: string | null): { fresh: T[]; older: T[] } {
  const sorted = events.map((e, i) => [e, i] as const)
    .sort(([a, i], [b, j]) => (b.first_seen ?? '').localeCompare(a.first_seen ?? '') || i - j)
    .map(([e]) => e);
  const fresh = sorted.filter(e => isNewSince(e.first_seen, boundary));
  return { fresh, older: sorted.slice(fresh.length) };
}

/** The rows of 「按首见排序」: the fresh events, the previous-visit line, the rest. The line is drawn only when it
 *  separates something (fresh above AND older below) — a line at the top or the bottom says nothing. */
export function visitLineRows<T>(order: { fresh: T[]; older: T[] }, boundary: string | null): Array<{ ev: T } | { line: string }> {
  const line = boundary && order.fresh.length && order.older.length
    ? [{ line: `上次来访 · ${boundary.slice(5, 16).replace('T', ' ')} UTC` }] : [];
  return [...order.fresh.map(ev => ({ ev })), ...line, ...order.older.map(ev => ({ ev }))];
}
