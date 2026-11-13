import type { SearchRow } from '@/types/site-data';

/** Every whitespace-separated term must match the title, a CVE, an entity or the id (case-insensitive).
 *  Newest first-seen first; at most `limit` rows. */
export function searchRows(rows: SearchRow[], query: string, limit = 200): SearchRow[] {
  const terms = query.trim().toLowerCase().split(/\s+/).filter(Boolean);
  if (terms.length === 0) return [];
  const hay = (r: SearchRow) => [r.t, r.id, ...r.c, ...r.e].join(' ').toLowerCase();
  return rows.filter(r => { const h = hay(r); return terms.every(t => h.includes(t)); })
    .sort((a, b) => b.f.localeCompare(a.f))
    .slice(0, limit);
}

export interface SearchMonth { month: string; events: number }
type Get = (url: string) => Promise<Pick<Response, 'ok' | 'status' | 'json'>>;

/** What the page is told while loading. No callback runs once `live()` is false (the page unmounted). */
export interface SearchSink {
  /** detailCap = index.detail_cap (Limits.PUBLISH_MAX_EVENTS, the one source of the cap); null when the index predates it */
  index(months: SearchMonth[], detailCap: number | null): void;
  /** one batch of shards: their rows, how many shards it covered, and the months among them that failed to load */
  shards(rows: SearchRow[], count: number, failed: string[]): void;
  error(message: string): void;
}

/** One month shard, or null when it did not load (HTTP error, network error, not JSON, not a search shard).
 *  null ≠ an empty month: the page must say the month is missing, not silently show fewer hits. */
export async function fetchShard(get: Get, month: string): Promise<SearchRow[] | null> {
  try {
    const r = await get(`./data/search/${month}.json`);
    if (!r.ok) return null;
    const d = await r.json();
    if (d?.kind !== 'search-shard' || !Array.isArray(d.events)) return null;
    return d.events as SearchRow[];
  } catch {
    return null;   // network error or not JSON (SPA fallback serving index.html): reported as a failed month
  }
}

/** index.json, then the month shards newest first, 8 at a time. The index's kind is checked like the Ops / Mitigate
 *  pages check theirs: an SPA fallback serving index.html must read as "unexpected data kind", not a SyntaxError. */
export async function loadSearch(get: Get, live: () => boolean, sink: SearchSink): Promise<void> {
  try {
    const r = await get('./data/search/index.json');
    if (!r.ok) throw new Error(`HTTP ${r.status}`);
    const idx = await r.json().catch(() => null);
    if (idx?.kind !== 'search-index' || !Array.isArray(idx.months)) throw new Error('unexpected data kind');
    if (!live()) return;
    const ms: SearchMonth[] = idx.months;
    sink.index(ms, Number.isInteger(idx.detail_cap) ? idx.detail_cap : null);
    for (let i = 0; i < ms.length; i += 8) {
      const batch = ms.slice(i, i + 8);
      const got = await Promise.all(batch.map(m => fetchShard(get, m.month)));
      if (!live()) return;
      sink.shards(got.flatMap(g => g ?? []), batch.length, batch.filter((_, k) => got[k] === null).map(m => m.month));
    }
  } catch (e: unknown) {
    if (live()) sink.error(String(e));
  }
}
