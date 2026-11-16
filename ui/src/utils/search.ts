import type { SearchRow } from '@/types/site-data';
import { safeHref } from '@/utils/safeHref';

export const SEARCH_LIMIT = 200;

/** R3.5 filters: domain, the lowest severity to show, a first-seen month (yyyy-mm). Absent = no constraint. */
export interface SearchFilters { domain?: string; severity?: 'P0' | 'P1' | 'P2'; month?: string }

const SEV = { P0: 0, P1: 1, P2: 2 } as const;

/** One row per event id — a re-published event can sit in two month shards (its first_seen moved); the newest
 *  (latest `u`) wins (R3.5, audit 03 Q3). */
export function dedupe(rows: SearchRow[]): SearchRow[] {
  const by = new Map<string, SearchRow>();
  for (const r of rows) {
    const had = by.get(r.id);
    if (!had || r.u > had.u) by.set(r.id, r);
  }
  return [...by.values()];
}

/** Relevance of a row that matches every term: an exact id / CVE beats a title word, a title word beats an entity
 *  or a substring; the whole query as a phrase in the title adds more. */
function score(r: SearchRow, terms: string[], phrase: string): number {
  const title = r.t.toLowerCase();
  let n = terms.length > 1 && title.includes(phrase) ? 15 : 0;
  for (const t of terms) {
    if (r.id.toLowerCase() === t) n += 50;
    else if (r.c.some(c => c.toLowerCase() === t)) n += 40;
    else if (new RegExp(`(^|[^\\p{L}\\p{N}])${t.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}($|[^\\p{L}\\p{N}])`, 'u').test(title)) n += 10;
    else if (title.includes(t)) n += 5;
    else n += 4;                                   // matched an entity, a CVE prefix or the id
  }
  return n;
}

/** Every whitespace-separated term must match the title, a CVE, an entity or the id (case-insensitive), within the
 *  filters. Most relevant first, then most severe, then newest; `total` is how many matched before the limit. */
export function searchHits(rows: SearchRow[], query: string, filters: SearchFilters = {}, limit = SEARCH_LIMIT):
  { hits: SearchRow[]; total: number } {
  const terms = query.trim().toLowerCase().split(/\s+/).filter(Boolean);
  if (terms.length === 0) return { hits: [], total: 0 };
  const phrase = terms.join(' ');
  const hay = (r: SearchRow) => [r.t, r.id, ...r.c, ...r.e].join(' ').toLowerCase();
  const ok = (r: SearchRow) => (!filters.domain || r.d === filters.domain)
    && (!filters.severity || SEV[r.s] <= SEV[filters.severity])
    && (!filters.month || r.f.startsWith(filters.month));
  const all = dedupe(rows).filter(r => ok(r) && terms.every(t => hay(r).includes(t)))
    .map(r => ({ r, n: score(r, terms, phrase) }))
    .sort((a, b) => b.n - a.n || SEV[a.r.s] - SEV[b.r.s] || b.r.f.localeCompare(a.r.f));
  return { hits: all.slice(0, limit).map(x => x.r), total: all.length };
}

/** The hits only (kept for callers that need no count). */
export function searchRows(rows: SearchRow[], query: string, limit = SEARCH_LIMIT, filters: SearchFilters = {}): SearchRow[] {
  return searchHits(rows, query, filters, limit).hits;
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
    // the newest 3 months first, so recent hits show while older shards load (R3.5); then 8 at a time
    for (let i = 0; i < ms.length; i += i === 0 ? 3 : 8) {
      const batch = ms.slice(i, i === 0 ? 3 : i + 8);
      const got = await Promise.all(batch.map(m => fetchShard(get, m.month)));
      if (!live()) return;
      sink.shards(got.flatMap(g => g ?? []), batch.length, batch.filter((_, k) => got[k] === null).map(m => m.month));
    }
  } catch (e: unknown) {
    if (live()) sink.error(String(e));
  }
}

/** R3.5: where a hit leads — its detail page when Publish wrote one (row.p), else the source the event started from
 *  (row.r, http(s) only via safeHref), else nowhere (said, not a dead link). */
export type HitLink = { kind: 'page'; to: string } | { kind: 'source'; href: string } | { kind: 'none' };
export function hitLink(r: SearchRow): HitLink {
  if (r.p) return { kind: 'page', to: `/events/${r.id}` };
  const href = safeHref(r.r);
  return href ? { kind: 'source', href } : { kind: 'none' };
}
