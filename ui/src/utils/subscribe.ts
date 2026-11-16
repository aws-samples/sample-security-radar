import type { FeedEntry } from '@/types/site-data';

/** One feed as the page shows it: two addresses per format — the site's (browser / Basic Auth) and the token API's. */
export interface FeedRow {
  name: string; title: string; items: number; filter: string;
  atom: { site: string; api: string }; json: { site: string; api: string };
}

// a feed document path as Publish writes it (radar.feeds): feeds/<name>.json|atom — anything else is not linked
const FEED_PATH = /^feeds\/[a-z0-9][a-z0-9-]{0,40}\.(json|atom)$/;

const WORDS: Record<string, string> = { severity: '级别', domain: '域', exchanges: '交易所', has_waf_pack: '已有 WAF 规则包' };

/** The feed's filters in words; no filter is said, not left blank. */
export function filterText(filters: Record<string, unknown>): string {
  const parts = Object.entries(filters).map(([k, v]) => {
    const name = WORDS[k] ?? k;
    if (v === true) return name;
    if (Array.isArray(v)) return v.length > 4 ? `${name}：${v.length} 个` : `${name}：${v.join(' / ')}`;
    return `${name}：${String(v)}`;
  });
  return parts.length ? parts.join(' · ') : '不筛选';
}

/** base = the site root as the browser sees it (origin + path, trailing slash). A row whose paths are not feed paths
 *  is dropped: an address the page shows is one a reader will paste into a client with a credential. */
export function feedRows(feeds: FeedEntry[], base: string): FeedRow[] {
  const root = base.endsWith('/') ? base : `${base}/`;
  const both = (p: string) => ({ site: `${root}data/${p}`, api: `${root}api/data/${p}` });
  return feeds
    .filter(f => FEED_PATH.test(f.atom) && FEED_PATH.test(f.json))
    .map(f => ({ name: f.name, title: f.title, items: f.items, filter: filterText(f.filters as Record<string, unknown>),
                 atom: both(f.atom), json: both(f.json) }));
}
