import type { P0Event, P0Group, P0Tile, SecurityRadarSiteDataPublishedToS3ReadByTheUI } from '@/types/site-data';

/** p0.json (radar.publish.p0_doc): every vulnerability P0 of the publish window on its product tile (radar.p0class). */
export type P0Doc = Extract<SecurityRadarSiteDataPublishedToS3ReadByTheUI, { kind: 'p0' }>;
export type { P0Event, P0Group, P0Tile };

/**
 * The tile's mark: two characters that stand for the product — the wall has no vendor logos (trademarks, and nothing
 * is fetched from third parties), so the mark is drawn from the label. 「Apache HTTP Server」 → AH, 「Nginx」 → Ng,
 * 「路由器 / NAS」 → 路由, 「.NET」 → NE, 「Python 框架 (Django 等)」 → Dj (a mixed label is marked by its example).
 */
export function monogram(label: string): string {
  const bracket = /[(（]\s*([A-Za-z][\w.+-]*)/.exec(label)?.[1];
  const head = label.replace(/\(.*?\)|（.*?）/g, ' ').split('/')[0].trim();
  const cjk = /[一-鿿]/;
  if (cjk.test(head) && /[A-Za-z]/.test(head) && bracket) return mark1(bracket);
  if (cjk.test(head[0] ?? '')) return [...head.replace(/[^一-鿿]/g, '')].slice(0, 2).join('');
  const words = head.split(/\s+/).map(w => w.replace(/[^A-Za-z0-9]/g, '')).filter(Boolean);
  const second = words.slice(1).find(w => /^[A-Z0-9]/.test(w));        // 「Ruby on Rails」 → RR, not RO
  if (second) return (words[0][0] + second[0]).toUpperCase();
  return mark1(words[0] ?? '?');
}

function mark1(w: string): string {
  if (w.length < 2 || /^[0-9]/.test(w)) return w.slice(0, 2).toUpperCase();      // 7-Zip → 7Z
  return w[0].toUpperCase() + (/^[A-Z0-9]+$/.test(w) ? w[1] : w[1].toLowerCase());
}

/** Marks for a whole wall: a mark already taken gets the first letter + the next letter that makes it unique
 *  (Ruby → Ru, then Rust → Rs), so two tiles never look alike. */
export function wallMarks(labels: string[]): Map<string, string> {
  const out = new Map<string, string>(); const used = new Set<string>();
  for (const label of labels) {
    let m = monogram(label);
    if (used.has(m) && !/[一-鿿]/.test(m)) {
      const letters = label.replace(/[^A-Za-z0-9]/g, '');
      const alt = [...letters.slice(1)].map(c => m[0] + c.toLowerCase()).find(x => !used.has(x));
      if (alt) m = alt;
    }
    used.add(m); out.set(label, m);
  }
  return out;
}

export interface WallFilter { firedOnly: boolean; cloudOnly: boolean }

/** The groups and tiles to draw. Empty registered tiles are drawn too (dimmed) unless firedOnly: the wall shows what is
 *  watched, not only what fired. A group left with no tile is dropped. */
export function visibleGroups(groups: P0Group[], f: WallFilter): P0Group[] {
  return groups
    .filter(g => !f.cloudOnly || g.cloud)
    .map(g => ({ ...g, tiles: f.firedOnly ? g.tiles.filter(t => t.count > 0) : g.tiles }))
    .filter(g => g.tiles.length > 0);
}

/** The vulnerabilities behind one tile, newest P0 first (p0.json is already in that order). */
export function eventsOf(events: P0Event[], product: string): P0Event[] {
  return events.filter(e => e.product === product);
}

/** What the team channel did with it (radar.send_judge): the cloud prefilter, then the arbitration's verdict. */
export function teamLine(e: P0Event): { word: string; tone: 'sent' | 'held' | 'wait' | 'none'; reason: string | null } {
  if (!e.cloud) return { word: '非云组件 · 不进团队群', tone: 'none', reason: null };
  if (e.team_send === true) return { word: '团队群 · 仲裁通过', tone: 'sent', reason: e.team_send_reason };
  if (e.team_send === false) return { word: '团队群 · 仲裁不发', tone: 'held', reason: e.team_send_reason };
  return { word: '团队群 · 待仲裁', tone: 'wait', reason: null };
}

/** GET p0.json. null = not published yet (an older backend): a missing file is a 403/404 or falls through to index.html
 *  — the same rule as fetchMitigateDoc. Throws on any other failure. */
export async function fetchP0(): Promise<P0Doc | null> {
  const r = await fetch('./data/p0.json');
  if (r.status === 404 || r.status === 403 || (r.headers.get('content-type') ?? '').includes('text/html')) return null;
  if (!r.ok) throw new Error(`HTTP ${r.status}`);
  const d = await r.json();
  if (d.kind !== 'p0') throw new Error('unexpected data kind');
  return d as P0Doc;
}
