import type { Freshness } from '@/utils/staleness';

/** R3.3: the one site-wide line (sidebar, every page) — how old the published data is, said the same way everywhere. */
export interface StatusLine { tone: 'ok' | 'warn' | 'error' | 'muted'; text: string }

export function statusLine(f: Freshness): StatusLine {
  switch (f.kind) {
    case 'unknown': return { tone: 'muted', text: '数据时间未知' };
    case 'fetch_failing': return { tone: 'error', text: `刷新失败 ${Math.floor(f.sinceFetchSecs / 60)} 分钟` };
    case 'publish_stale': return { tone: 'warn', text: `数据已 ${Math.floor(f.dataAgeSecs / 60)} 分钟未更新` };
    case 'fresh': return { tone: 'ok', text: f.dataAgeSecs < 60 ? '数据刚更新' : `数据 ${Math.floor(f.dataAgeSecs / 60)} 分钟前更新` };
  }
}

/** A newer UI is live: the deployed version.json names another build than the one running. No file (dev server, an
 *  older deploy) ⇒ nothing is claimed. */
export function newVersion(deployed: string | null, own: string): boolean {
  return deployed !== null && deployed !== own;
}

/** Audit 03 4.8: a detail page is rewritten only when its event changes, but its lifecycle word is computed at that
 *  moment; the listing recomputes it every cycle. So a page older than an hour says WHEN its judgement was made —
 *  「3 天前判定」 next to 「活跃」 instead of 「活跃」 alone while the list already says 「休眠」. null = recent enough. */
export function judgedAgo(generatedAt: string | null, nowMs: number): string | null {
  if (!generatedAt) return null;
  const mins = Math.floor((nowMs - new Date(generatedAt).getTime()) / 60_000);
  if (!(mins >= 60)) return null;
  return mins < 48 * 60 ? `${Math.floor(mins / 60)} 小时前判定` : `${Math.floor(mins / 1440)} 天前判定`;
}
