import type { Notice } from '@/types/site-data';

/** Board order: what an operator must see first (radar.announcements.PRIORITY). */
export const KIND_ORDER = ['security', 'suspension', 'delisting', 'maintenance', 'listing', 'other'] as const;
export type NoticeKind = (typeof KIND_ORDER)[number];

export const KIND_META: Record<NoticeKind, { label: string; color: string }> = {
  security:    { label: '安全事件', color: 'var(--sev-p0)' },
  suspension:  { label: '充提暂停', color: 'var(--sev-p1)' },
  delisting:   { label: '下架',     color: 'var(--sev-p2)' },
  maintenance: { label: '维护升级', color: 'var(--text-secondary)' },
  listing:     { label: '上新',     color: 'var(--status-ok)' },
  other:       { label: '其他',     color: 'var(--text-muted)' },
};

export interface NoticeFilter {
  kinds: NoticeKind[];        // empty = all
  exchange: string | null;
  query: string;
}

/** Filter, then pin security and suspension notices of the last 72 h above the rest (newest first within a group). */
export function filterNotices(rows: Notice[], f: NoticeFilter, now: Date = new Date()): Notice[] {
  const q = f.query.trim().toLowerCase();
  const out = rows.filter(r =>
    (f.kinds.length === 0 || f.kinds.includes(r.kind as NoticeKind)) &&
    (!f.exchange || r.exchange === f.exchange) &&
    (!q || r.title.toLowerCase().includes(q) || r.exchange.toLowerCase().includes(q)));
  const at = (r: Notice) => Date.parse(r.published_at ?? r.seen_at);
  const pinned = (r: Notice) => (r.kind === 'security' || r.kind === 'suspension') && now.getTime() - at(r) < 72 * 3600e3;
  return out.sort((a, b) => Number(pinned(b)) - Number(pinned(a)) || at(b) - at(a));
}
