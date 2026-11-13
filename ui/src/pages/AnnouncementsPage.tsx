import { useMemo, useState } from 'react';
import { useAnnouncements } from '@/hooks/useAnnouncements';
import { KIND_META, KIND_ORDER, filterNotices, type NoticeKind } from '@/utils/announcements';
import { formatDateTime, formatRelative } from '@/utils/formatters';
import { safeHref } from '@/utils/safeHref';   // notice URLs are verbatim exchange JSON (research/action/05 #2)

/** #/announcements — every exchange's own notices (CMC top-100 boards), kind decided by code; security incidents and
 *  deposit/withdrawal suspensions of the last 72 h stay on top. */
export function AnnouncementsPage() {
  const { notices, boards, counts, generatedAt, loading, error } = useAnnouncements();
  const [kinds, setKinds] = useState<NoticeKind[]>([]);
  const [exchange, setExchange] = useState<string | null>(null);
  const [query, setQuery] = useState('');
  const rows = useMemo(() => filterNotices(notices, { kinds, exchange, query }), [notices, kinds, exchange, query]);
  const exchanges = useMemo(() => [...new Set(boards.map(b => b.exchange))].sort((a, b) => a.localeCompare(b)), [boards]);
  const toggle = (k: NoticeKind) => setKinds(ks => ks.includes(k) ? ks.filter(x => x !== k) : [...ks, k]);

  if (error) return <div style={{ padding: 40, color: 'var(--sev-p0)', fontFamily: 'var(--font-mono)' }}>{error}</div>;
  return (
    <div style={{ display: 'flex', flexDirection: 'column', height: '100%', overflow: 'hidden' }}>
      <div style={{ padding: '12px 16px', borderBottom: '1px solid var(--border)' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexWrap: 'wrap', gap: 8 }}>
          <div>
            <h1 style={{ fontFamily: 'var(--font-display)', fontSize: 18, fontWeight: 700, color: 'var(--text-primary)', marginBottom: 2 }}>
              交易所公告
            </h1>
            <p style={{ fontSize: 11, color: 'var(--text-muted)' }}>
              {boards.length} 个交易所公告源 · {notices.length} 条 · 类型由代码判定（安全事件 &gt; 充提暂停 &gt; 下架 &gt; 维护 &gt; 上新）
            </p>
          </div>
          {generatedAt && <span style={{ fontSize: 10, color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>as of {formatDateTime(generatedAt)}</span>}
        </div>
        <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap', marginTop: 10, alignItems: 'center' }} role="group" aria-label="公告类型">
          {KIND_ORDER.map(k => (
            <button key={k} type="button" onClick={() => toggle(k)} aria-pressed={kinds.includes(k)}
              style={{ fontSize: 11, padding: '3px 9px', borderRadius: 12, cursor: 'pointer',
                border: `1px solid ${KIND_META[k].color}`, color: kinds.includes(k) ? 'var(--bg-base)' : KIND_META[k].color,
                background: kinds.includes(k) ? KIND_META[k].color : 'transparent' }}>
              {KIND_META[k].label} {counts[k] ?? 0}
            </button>
          ))}
          <select aria-label="交易所" value={exchange ?? ''} onChange={e => setExchange(e.target.value || null)}
            style={{ fontSize: 11, padding: '3px 6px', background: 'var(--bg-surface)', color: 'var(--text-primary)', border: '1px solid var(--border)' }}>
            <option value="">全部交易所</option>
            {exchanges.map(x => <option key={x} value={x}>{x}</option>)}
          </select>
          <input aria-label="搜索公告" placeholder="搜索标题 / 交易所" value={query} onChange={e => setQuery(e.target.value)}
            style={{ fontSize: 11, padding: '3px 8px', minWidth: 180, background: 'var(--bg-surface)', color: 'var(--text-primary)', border: '1px solid var(--border)' }} />
        </div>
      </div>
      <div style={{ flex: 1, overflowY: 'auto', padding: '8px 16px' }}>
        {loading && <p style={{ color: 'var(--text-muted)', fontSize: 12 }}>loading…</p>}
        {!loading && rows.length === 0 && <p style={{ color: 'var(--text-muted)', fontSize: 12 }}>没有符合条件的公告</p>}
        <ul style={{ listStyle: 'none', margin: 0, padding: 0 }}>
          {rows.map(r => {
            const m = KIND_META[r.kind as NoticeKind] ?? KIND_META.other;
            const at = r.published_at ?? r.seen_at;
            return (
              <li key={`${r.source_id}|${r.url}`} style={{ display: 'grid', gridTemplateColumns: '72px 130px 1fr 90px', gap: 10,
                alignItems: 'baseline', padding: '7px 0', borderBottom: '1px solid var(--border-subtle, var(--border))' }}>
                <span style={{ fontSize: 10, fontWeight: 700, color: m.color }}>{m.label}</span>
                <span style={{ fontSize: 11, color: 'var(--text-secondary)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{r.exchange}</span>
                <a href={safeHref(r.url)} target="_blank" rel="noopener noreferrer" style={{ fontSize: 12, color: 'var(--text-primary)', textDecoration: 'none' }}>{r.title}</a>
                <time dateTime={at} title={formatDateTime(at)} style={{ fontSize: 10, color: 'var(--text-muted)', fontFamily: 'var(--font-mono)', textAlign: 'right' }}>
                  {formatRelative(at)}
                </time>
              </li>
            );
          })}
        </ul>
      </div>
    </div>
  );
}
