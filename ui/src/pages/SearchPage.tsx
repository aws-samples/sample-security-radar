import { useEffect, useMemo, useState } from 'react';
import { Link } from 'react-router-dom';
import type { SearchRow } from '@/types/site-data';
import { loadSearch, searchRows, type SearchMonth } from '@/utils/search';

/** #/search — every event the radar ever published (data/search/<yyyy-mm>.json, radar.search), searched in the
 *  browser: the live pages show the last 60 days, this finds anything older too. */
export function SearchPage() {
  const [rows, setRows] = useState<SearchRow[]>([]);
  const [months, setMonths] = useState<SearchMonth[]>([]);
  const [loaded, setLoaded] = useState(0);
  const [failed, setFailed] = useState<string[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [detailCap, setDetailCap] = useState<number | null>(null);
  const [q, setQ] = useState('');

  useEffect(() => {
    let live = true;
    void loadSearch(url => fetch(url), () => live, {
      index: (ms, cap) => { setMonths(ms); setDetailCap(cap); },
      shards: (got, n, bad) => {
        setRows(prev => [...prev, ...got]);
        setLoaded(k => k + n);
        if (bad.length) setFailed(prev => [...prev, ...bad]);
      },
      error: setError,
    });
    return () => { live = false; };
  }, []);

  if (error) return <div style={{ padding: 40, color: 'var(--sev-p0)', fontFamily: 'var(--font-mono)' }}>{error}</div>;
  return <SearchView months={months} rows={rows} loaded={loaded} failed={failed} detailCap={detailCap} q={q} setQ={setQ} />;
}

interface ViewProps {
  months: SearchMonth[]; rows: SearchRow[]; loaded: number; failed: string[];
  /** index.detail_cap — never a literal here: the cap's one source is Limits.PUBLISH_MAX_EVENTS */
  detailCap: number | null;
  q: string; setQ: (q: string) => void;
}

/** A hit links to its detail page only when Publish wrote one (row.p): detail docs exist for the window's top
 *  `detailCap` events, the index holds every event — an unmarked hit is shown, not linked to 「事件不存在」. */
export function SearchView({ months, rows, loaded, failed, detailCap, q, setQ }: ViewProps) {
  const noPage = detailCap !== null ? `无详情页（未进入发布的前 ${detailCap} 条）` : '无详情页（未进入发布）';
  const hits = useMemo(() => searchRows(rows, q), [rows, q]);
  const total = months.reduce((n, m) => n + m.events, 0);
  const label = (r: SearchRow) => (
    <>{r.t}{r.c.length > 0 && <span style={{ color: 'var(--text-muted)', fontFamily: 'var(--font-mono)', fontSize: 10 }}> · {r.c.slice(0, 3).join(', ')}</span>}</>
  );
  return (
    <div style={{ display: 'flex', flexDirection: 'column', height: '100%', overflow: 'hidden' }}>
      <div style={{ padding: '12px 16px', borderBottom: '1px solid var(--border)' }}>
        <h1 style={{ fontFamily: 'var(--font-display)', fontSize: 18, fontWeight: 700, color: 'var(--text-primary)', marginBottom: 2 }}>搜索全部事件</h1>
        <p style={{ fontSize: 11, color: 'var(--text-muted)' }}>
          {total} 个事件 · {months.length} 个月{loaded < months.length ? ` · 已载入 ${loaded}/${months.length}` : ''} · 标题 / CVE / 实体，空格分隔多个词
        </p>
        {failed.length > 0 && (
          <p role="status" title={failed.join(', ')} style={{ fontSize: 11, color: 'var(--sev-p1)', marginTop: 2 }}>
            {failed.length} 个月载入失败（{failed.slice(0, 6).join(', ')}{failed.length > 6 ? ' …' : ''}）—— 这些月份的事件搜不到，刷新重试
          </p>
        )}
        <input aria-label="搜索事件" placeholder="例如：fortinet vpn 或 CVE-2026-1234" value={q} onChange={e => setQ(e.target.value)} autoFocus
          style={{ marginTop: 8, fontSize: 13, padding: '6px 10px', width: '100%', maxWidth: 520, background: 'var(--bg-surface)',
                   color: 'var(--text-primary)', border: '1px solid var(--border)' }} />
      </div>
      <div style={{ flex: 1, overflowY: 'auto', padding: '8px 16px' }}>
        {q.trim() && hits.length === 0 && <p style={{ color: 'var(--text-muted)', fontSize: 12 }}>没有匹配的事件</p>}
        <ul style={{ listStyle: 'none', margin: 0, padding: 0 }}>
          {hits.map(r => (
            <li key={r.id} style={{ display: 'grid', gridTemplateColumns: '40px 40px 1fr 90px', gap: 10, alignItems: 'baseline',
                                    padding: '7px 0', borderBottom: '1px solid var(--border)' }}>
              <span style={{ fontSize: 10, fontWeight: 700, color: `var(--sev-${r.s.toLowerCase()})` }}>{r.s}</span>
              <span style={{ fontSize: 10, color: 'var(--text-muted)' }}>{r.l}</span>
              {r.p ? (
                <Link to={`/events/${r.id}`} style={{ fontSize: 12, color: 'var(--text-primary)', textDecoration: 'none' }}>{label(r)}</Link>
              ) : (
                <span style={{ fontSize: 12, color: 'var(--text-secondary)' }}>
                  {label(r)}<span style={{ color: 'var(--text-muted)', fontSize: 10 }}> · {noPage}</span>
                </span>
              )}
              <time dateTime={r.f} style={{ fontSize: 10, color: 'var(--text-muted)', fontFamily: 'var(--font-mono)', textAlign: 'right' }}>{r.f}</time>
            </li>
          ))}
        </ul>
      </div>
    </div>
  );
}
