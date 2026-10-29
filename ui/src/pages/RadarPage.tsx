import { useMemo } from 'react';
import { Link, useSearchParams } from 'react-router-dom';
import { useEvents } from '@/hooks/useEvents';
import { useSources } from '@/hooks/useSources';
import { EventCard } from '@/components/EventCard';
import { FilterBar } from '@/components/FilterBar';
import { Breadcrumbs } from '@/components/Breadcrumbs';
import { DigestCard } from '@/components/home/DigestCard';
import { HeadlineBar } from '@/components/home/HeadlineBar';
import { NowBoard } from '@/components/home/NowBoard';
import { applyFilters, DEFAULT_FILTERS } from '@/utils/filters';
import type { FilterState } from '@/utils/filters';
import {
  applyFunnelAction, corroborationView, funnelView, groupByLifecycle, parseHomeQuery, resolveNow, sourceRatio, toHomeQuery, web3Loss24h,
} from '@/utils/home';
import type { FunnelAction, LifecycleGroup, MonitorTab } from '@/utils/home';
import { freshness } from '@/utils/staleness';
import '@/styles/home.css';

const STAGE_WORD: Record<FilterState['stage'], string> = { all: '', touched_24h: '近 24h 有更新', corroborated: '已证实（V2+）' };

/**
 * Home (#/) — reading order is the page order (UI-IA §1, spec 01 §3.2):
 * L0 headline + 24 h funnel ("现在怎么样") → L1 NOW ≤3 cards ("必须处理什么") → L1' monitor grouped by
 * lifecycle ("其余在怎么变"). Every card/row drills down to #/events/:id; impact chips drill to ?section=env.
 * View state (tab + filters) lives in the URL so "back" from a detail page restores it (UI-IA §1 rule 3).
 */
export function RadarPage() {
  const { events, now, headline, funnel, digest, generatedAt, loading, error, staleSecs } = useEvents();
  const { sources, loading: srcLoading } = useSources();
  const [params, setParams] = useSearchParams();
  const { filters, tab } = parseHomeQuery(params);

  const setView = (f: FilterState, t: MonitorTab) => setParams(toHomeQuery(f, t), { replace: true });

  const fv = useMemo(() => funnelView(funnel), [funnel]);
  const corr = useMemo(() => corroborationView(events), [events]);
  const nowCards = useMemo(() => resolveNow(now, events), [now, events]);
  const ratio = sourceRatio(sources, srcLoading);
  const sourcesLine = ratio ? `${ratio.ok}/${ratio.enabled} 源正常` : null;
  const filtered = useMemo(() => applyFilters(events, filters), [events, filters]);
  const groups = useMemo(() => groupByLifecycle(filtered), [filtered]);
  const loss = useMemo(() => web3Loss24h(events), [events]);
  const fresh = freshness(generatedAt, staleSecs, Date.now());

  const activeAction: FunnelAction =
    filters.stage === 'touched_24h' ? 'touched_24h' : filters.stage === 'corroborated' ? 'corroborated'
      : filters.severity === 'P0' ? 'p0' : null;
  const onFunnel = (a: FunnelAction) => {
    // toggling off clears exactly what the segment set; other filters are kept
    const base: FilterState = a === null
      ? { ...filters, stage: 'all', severity: activeAction === 'p0' ? 'all' : filters.severity }
      : { ...filters, stage: 'all' };
    setView(applyFunnelAction(base, a), tab);
    document.getElementById('monitor')?.scrollIntoView({ block: 'start' });
  };

  const visibleGroups = groups.filter(g => g.events.length > 0 || (g.key !== 'dormant' && g.key !== 'unknown'));
  const shown: LifecycleGroup[] = tab === 'all' ? groups.filter(g => g.events.length) : groups.filter(g => g.key === tab);
  const total = filtered.length;

  if (error && events.length === 0) {
    return <div className="hm-page"><p className="hm-error" role="alert">事件数据加载失败：{error}</p></div>;
  }

  return (
    <div className="hm-page" data-page="home">
      <div className="hm-wrap">
        <div className="hm-top">
          <Breadcrumbs items={[{ label: '态势' }]} />
          <span className={`hm-status is-${fresh.kind}`} role="status">
            <span className="hm-dot" aria-hidden="true" />
            {fresh.kind === 'fetch_failing' ? `刷新失败 ${Math.floor(fresh.sinceFetchSecs / 60)} 分钟` :
              fresh.kind === 'publish_stale' ? `数据 ${Math.floor(fresh.dataAgeSecs / 60)} 分钟未更新` :
                fresh.kind === 'fresh' ? 'LIVE' : '加载中'}
            {sourcesLine && <> · <Link to="/sources">{sourcesLine}</Link></>}
            {generatedAt && <> · 发布 {generatedAt.slice(11, 16)} UTC</>}
          </span>
        </div>

        {loading && events.length === 0 ? (
          <p className="hm-loading" aria-busy="true">加载态势…</p>
        ) : (
          <>
            <HeadlineBar headline={headline} funnel={fv} activeAction={activeAction} onFunnel={onFunnel} web3Loss={loss} corroboration={corr} />
            <DigestCard digest={digest} events={events} />

            <section className="hm-sec" aria-labelledby="now-h2">
              <h2 id="now-h2" className="hm-h2"><span className="hm-step">L1</span> 必须处理 <span className="hm-en">NOW</span>
                <span className="hm-aside">后端按紧迫度排序 · 理由原样显示</span></h2>
              <NowBoard cards={nowCards} generatedAt={generatedAt} sourcesLine={sourcesLine} />
            </section>

            <section className="hm-sec" id="monitor" aria-labelledby="mon-h2">
              <h2 id="mon-h2" className="hm-h2"><span className="hm-step">L1′</span> 监控中 <span className="hm-en">MONITOR</span>
                <span className="hm-aside">按生命周期分组：先看在变的，再看已定的</span></h2>

              <div className="tabs" role="group" aria-label="按生命周期筛选">
                <button type="button" className="tab" aria-pressed={tab === 'all'} onClick={() => setView(filters, 'all')}>
                  全部 <b className="tabular">{total}</b>
                </button>
                {visibleGroups.map(g => (
                  <button key={g.key} type="button" className={`tab lc-${g.key}`} aria-pressed={tab === g.key}
                    onClick={() => setView(filters, g.key)}>
                    {g.label} <b className="tabular">{g.events.length}</b>
                  </button>
                ))}
                {filters.stage !== 'all' && (
                  <button type="button" className="tab is-filter" onClick={() => setView({ ...filters, stage: 'all' }, tab)}
                    aria-label={`清除漏斗筛选：${STAGE_WORD[filters.stage]}`}>
                    {STAGE_WORD[filters.stage]} <span aria-hidden="true">✕</span>
                  </button>
                )}
              </div>

              <FilterBar filters={filters} onChange={f => setView(f, tab)} resultCount={total} />

              <div className="mon-list" aria-busy={loading}>
                {total === 0 && (
                  <p className="hm-none">
                    没有符合筛选条件的事件。
                    <button type="button" className="btn-ghost" onClick={() => setView(DEFAULT_FILTERS, 'all')}>清除筛选</button>
                  </p>
                )}
                {total > 0 && shown.every(g => g.events.length === 0) && (
                  <p className="hm-none">该分组下没有事件。</p>
                )}
                {shown.map(g => g.events.length > 0 && (
                  g.folded && tab === 'all' ? (
                    <details key={g.key} className={`lc-group lc-${g.key}`}>
                      <summary className="lc-h">{g.label} <b className="tabular">{g.events.length}</b> <span className="hm-muted">超过 14 天无动静，默认折叠</span></summary>
                      <div className="lc-rows">{g.events.map(ev => <EventCard key={ev.event_id} event={ev} showSummary={false} />)}</div>
                    </details>
                  ) : (
                    <div key={g.key} className={`lc-group lc-${g.key}`} role="group" aria-label={`${g.label} ${g.events.length} 件`}>
                      {tab === 'all' && <h3 className="lc-h">{g.label} <b className="tabular">{g.events.length}</b></h3>}
                      <div className="lc-rows">{g.events.map(ev => <EventCard key={ev.event_id} event={ev} showSummary={false} />)}</div>
                    </div>
                  )
                ))}
              </div>
            </section>
          </>
        )}
      </div>
    </div>
  );
}
