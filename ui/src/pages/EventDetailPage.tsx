import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { useParams, useSearchParams, Link } from 'react-router-dom';
import { attackFlow, showFlow } from '@/utils/attackFlow';
import { TABS, detailTab, nextTab, type DetailTab } from '@/utils/detailTabs';
import { useEventDetail } from '@/hooks/useEventDetail';
import { DuplicateNote } from '@/components/detail/DuplicateNote';
import { Breadcrumbs } from '@/components/Breadcrumbs';
import { VerdictPanel } from '@/components/detail/VerdictPanel';
import { ProgressPanel } from '@/components/detail/ProgressPanel';
import { AnalysisCard } from '@/components/detail/AnalysisCard';
import { KeyData } from '@/components/detail/KeyData';
import { AttackFlow } from '@/components/detail/AttackFlow';
import { OnchainPanel } from '@/components/detail/OnchainPanel';
import { AttackTxPanel } from '@/components/detail/AttackTxPanel';
import { EvidenceTimeline, ChangeLog } from '@/components/detail/EvidenceTimeline';
import { EnvSection } from '@/components/env/EnvSection';
import { MitigationPanel } from '@/components/detail/MitigationPanel';
import { LevelBadge } from '@/components/LevelBadge';
import { resolveImpact } from '@/utils/response';
import { citationNumbers, groupEvidence } from '@/utils/evidence';
import { utcShort } from '@/utils/timeZh';
import '@/styles/detail.css';

const SECTIONS = ['env', 'evidence'] as const;

/**
 * L2 event detail. The verdict (BLUF) stays on top; below it two tabs, each its own reading order:
 *   事件跟踪 (default): analysis → attack flow + on-chain reconstruction (M4) → key data → progress → why this level →
 *                       evidence → change log;
 *   在你的环境中:       Security Agent + Continuum response → mitigation fast path (M3).
 * (2026-10-30 Neo: the incident first, the radar's own scan as a tab.) Deep links: `?tab=env`, `?section=env|evidence`
 * (the hash is owned by HashRouter).
 */
export function EventDetailPage() {
  const { eventId = '' } = useParams<{ eventId: string }>();
  const [params, setParams] = useSearchParams();
  const section = params.get('section');
  const tab = detailTab(params);
  const setTab = useCallback((t: DetailTab) => {
    setParams(p => { const n = new URLSearchParams(p); n.delete('section'); if (t === 'env') n.set('tab', 'env'); else n.delete('tab'); return n; }, { replace: true });
  }, [setParams]);
  const d = useEventDetail(eventId);

  const groups = useMemo(() => groupEvidence(d.items), [d.items]);
  const numbers = useMemo(() => citationNumbers(groups), [groups]);
  const groupOf = useMemo(() => {
    const m = new Map<string, { group: number; echo: boolean }>();
    for (const g of groups) { m.set(g.lead.item_id, { group: g.group, echo: false }); for (const e of g.echoes) m.set(e.item_id, { group: g.group, echo: true }); }
    return m;
  }, [groups]);
  const [expanded, setExpanded] = useState<Set<number>>(new Set());
  const [flash, setFlash] = useState<{ id: string; n: number } | null>(null);
  const flashId = flash?.id ?? null;
  const pendingFocus = useRef<string | null>(null);

  const impact = useMemo(() => resolveImpact(d.event?.impact, d.response, d.pipelineSteps), [d.event, d.response, d.pipelineSteps]);

  const scrollTo = useCallback((id: string) => document.getElementById(id)?.scrollIntoView({ block: 'start' }), []);

  // Citation [n] ⇒ unfold its echo group if needed, then scroll + focus + flash the item (1.2 s).
  const onCite = useCallback((itemId: string) => {
    const g = groupOf.get(itemId);
    if (!g) return;
    setTab('track');                                        // the evidence lives in the incident tab
    if (g.echo) setExpanded(s => (s.has(g.group) ? s : new Set(s).add(g.group)));
    pendingFocus.current = itemId;
    setFlash(f => ({ id: itemId, n: (f?.n ?? 0) + 1 }));
  }, [groupOf, setTab]);

  useEffect(() => {
    const id = pendingFocus.current;
    if (!id) return;
    const el = document.getElementById(`item-${id}`);
    if (!el) return;
    pendingFocus.current = null;
    el.scrollIntoView({ block: 'center' });
    el.focus({ preventScroll: true });
    const t = window.setTimeout(() => setFlash(null), 1200);
    return () => window.clearTimeout(t);
  }, [flash, expanded]);

  useEffect(() => {
    if (d.loading || !d.event || !section || !(SECTIONS as readonly string[]).includes(section)) return;
    // after first paint of the loaded page
    const r = requestAnimationFrame(() => scrollTo(section === 'env' ? 'dt-tabs' : section));
    return () => cancelAnimationFrame(r);
  }, [d.loading, d.event, section, scrollTo]);

  if (d.loading) {
    return <div className="dt-page" aria-busy="true"><p className="dt-muted dt-mono dt-small">正在加载事件…</p></div>;
  }
  if (d.error || !d.event) {
    const notFound = d.error === 'not_found' || !d.event;
    return (
      <div className="dt-page">
        <div className="dt-wrap">
          <Breadcrumbs items={[{ label: '态势', to: '/' }, { label: '事件不存在' }]} />
          <section className="dt-section">
            <h1 className="dt-h2">{notFound ? '事件不存在' : '事件加载失败'}</h1>
            <p className="dt-small">
              {notFound ? <>没有找到 <code className="dt-mono">{eventId}</code> 的详情文件（可能已合并或被清理）。</> : <>错误：<code className="dt-mono">{d.error}</code></>}
            </p>
            <Link to="/">← 返回态势</Link>
          </section>
        </div>
      </div>
    );
  }

  const ev = d.event;
  const echoes = d.items.length - groups.length;
  const toggle = (g: number) => setExpanded(s => { const n = new Set(s); if (n.has(g)) n.delete(g); else n.add(g); return n; });
  const hasKeyData = d.cveDetails.length + d.amountHistory.length + d.tx.length > 0;
  const hasFlow = showFlow(attackFlow(d.items), ev.domain === 'web3') || Boolean(ev.attribution) || Boolean(d.onchain) || Boolean(d.attackTxs);
  // section numbers of the incident tab follow what is shown (no gaps)
  const n = (() => {
    const order = ['an', ...(hasFlow ? ['flow'] : []), ...(hasKeyData ? ['kd'] : []), 'progress', 'why', 'ev'];
    return Object.fromEntries(order.map((k, i) => [k, String(i + 1).padStart(2, '0')])) as Record<string, string>;
  })();

  return (
    <div className="dt-page">
      <div className="dt-wrap">
        <Breadcrumbs items={[{ label: '态势', to: '/' }, { label: '事件', to: '/' }, { label: ev.title }]} />

        <DuplicateNote dups={d.possibleDuplicates} />

        {/* verdict (BLUF) — above both tabs */}
        <VerdictPanel
          event={ev} analysis={d.analysis} progress={d.progress} response={d.response} impact={impact}
          cite={id => numbers.get(id)} onCite={onCite} onEnv={() => { setTab('env'); requestAnimationFrame(() => scrollTo('dt-tabs')); }}
        />

        <div className="dt-tabs" id="dt-tabs" role="tablist" aria-label="事件详情视图">
          {TABS.map(t => (
            <button key={t.id} type="button" role="tab" id={`dt-tab-${t.id}`} aria-controls={`dt-panel-${t.id}`}
              aria-selected={tab === t.id} tabIndex={tab === t.id ? 0 : -1} className={`dt-tab${tab === t.id ? ' is-on' : ''}`}
              onClick={() => setTab(t.id)}
              onKeyDown={e => { const n = nextTab(tab, e.key); if (n) { e.preventDefault(); setTab(n); document.getElementById(`dt-tab-${n}`)?.focus(); } }}>
              {t.label} <span className="dt-en">{t.en}</span>
            </button>
          ))}
        </div>

        {tab === 'track' ? (
          <div role="tabpanel" id="dt-panel-track" aria-labelledby="dt-tab-track">
            <section className="dt-section" aria-labelledby="dt-h-an">
              <h2 className="dt-h2" id="dt-h-an"><span className="dt-step">{n.an}</span>分析卡 <span className="dt-en">Analysis</span>
                <span className="dt-aside">[n] = 证据编号，点击跳转</span></h2>
              <AnalysisCard analysis={d.analysis} cite={id => numbers.get(id)} onCite={onCite} />
            </section>

            {/* attack flow (M4) — rendered when the story has ≥ 2 phases, an attribution or an on-chain reconstruction */}
            <AttackFlow event={ev} items={d.items} onCite={onCite} step={n.flow}>
              {d.attackTxs && <AttackTxPanel data={d.attackTxs} />}
              {d.onchain && <OnchainPanel onchain={d.onchain} />}
            </AttackFlow>

            {hasKeyData && (
              <section className="dt-section" aria-labelledby="dt-h-kd">
                <h2 className="dt-h2" id="dt-h-kd"><span className="dt-step">{n.kd}</span>关键数据 <span className="dt-en">Key data</span></h2>
                <KeyData event={ev} cves={d.cveDetails} amounts={d.amountHistory} tx={d.tx} />
              </section>
            )}

            <section className="dt-section" aria-labelledby="dt-h-progress">
              <h2 className="dt-h2" id="dt-h-progress"><span className="dt-step">{n.progress}</span>进展流程 <span className="dt-en">Progress</span>
                <span className="dt-aside">代码计算 · 时间为证据发布时间（UTC）</span></h2>
              <ProgressPanel progress={d.progress} steps={d.pipelineSteps} response={d.response} />
            </section>

            <section className="dt-section" aria-labelledby="dt-h-why">
              <h2 className="dt-h2" id="dt-h-why"><span className="dt-step">{n.why}</span>为什么是这个等级 <span className="dt-en">Why this level</span></h2>
              <p style={{ display: 'flex', gap: 10, alignItems: 'center', flexWrap: 'wrap', fontSize: 13, margin: 0 }}>
                <LevelBadge level={ev.level} />
                <span className="dt-mono">{ev.level_reason}</span>
                <span className="dt-muted">· {groups.length} 个独立来源组 · {echoes} 条转载（同源，不计入独立来源）</span>
              </p>
            </section>

            <section className="dt-section" id="evidence" aria-labelledby="dt-h-ev">
              <h2 className="dt-h2" id="dt-h-ev"><span className="dt-step">{n.ev}</span>证据时间线 <span className="dt-en">Evidence</span>
                <span className="dt-aside">{d.items.length} 条 · {groups.length} 个独立来源 · 转载已折叠</span></h2>
              {d.items.length === 0
                ? <p className="dt-small dt-muted">没有证据条目</p>
                : <EvidenceTimeline groups={groups} numbers={numbers} expanded={expanded} onToggle={toggle} flashId={flashId} />}
            </section>

            <ChangeLog timeline={d.timeline} />
          </div>
        ) : (
          <div role="tabpanel" id="dt-panel-env" aria-labelledby="dt-tab-env">
            <section className="dt-section" id="env" aria-labelledby="dt-h-env">
              <h2 className="dt-h2" id="dt-h-env"><span className="dt-step">01</span>在你的环境中 <span className="dt-en">In your environment</span>
                <span className="dt-aside">AWS Security Agent + AWS Continuum{d.response ? ` · 更新 ${utcShort(d.response.updated_at)} UTC` : ''}</span></h2>
              <EnvSection response={d.response} steps={d.pipelineSteps} impact={impact} deepLinked={section === 'env'} />
            </section>
            {/* mitigation fast path (M3) — absent / null ⇒ not rendered */}
            <MitigationPanel mitigation={d.mitigation} step="02" />
          </div>
        )}
      </div>
    </div>
  );
}
