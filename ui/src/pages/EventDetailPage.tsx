import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { useParams, useSearchParams, Link } from 'react-router-dom';
import { useEventDetail } from '@/hooks/useEventDetail';
import { DuplicateNote } from '@/components/detail/DuplicateNote';
import { Breadcrumbs } from '@/components/Breadcrumbs';
import { VerdictPanel } from '@/components/detail/VerdictPanel';
import { ProgressPanel } from '@/components/detail/ProgressPanel';
import { AnalysisCard } from '@/components/detail/AnalysisCard';
import { KeyData } from '@/components/detail/KeyData';
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
 * L2 event detail — reading order is a hard constraint (UI-IA §2, spec 01 §4.2):
 * verdict (BLUF) → progress + system steps → 在你的环境中 → 缓解（快路，M3）→ why this level → analysis → key data → evidence → change log.
 * Deep links: `?section=env|evidence` (the hash is owned by HashRouter).
 */
export function EventDetailPage() {
  const { eventId = '' } = useParams<{ eventId: string }>();
  const [params] = useSearchParams();
  const section = params.get('section');
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
    if (g.echo) setExpanded(s => (s.has(g.group) ? s : new Set(s).add(g.group)));
    pendingFocus.current = itemId;
    setFlash(f => ({ id: itemId, n: (f?.n ?? 0) + 1 }));
  }, [groupOf]);

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
    const r = requestAnimationFrame(() => scrollTo(section));
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

  return (
    <div className="dt-page">
      <div className="dt-wrap">
        <Breadcrumbs items={[{ label: '态势', to: '/' }, { label: '事件', to: '/' }, { label: ev.title }]} />

        <DuplicateNote dups={d.possibleDuplicates} />

        {/* 1 · verdict */}
        <VerdictPanel
          event={ev} analysis={d.analysis} progress={d.progress} response={d.response} impact={impact}
          cite={id => numbers.get(id)} onCite={onCite} onEnv={() => scrollTo('env')}
        />

        {/* 2 · progress */}
        <section className="dt-section" aria-labelledby="dt-h-progress">
          <h2 className="dt-h2" id="dt-h-progress"><span className="dt-step">02</span>进展流程 <span className="dt-en">Progress</span>
            <span className="dt-aside">代码计算 · 时间为证据发布时间（UTC）</span></h2>
          <ProgressPanel progress={d.progress} steps={d.pipelineSteps} response={d.response} />
        </section>

        {/* 3 · in your environment */}
        <section className="dt-section" id="env" aria-labelledby="dt-h-env">
          <h2 className="dt-h2" id="dt-h-env"><span className="dt-step">03</span>在你的环境中 <span className="dt-en">In your environment</span>
            <span className="dt-aside">AWS Security Agent + AWS Continuum{d.response ? ` · 更新 ${utcShort(d.response.updated_at)} UTC` : ''}</span></h2>
          <EnvSection response={d.response} steps={d.pipelineSteps} impact={impact} deepLinked={section === 'env'} />
        </section>

        {/* 3b · mitigation fast path (M3) — absent / null ⇒ not rendered */}
        <MitigationPanel mitigation={d.mitigation} />

        {/* 4 · why this level */}
        <section className="dt-section" aria-labelledby="dt-h-why">
          <h2 className="dt-h2" id="dt-h-why"><span className="dt-step">04</span>为什么是这个等级 <span className="dt-en">Why this level</span></h2>
          <p style={{ display: 'flex', gap: 10, alignItems: 'center', flexWrap: 'wrap', fontSize: 13, margin: 0 }}>
            <LevelBadge level={ev.level} />
            <span className="dt-mono">{ev.level_reason}</span>
            <span className="dt-muted">· {groups.length} 个独立来源组 · {echoes} 条转载（同源，不计入独立来源）</span>
          </p>
        </section>

        {/* 5 · analysis */}
        <section className="dt-section" aria-labelledby="dt-h-an">
          <h2 className="dt-h2" id="dt-h-an"><span className="dt-step">05</span>分析卡 <span className="dt-en">Analysis</span>
            <span className="dt-aside">[n] = 证据编号，点击跳转</span></h2>
          <AnalysisCard analysis={d.analysis} cite={id => numbers.get(id)} onCite={onCite} />
        </section>

        {/* 6 · key data */}
        {hasKeyData && (
          <section className="dt-section" aria-labelledby="dt-h-kd">
            <h2 className="dt-h2" id="dt-h-kd"><span className="dt-step">06</span>关键数据 <span className="dt-en">Key data</span></h2>
            <KeyData event={ev} cves={d.cveDetails} amounts={d.amountHistory} tx={d.tx} />
          </section>
        )}

        {/* 7 · evidence (L3) */}
        <section className="dt-section" id="evidence" aria-labelledby="dt-h-ev">
          <h2 className="dt-h2" id="dt-h-ev"><span className="dt-step">07</span>证据时间线 <span className="dt-en">Evidence</span>
            <span className="dt-aside">{d.items.length} 条 · {groups.length} 个独立来源 · 转载已折叠</span></h2>
          {d.items.length === 0
            ? <p className="dt-small dt-muted">没有证据条目</p>
            : <EvidenceTimeline groups={groups} numbers={numbers} expanded={expanded} onToggle={toggle} flashId={flashId} />}
        </section>

        {/* 8 · change log */}
        <ChangeLog timeline={d.timeline} />
      </div>
    </div>
  );
}
