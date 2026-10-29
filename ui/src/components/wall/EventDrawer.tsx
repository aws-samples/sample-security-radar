/**
 * EventDrawer — the wall's L2 (spec 01 §6.2): click a radar blip / NOW card / label / stream row ⇒ the verdict
 * opens beside the wall instead of navigating away. Content = what is it (BLUF), does it hit us (impact + env
 * line), then one way down: "打开完整详情 →". URL-driven (`#/wall?event=<id>`), so refresh restores it and
 * Back closes it. Wording comes from the detail page's single sources (responseBluf, resolveImpact, VerdictPanel
 * word tables) — no second copy of any rule.
 */
import { useEffect, useMemo, useRef } from 'react';
import type { KeyboardEvent as ReactKeyboardEvent } from 'react';
import { Link } from 'react-router-dom';
import type { EventSummary } from '@/types/site-data';
import { useEventDetail } from '@/hooks/useEventDetail';
import { SeverityBadge } from '@/components/SeverityBadge';
import { LevelBadge } from '@/components/LevelBadge';
import { ImpactChip } from '@/components/ImpactChip';
import { ANALYSIS_STATUS_WORD, EXPLOITATION_WORD, LIFECYCLE_WORD } from '@/components/detail/VerdictPanel';
import { resolveImpact, responseBluf } from '@/utils/response';
import { agoZh, utcShort } from '@/utils/timeZh';
import '@/styles/detail.css';
import '@/styles/wall.css';

interface Props {
  eventId: string;
  /** Summary from events.json — renders the header instantly while the detail file loads. */
  summary: EventSummary | null;
  onClose: () => void;
}

const FOCUSABLE = 'a[href], button:not([disabled]), [tabindex]:not([tabindex="-1"])';

export function EventDrawer({ eventId, summary, onClose }: Props) {
  const d = useEventDetail(eventId);
  const ref = useRef<HTMLElement>(null);
  const opener = useRef<Element | null>(null);

  // Focus: remember who opened us, move focus in, give it back on close (spec 01 §6.2).
  useEffect(() => {
    opener.current = document.activeElement;
    ref.current?.focus();
    return () => {
      const el = opener.current;
      if (el instanceof HTMLElement && el.isConnected) el.focus();
    };
  }, []);

  const onKeyDown = (e: ReactKeyboardEvent) => {
    if (e.key === 'Escape') { e.stopPropagation(); onClose(); return; }
    if (e.key !== 'Tab' || !ref.current) return;
    const items = Array.from(ref.current.querySelectorAll<HTMLElement>(FOCUSABLE));
    if (items.length === 0) return;
    const first = items[0], last = items[items.length - 1];
    if (e.shiftKey && (document.activeElement === first || document.activeElement === ref.current)) { e.preventDefault(); last.focus(); }
    else if (!e.shiftKey && document.activeElement === last) { e.preventDefault(); first.focus(); }
  };

  const ev = d.event ?? summary;
  const impact = useMemo(
    () => resolveImpact(ev?.impact, d.loading ? undefined : d.response, d.pipelineSteps),
    [ev, d.loading, d.response, d.pipelineSteps],
  );
  // While loading, `response` is not "absent from the backend" yet — say loading, not 未接入.
  const env = d.loading ? { tone: 'muted' as const, text: '正在加载环境检查…' } : responseBluf(d.response);
  const href = `/events/${encodeURIComponent(eventId)}`;

  let bluf: React.ReactNode;
  const sentences = d.analysis?.bluf ?? [];
  if (d.loading) bluf = <p className="dt-bluf is-dim">正在加载结论…</p>;
  else if (d.error) bluf = <p className="dt-bluf is-dim">{d.error === 'not_found' ? '详情文件缺失（events/ 下无此事件）' : `详情加载失败：${d.error}`}</p>;
  else if (d.analysis && d.analysis.status !== 'failed' && sentences.length > 0) {
    bluf = (
      <p className="dt-bluf">
        {sentences.map((s, i) => <span key={i} className={s.grounded ? '' : 'wd-ungrounded'}>{s.text}</span>)}
      </p>
    );
  } else {
    const why = d.analysis?.status === 'failed'
      ? `结论生成失败（${d.analysis.reason ?? '未给原因'}）`
      : ev?.analysis_status ? ANALYSIS_STATUS_WORD[ev.analysis_status] : '结论未接入（后端未产出 analysis）';
    bluf = <p className="dt-bluf is-dim">{why}</p>;
  }

  return (
    <>
      <div className="wd-backdrop" aria-hidden="true" onClick={onClose} />
      <aside
        ref={ref}
        className="wd-drawer"
        role="dialog"
        aria-modal="true"
        aria-labelledby="wd-title"
        tabIndex={-1}
        onKeyDown={onKeyDown}
        data-testid="event-drawer"
      >
        <header className="wd-head">
          <span className="wd-kicker">事件判定 · L2</span>
          <button type="button" className="wd-close" onClick={onClose} aria-label="关闭判定抽屉（Esc）">✕</button>
        </header>

        {ev ? (
          <>
            <div className="dt-verdict-row">
              <SeverityBadge severity={ev.severity} pulse={ev.severity === 'P0'} />
              <LevelBadge level={ev.level} />
              <span className={`dt-word tone-${EXPLOITATION_WORD[ev.exploitation].tone}`}>{EXPLOITATION_WORD[ev.exploitation].text}</span>
              {ev.lifecycle && <span className="dt-word tone-info">{LIFECYCLE_WORD[ev.lifecycle]}</span>}
            </div>
            <h2 id="wd-title" className="wd-title">{ev.title}</h2>
          </>
        ) : (
          <h2 id="wd-title" className="wd-title">{eventId}</h2>
        )}

        <section className="wd-sec" aria-label="结论">
          <h3 className="wd-label">结论</h3>
          <div data-testid="drawer-bluf">{bluf}</div>
        </section>

        <section className={`wd-sec wd-env tone-${env.tone}`} aria-label="在你的环境中">
          <h3 className="wd-label">在你的环境中</h3>
          <div className="wd-env-row">
            <ImpactChip impact={impact.impact} context="detail" />
            <span className="wd-env-text">{env.text}{'tail' in env && env.tail && <span className={`bluf-tail tone-${env.tail.tone}`}> · {env.tail.text}</span>}</span>
          </div>
          {impact.note && <p className="wd-note">{impact.note}</p>}
        </section>

        {ev && (
          <dl className="wd-facts">
            <div><dt>首见</dt><dd>{agoZh(ev.first_seen)} · {utcShort(ev.first_seen)} UTC</dd></div>
            <div><dt>来源</dt><dd>{ev.independent_sources} 个独立来源 · {ev.item_count} 条证据</dd></div>
            <div><dt>更新</dt><dd>{agoZh(ev.last_updated)}</dd></div>
          </dl>
        )}

        <footer className="wd-foot">
          <Link className="wd-link" to={`${href}?section=env`}>查看环境检查 →</Link>
          <Link className="wd-primary" to={href}>打开完整详情 →</Link>
        </footer>
      </aside>
    </>
  );
}
