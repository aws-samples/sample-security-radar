import type { Analysis, EventSummary, ProgressStage, Response } from '@/types/site-data';
import { SeverityBadge } from '@/components/SeverityBadge';
import { LevelBadge } from '@/components/LevelBadge';
import { ImpactChip } from '@/components/ImpactChip';
import { SentenceText } from '@/components/detail/AnalysisCard';
import type { ResolvedImpact } from '@/utils/response';
import { responseBluf } from '@/utils/response';
import { corroborationMs } from '@/utils/evidence';
import { agoZh, durationZh, utcShort } from '@/utils/timeZh';

export const EXPLOITATION_WORD: Record<EventSummary['exploitation'], { text: string; tone: string }> = {
  none: { text: '无利用迹象', tone: 'muted' },
  poc: { text: '已有 PoC', tone: 'warn' },
  reported: { text: '在野利用·已报道', tone: 'loss' },
  confirmed: { text: '在野利用·已确认', tone: 'loss' },
};

export const LIFECYCLE_WORD: Record<NonNullable<EventSummary['lifecycle']>, string> = {
  escalating: '升级中', active: '活跃', cooling: '冷却', finalized: '定稿', dormant: '休眠',
};

export const ANALYSIS_STATUS_WORD: Record<NonNullable<EventSummary['analysis_status']>, string> = {
  ok: '结论已生成', partial: '部分句子未通过校验', pending: '结论未生成（pending，排队中）',
  failed: '结论生成失败', not_applicable: '低于 P1，不生成结论',
};

interface Props {
  event: EventSummary;
  analysis: Analysis | null | undefined;
  progress: ProgressStage[] | undefined;
  response: Response | null | undefined;
  impact: ResolvedImpact;
  cite: (itemId: string) => number | undefined;
  onCite: (itemId: string) => void;
  onEnv: () => void;
}

/** L2 protagonist: what is it, how sure, how bad, does it hit us — one screen, before anything else. */
export function VerdictPanel({ event, analysis, progress, response, impact, cite, onCite, onEnv }: Props) {
  const ex = EXPLOITATION_WORD[event.exploitation];
  const env = responseBluf(response);
  const corr = corroborationMs(progress);
  const firstStage = progress?.find(p => p.stage === 'first_report');
  const t1Instant = corr === 0 && event.level_reason.includes('T1');

  let bluf: React.ReactNode;
  const sentences = analysis?.bluf ?? [];
  if (analysis && analysis.status !== 'failed' && sentences.length > 0) {
    const allGrounded = sentences.every(s => s.grounded);
    bluf = (
      <p className={`dt-bluf${allGrounded ? '' : ' is-dim'}`}>
        {sentences.map((s, i) => <SentenceText key={i} s={s} cite={cite} onCite={onCite} />)}
      </p>
    );
  } else {
    const why = analysis?.status === 'failed'
      ? `结论生成失败（${analysis.reason ?? '未给原因'}）`
      : analysis === undefined && !event.analysis_status
        ? '结论未接入（后端版本未产出 analysis）'
        : event.analysis_status ? ANALYSIS_STATUS_WORD[event.analysis_status] : '结论未生成';
    bluf = <p className="dt-bluf is-dim">{why}</p>;
  }

  return (
    <section className={`dt-verdict${event.severity === 'P0' ? ' is-p0' : ''}`} data-testid="verdict-panel" aria-labelledby="dt-title">
      <div className="dt-verdict-row">
        <SeverityBadge severity={event.severity} pulse={event.severity === 'P0'} />
        <LevelBadge level={event.level} />
        <span className={`dt-word tone-${ex.tone}`}>{ex.text}</span>
        {event.lifecycle && <span className="dt-word tone-info">{LIFECYCLE_WORD[event.lifecycle]}</span>}
        <span style={{ marginLeft: 'auto' }}>
          <ImpactChip impact={impact.impact} context="detail" withContext />
        </span>
      </div>
      <h1 id="dt-title">{event.title}</h1>
      {bluf}
      <div className="dt-timing">
        <span>首见 <b>{agoZh(firstStage?.at ?? event.first_seen)}</b>（{utcShort(firstStage?.at ?? event.first_seen)} UTC · {event.first_report_source}）</span>
        <span>证实用时 <b>{durationZh(corr) ?? '未证实'}</b>{t1Instant ? '（T1 首报即证实）' : ''}</span>
        <span>最后更新 <b>{agoZh(event.last_updated)}</b></span>
        <span><b>{event.independent_sources}</b> 个独立来源 · <b>{event.item_count}</b> 条证据</span>
      </div>
      <button type="button" className={`dt-envline tone-${env.tone}`} onClick={onEnv} aria-describedby="dt-envline-hint">
        <span className="dt-envlabel">在你的环境中</span>
        <span>{env.text}{env.tail && <span className={`bluf-tail tone-${env.tail.tone}`}> · {env.tail.text}</span>}</span>
        <span className="dt-go" id="dt-envline-hint">查看环境检查 ↓</span>
      </button>
    </section>
  );
}
