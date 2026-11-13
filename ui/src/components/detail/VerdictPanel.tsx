import type { Analysis, Disclosure, EventSummary, ProgressStage, Response, Sighting } from '@/types/site-data';
import { SeverityBadge } from '@/components/SeverityBadge';
import { LevelBadge } from '@/components/LevelBadge';
import { ImpactChip } from '@/components/ImpactChip';
import { SentenceText } from '@/components/detail/AnalysisCard';
import type { ResolvedImpact } from '@/utils/response';
import { responseBluf } from '@/utils/response';
import { corroborationMs } from '@/utils/evidence';
import { agoZh, durationZh, utcShort } from '@/utils/timeZh';
import { triageLine } from '@/utils/triageView';
import { titleFix } from '@/utils/retitleView';
import { disclosureLine, fmtDisclosureAt } from '@/utils/disclosureView';
import { sightingLine } from '@/utils/sightingView';

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
  disclosure?: Disclosure | null;
  sighting?: Sighting | null;
}

/** L2 protagonist: what is it, how sure, how bad, does it hit us — one screen, before anything else. */
export function VerdictPanel({ event, analysis, progress, response, impact, cite, onCite, onEnv, disclosure, sighting }: Props) {
  const sight = sightingLine(sighting);
  const disc = disclosureLine(disclosure, fmtDisclosureAt);
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
      {(() => { const f = titleFix(event, iso => `${utcShort(iso)} UTC`); return f && (
        <p className="dt-small dt-muted" data-testid="title-fix">
          {f.text}{f.href && <> · 依据 <a href={f.href} target="_blank" rel="noopener noreferrer">{f.host || '来源'} ↗</a></>}
          <span> · 原标题：{f.original}</span>
        </p>); })()}
      {bluf}
      <div className="dt-timing">
        {disc && (
          <span data-testid="disclosure" className={disc.late ? 'tone-warn' : undefined}
            title="CVE 公开时间来自 CVE 记录（cveawg.mitre.org）；「首报」是第一篇报道的发布时间，「雷达采集」是雷达抓到它的时间">
            {disc.published}{disc.lag && <> · <b>{disc.lag}</b></>}
          </span>
        )}
        {sight ? (
          <>
            <span data-testid="first-report" title="第一篇报道由其来源发布的时间（证据时间）">{sight.report}</span>
            <span data-testid="radar-collected" title="雷达第一次采集到这起事件任一报道的时间">{sight.collected}</span>
          </>
        ) : (
          <span>首报 <b>{agoZh(firstStage?.at ?? event.first_seen)}</b>（{utcShort(firstStage?.at ?? event.first_seen)} UTC · {event.first_report_source}）</span>
        )}
        <span>证实用时 <b>{durationZh(corr) ?? '未证实'}</b>{t1Instant ? '（T1 首报即证实）' : ''}</span>
        <span>最后更新 <b>{agoZh(event.last_updated)}</b></span>
        <span><b>{event.independent_sources}</b> 个独立来源 · <b>{event.item_count}</b> 条证据</span>
        <span title="scripts/triage.py（IAM 凭证）写入，页面只读">处置 <b>{triageLine(event.triage, iso => `${utcShort(iso)} UTC`)}</b></span>
      </div>
      <button type="button" className={`dt-envline tone-${env.tone}`} onClick={onEnv} aria-describedby="dt-envline-hint">
        <span className="dt-envlabel">在你的环境中</span>
        <span>{env.text}{env.tail && <span className={`bluf-tail tone-${env.tail.tone}`}> · {env.tail.text}</span>}</span>
        <span className="dt-go" id="dt-envline-hint">查看环境检查 ↓</span>
      </button>
    </section>
  );
}
