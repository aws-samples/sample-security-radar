import { Link } from 'react-router-dom';
import type { EventSummary } from '@/types/site-data';
import { SeverityBadge } from './SeverityBadge';
import { SignalBar } from './SignalBar';
import { ImpactChip } from './ImpactChip';
import { EXPLOITATION_WORD } from './detail/VerdictPanel';
import { formatAmount } from '@/utils/formatters';
import { eventTimeLabel } from '@/utils/home';
import '@/styles/home.css';

interface Props {
  event: EventSummary;
  /** One-line summary under the meta row (domain pages); the home monitor keeps rows at ~64 px without it. */
  showSummary?: boolean;
}

const DOMAIN_WORD: Record<EventSummary['domain'], string> = { vuln: '漏洞', incident: '事件', web3: 'Web3' };

/**
 * Monitor row (L1'): domain bar · P · verification signal · title · impact chip · time, meta underneath.
 * The whole row is one link target (stretched title link); the impact chip is a separate link to #env, layered
 * above it — never nested interactive content.
 */
export function EventCard({ event, showSummary = true }: Props) {
  const ex = EXPLOITATION_WORD[event.exploitation];
  const time = eventTimeLabel(event);
  return (
    <article className={`row dom-${event.domain} sev-${event.severity}`}>
      <SeverityBadge severity={event.severity} pulse={event.severity === 'P0'} />
      <SignalBar level={event.level} />
      <div className="row-title">
        <Link to={`/events/${event.event_id}`} title={`${event.title} · 查看进展 →`}>{event.title}</Link>
      </div>
      <span className="row-right">
        <ImpactChip impact={event.impact} eventId={event.event_id} />
        <span className={`row-time${time.longRunning ? ' is-long' : ''}`} title={`首见 ${event.first_seen} · 最后更新 ${event.last_updated}`}>{time.text}</span>
        <span className="row-go" aria-hidden="true">→</span>
      </span>
      <div className="row-meta">
        <span className="row-dom">{DOMAIN_WORD[event.domain]}</span>
        <span title="独立来源数（已去除转载）"><b>{event.independent_sources}</b> 个独立来源</span>
        {event.exploitation !== 'none' && <span className={`tone-${ex.tone} row-ex`}>{ex.text}</span>}
        {event.amount_usd_latest !== null && (
          <span className="row-amt" title={event.amount_disputed ? '各来源金额不一致' : '报道损失金额'}>
            {formatAmount(event.amount_usd_latest)}{event.amount_disputed && <span aria-label="金额有争议"> ⚠</span>}
          </span>
        )}
        {event.cves.length > 0 && <code className="row-cve">{event.cves[0]}{event.cves.length > 1 ? ` +${event.cves.length - 1}` : ''}</code>}
        <span className="row-src">首报 {event.first_report_source}</span>
      </div>
      {showSummary && event.summary && <p className="row-sum">{event.summary}</p>}
    </article>
  );
}
