import { Link } from 'react-router-dom';
import type { NowCardModel } from '@/utils/home';
import { SeverityBadge } from '@/components/SeverityBadge';
import { LevelBadge } from '@/components/LevelBadge';
import { ImpactChip } from '@/components/ImpactChip';
import { EXPLOITATION_WORD } from '@/components/detail/VerdictPanel';
import { agoZh, utcShort } from '@/utils/timeZh';

interface Props {
  /** null = the publisher did not emit `now` (older backend). */
  cards: NowCardModel[] | null;
  generatedAt: string | null;
  sourcesLine: string | null;
}

/** L1 "必须处理": ≤3 backend-ranked cards. Each says why (reasons verbatim), whether it hits us, and where to go next. */
export function NowBoard({ cards, generatedAt, sourcesLine }: Props) {
  if (cards === null) {
    return <p className="now-empty is-absent">NOW 未生成（后端未产出 now 字段）· 下方监控列表仍完整</p>;
  }
  if (cards.length === 0) {
    return (
      <p className="now-empty">
        当前无必须处理事件 · 最近检查 {generatedAt ? `${utcShort(generatedAt)} UTC` : '—'}{sourcesLine ? ` · ${sourcesLine}` : ''}
      </p>
    );
  }
  return (
    <ol className="now-grid" aria-label={`必须处理 ${cards.length} 件，按紧迫度排序`}>
      {cards.map(({ item, event }, i) => {
        const href = `/events/${encodeURIComponent(item.event_id)}`;
        if (!event) {
          // now[] names an event the list does not carry (publisher race) — show it, never drop it silently.
          return (
            <li key={item.event_id} className="now-card is-missing">
              <span className="now-rank" aria-hidden="true">{String(i + 1).padStart(2, '0')}</span>
              <h3 className="now-title"><Link to={href}>{item.event_id}</Link></h3>
              <p className="now-missing">摘要缺失（events.json 无此事件）</p>
              <ul className="now-reasons" aria-label="入选理由">{item.reasons.map(r => <li key={r}>{r}</li>)}</ul>
              <span className="now-go" aria-hidden="true">查看进展 →</span>
            </li>
          );
        }
        const ex = EXPLOITATION_WORD[event.exploitation];
        return (
          <li key={item.event_id} className={`now-card sev-${event.severity} dom-${event.domain}`}>
            <div className="now-head">
              <span className="now-rank" aria-hidden="true">{String(i + 1).padStart(2, '0')}</span>
              <SeverityBadge severity={event.severity} pulse={event.severity === 'P0'} />
              <LevelBadge level={event.level} size="sm" />
              <span className="now-chip"><ImpactChip impact={event.impact} eventId={event.event_id} withContext /></span>
            </div>
            <h3 className="now-title"><Link to={href} title={`${event.title} · 查看进展 →`}>{event.title}</Link></h3>
            <ul className="now-reasons" aria-label="入选理由">
              {item.reasons.map(r => <li key={r}>{r}</li>)}
            </ul>
            <div className="now-foot">
              {event.exploitation !== 'none' && !item.reasons.includes(ex.text) && <span className={`dt-word tone-${ex.tone}`}>{ex.text}</span>}
              {!item.reasons.some(r => r.startsWith('首见')) && <span className="now-age" title={event.first_seen}>首见 {agoZh(event.first_seen)}</span>}
              <span className="now-go" aria-hidden="true">查看进展 →</span>
            </div>
          </li>
        );
      })}
    </ol>
  );
}
