/**
 * WallNowBoard — right column, first card on the wall (spec 01 §6.2 ①): the ≤3 backend-ranked NOW events,
 * each with why (reasons verbatim), whether it hits us (ImpactChip) and how old. Same ranks as the radar's
 * leader labels (utils/wall.nowLabels). Whole card = one link that opens the L2 drawer (no nested controls).
 */
import { Link } from 'react-router-dom';
import type { NowCardModel } from '@/utils/home';
import { SeverityBadge } from '@/components/SeverityBadge';
import { LevelBadge } from '@/components/LevelBadge';
import { ImpactChip } from '@/components/ImpactChip';
import { drawerHref } from '@/utils/wall';
import { impactView } from '@/utils/response';
import { agoZh } from '@/utils/timeZh';
import '@/styles/wall.css';

interface Props {
  /** null = the publisher did not emit `now` (older backend) — said so, not shown as "nothing to do". */
  cards: NowCardModel[] | null;
}

export function WallNowBoard({ cards }: Props) {
  if (cards === null) return <p className="wn-empty is-absent">NOW 未生成（后端未产出 now 字段）</p>;
  if (cards.length === 0) return <p className="wn-empty">当前无必须处理事件</p>;
  return (
    <ol className="wn-list" aria-label={`必须处理 ${cards.length} 件，按紧迫度排序`}>
      {cards.map(({ item, event }, i) => (
        <li key={item.event_id}>
          <Link
            to={drawerHref(item.event_id)}
            className={`wn-card sev-${event?.severity ?? 'P2'}`}
            data-testid="wall-now-card"
            aria-label={`第 ${i + 1} 件：${event?.title ?? item.event_id} · ${item.reasons.join('、')}${event && impactView(event.impact) ? ` · ${impactView(event.impact)!.sr}` : ''} · 打开判定抽屉`}
          >
            <span className="wn-head" aria-hidden="true">
              <span className="wn-rank">#{i + 1}</span>
              {event && <SeverityBadge severity={event.severity} pulse={event.severity === 'P0'} />}
              {event && <LevelBadge level={event.level} size="sm" />}
              <span className="wn-chip">{event && <ImpactChip impact={event.impact} />}</span>
            </span>
            <span className="wn-title" aria-hidden="true">{event?.title ?? `${item.event_id}（摘要缺失）`}</span>
            <span className="wn-reasons" aria-hidden="true">
              {item.reasons.slice(0, 3).map(r => <span key={r}>{r}</span>)}
              {event && !item.reasons.some(r => r.startsWith('首见')) && <span className="wn-age">首见 {agoZh(event.first_seen)}</span>}
            </span>
          </Link>
        </li>
      ))}
    </ol>
  );
}
