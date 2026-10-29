import { Link } from 'react-router-dom';
import type { ImpactSummary } from '@/types/site-data';
import { impactView } from '@/utils/response';
import '@/styles/detail.css'; // .impact-chip / .tone-* live there; explicit so list pages never render it unstyled

interface Props {
  impact: ImpactSummary | null | undefined;
  /** list = hidden when null/not_eligible; detail = always rendered (未检查 / 不适用). */
  context?: 'list' | 'detail';
  /** Show the "在你的环境中" prefix inside the chip. */
  withContext?: boolean;
  /** When set (lists, NOW cards) the chip is a link to the event's 在你的环境中 section. */
  eventId?: string;
}

/** "Does it hit us" chip — glyph + text + colour (double-encoded); wording lives in utils/response.impactView. */
export function ImpactChip({ impact, context = 'list', withContext = false, eventId }: Props) {
  const v = impactView(impact, context);
  if (!v) return null;
  const cls = `impact-chip tone-${v.tone}${v.tone === 'warn' ? ' is-warn' : ''}`;
  const body = (
    <>
      {v.live ? <span className="live-dot" aria-hidden="true" /> : <span aria-hidden="true">{v.glyph}</span>}
      {withContext && <span className="impact-ctx" aria-hidden="true">在你的环境中</span>}
      <span aria-hidden="true">{v.label}</span>
    </>
  );
  if (eventId) {
    return (
      <Link to={`/events/${encodeURIComponent(eventId)}?section=env`} className={`${cls} is-link`} aria-label={`${v.sr}（查看环境检查）`} title={`${v.sr} · 查看环境检查 →`}>
        {body}
      </Link>
    );
  }
  return <span className={cls} role="img" aria-label={v.sr} title={v.sr}>{body}</span>;
}
