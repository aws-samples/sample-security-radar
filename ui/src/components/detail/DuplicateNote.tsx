import { Link } from 'react-router-dom';
import type { PossibleDuplicate } from '@/types/site-data';

/** C4: events the model judged to be the same incident — advisory, never merged; the reason is on hover. */
export function DuplicateNote({ dups }: { dups: PossibleDuplicate[] }) {
  if (dups.length === 0) return null;
  return (
    <p className="dt-dup" role="note">
      可能与{dups.map((x, i) => (
        <span key={x.event_id}>{i > 0 && '、'}<Link to={`/events/${x.event_id}`} title={x.why}>{x.title}</Link></span>
      ))}是同一事件 <span className="dt-muted">（模型判断，未合并；理由见悬停）</span>
    </p>
  );
}
