import { Link } from 'react-router-dom';
import type { Digest, EventSummary, Sentence } from '@/types/site-data';
import { ISSUE_WORD } from '@/components/detail/AnalysisCard';

const SECTIONS: { key: 'summary' | 'highlights' | 'watch'; label: string }[] = [
  { key: 'summary', label: '概要' }, { key: 'highlights', label: '要点' }, { key: 'watch', label: '待确认' },
];

/** C7 daily digest (08:00 HKT). Counts come from code (digest.header); each sentence cites events and is checked
 *  like an analysis card — an ungrounded one is shown with its reason, never as fact. Absent ⇒ nothing rendered. */
export function DigestCard({ digest, events }: { digest: Digest | null; events: EventSummary[] }) {
  if (!digest) return null;
  const title = new Map(events.map(e => [e.event_id, e.title]));
  const h = digest.header;
  const quiet = digest.status === 'ok' && h.events === 0;
  return (
    <section className="dg" aria-labelledby="dg-h2">
      <h2 id="dg-h2" className="dg-h2">今日简报 <span className="dg-day tabular">{digest.day}</span>
        <span className="dg-meta">08:00 HKT · 过去 24 小时 · {digest.model.replace(/^global\.anthropic\./, '')}</span>
        {digest.status !== 'ok' && <span className={`dg-status is-${digest.status}`}>{digest.status === 'partial' ? '部分句子未通过校验' : `生成失败：${digest.reason ?? '原因未给出'}`}</span>}
      </h2>
      <p className="dg-counts tabular">
        {h.events} 个事件 · P0 {h.p0} · P1 {h.p1} · 新出现 {h.new} · 升级 {h.escalated} · Web3 {h.web3}
      </p>
      {quiet ? <p className="dg-quiet">过去 24 小时没有 P0/P1 动态，也没有级别变化。</p> : (
        <div className="dg-grid">
          {SECTIONS.map(s => digest[s.key].length > 0 && (
            <div key={s.key} className="dg-block">
              <h3 className="dg-h3">{s.label}</h3>
              <ul>{digest[s.key].map((x: Sentence, i: number) => (
                <li key={i} className={x.grounded ? '' : 'is-ungrounded'}>
                  {x.text}{' '}
                  {x.cite.map(id => title.has(id)
                    ? <Link key={id} className="dg-cite" to={`/events/${id}`} title={title.get(id)} aria-label={`查看事件：${title.get(id)}`}>↗</Link>
                    : <span key={id} className="dg-issue">[引用不在榜]</span>)}
                  {!x.grounded && <em className="dg-issue">未通过校验：{x.issues.map(k => ISSUE_WORD[k] ?? k).join('、')}</em>}
                </li>))}
              </ul>
            </div>))}
        </div>
      )}
    </section>
  );
}
