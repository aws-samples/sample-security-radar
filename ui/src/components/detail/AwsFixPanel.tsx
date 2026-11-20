import type { AwsFix } from '@/types/site-data';
import { safeHref } from '@/utils/safeHref';

/** Status rows in reading order — what a colleague asks first: is AWS's own build fixed? (Neo 2026-11-18) */
const ROWS: { key: 'fixed' | 'pending' | 'no_fix' | 'not_affected' | 'other'; label: string; tone: string }[] = [
  { key: 'fixed', label: '已修复', tone: 'ok' },
  { key: 'pending', label: '待修复', tone: 'warn' },
  { key: 'no_fix', label: '不出修复', tone: 'loss' },
  { key: 'not_affected', label: '不受影响', tone: 'muted' },
  { key: 'other', label: '其他', tone: 'muted' },
];

/** AWS's own fix status for the event's CVE (radar.awsfix, Amazon Linux Security Center). Nothing when unknown. */
export function AwsFixPanel({ fix }: { fix: AwsFix | null | undefined }) {
  if (!fix) return null;
  const href = safeHref(fix.url);
  const s = fix.summary;
  return (
    <div className="awsfix" aria-label="AWS 修复状态">
      <h3 className="dt-h3">AWS 修复状态 <span className="dt-en">Amazon Linux Security Center · {fix.cve}</span></h3>
      {fix.line && <p className="awsfix-line">{fix.line}</p>}
      <table className="kd-table">
        <tbody>
          {ROWS.filter(r => (s[r.key] ?? []).length > 0).map(r => (
            <tr key={r.key}>
              <th scope="row" className={`tone-${r.tone}`}>{r.label}</th>
              <td>{(s[r.key] ?? []).map(p => `${p.package}（${p.platforms.join('、')}）`).join('；')}</td>
            </tr>
          ))}
        </tbody>
      </table>
      <p className="dt-muted">
        {s.advisories.length > 0 && <>公告 {s.advisories.join('、')} · </>}
        {href ? <a href={href} target="_blank" rel="noopener noreferrer">来源</a> : '来源'} · 核对于 {fix.checked_at.slice(0, 16).replace('T', ' ')} UTC
      </p>
    </div>
  );
}
