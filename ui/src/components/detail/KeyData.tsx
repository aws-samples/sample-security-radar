import type { AmountPoint, CveDetail, EventSummary, TxRef } from '@/types/site-data';
import { AmountSparkline } from '@/components/AmountSparkline';
import { formatAmount, formatEpss, truncateHash } from '@/utils/formatters';

const TX_WORD: Record<TxRef['verified'], { text: string; tone: string }> = {
  confirmed: { text: '✓ 链上已证实', tone: 'ok' },
  failed: { text: '✕ 交易已回滚', tone: 'loss' },
  unchecked: { text: '· 未核验', tone: 'muted' },
  not_found: { text: '⚠ 链上查无', tone: 'warn' },
  unsupported: { text: '· 该链暂不支持核验', tone: 'muted' },
};

/** CVE table (KEV filled/hollow, EPSS percentile bar), amount history, tx. Renders nothing when all empty. */
export function KeyData({ event, cves, amounts, tx }: { event: EventSummary; cves: CveDetail[]; amounts: AmountPoint[]; tx: TxRef[] }) {
  return (
    <>
      {cves.length > 0 && (
        <>
        <h3 className="dt-h3">CVE <span className="dt-count">{cves.length}</span></h3>
        <table className="kd-table">
          <thead><tr><th scope="col">CVE</th><th scope="col">CISA KEV</th><th scope="col">EPSS（百分位）</th><th scope="col">勒索利用</th></tr></thead>
          <tbody>
            {cves.map(c => (
              <tr key={c.cve}>
                <td className="dt-mono">{c.cve}</td>
                <td>{c.kev ? <span className="kev-yes">● 已收录 {c.kev_date_added ?? ''}</span> : <span className="dt-muted">○ 未收录</span>}</td>
                <td>
                  {c.epss === null
                    ? <span className="dt-muted">—</span>
                    : (
                      <span className="epss">
                        <span className="dt-mono">{formatEpss(c.epss)}</span>
                        {c.epss_percentile !== null && (
                          <>
                            <span className="epss-bar" aria-hidden="true"><span style={{ width: `${Math.round(c.epss_percentile * 100)}%` }} /></span>
                            <span className="dt-mono dt-muted">p{Math.round(c.epss_percentile * 100)}</span>
                          </>
                        )}
                      </span>
                    )}
                </td>
                <td>{c.ransomware === null ? <span className="dt-muted">—</span> : c.ransomware ? <span className="kev-yes">是</span> : '否'}</td>
              </tr>
            ))}
          </tbody>
        </table>
        </>
      )}
      {amounts.length > 0 && (
        <div style={{ marginTop: cves.length ? 14 : 0 }}>
          <h3 className="dt-h3">金额历史</h3>
          <AmountSparkline data={amounts} disputed={event.amount_disputed} width={280} height={60} />
          {event.amount_usd_latest !== null && (
            <p className="dt-small" style={{ marginTop: 6 }}>
              最新估计 <b className="dt-mono" style={{ color: 'var(--loss)' }}>{formatAmount(event.amount_usd_latest)}</b>
              {event.amount_disputed && <span style={{ color: 'var(--p1)', marginLeft: 6 }}>⚠ 各来源相差 3 倍以上，存在争议</span>}
            </p>
          )}
        </div>
      )}
      {tx.length > 0 && (
        <div style={{ marginTop: 14 }}>
          <h3 className="dt-h3">链上交易 <span className="dt-count">{tx.length}</span></h3>
          <ul style={{ listStyle: 'none', padding: 0, margin: 0, display: 'flex', flexDirection: 'column', gap: 4 }}>
            {tx.map(t => (
              <li key={t.hash} className="dt-small" style={{ display: 'flex', gap: 10, alignItems: 'center' }}>
                <span className={`tone-${TX_WORD[t.verified].tone}`} style={{ color: 'var(--tone)' }}>{TX_WORD[t.verified].text}</span>
                <span className="dt-mono dt-muted">{t.chain}</span>
                <code className="dt-mono">{truncateHash(t.hash)}</code>
                {t.explorer_url && <a href={t.explorer_url} target="_blank" rel="noopener noreferrer">浏览器 ↗</a>}
              </li>
            ))}
          </ul>
        </div>
      )}
    </>
  );
}
