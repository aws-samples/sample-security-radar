import { healthSummary } from '@/utils/health';
import { useSources } from '@/hooks/useSources';
import { formatDateTime } from '@/utils/formatters';

const STATUS_META: Record<string, { color: string; label: string; shape: string }> = {
  ok:        { color: 'var(--status-ok)',       label: 'OK',        shape: '●' },
  degraded:  { color: 'var(--status-degraded)', label: 'Degraded',  shape: '▲' },
  failing:   { color: 'var(--status-failing)',  label: 'Failing',   shape: '✕' },
  disabled:  { color: 'var(--status-disabled)', label: 'Disabled',  shape: '◇' },
  never_run: { color: 'var(--status-never)',    label: 'Never run', shape: '○' },
};

const DOMAIN_COLOR: Record<string, string> = {
  vuln:     'var(--domain-vuln)',
  incident: 'var(--domain-incident)',
  web3:     'var(--domain-web3)',
};

export function SourcesPage() {
  const { sources, generatedAt, loading, error } = useSources();


  if (error) {
    return (
      <div style={{ padding: '40px', color: 'var(--sev-p0)', fontFamily: 'var(--font-mono)' }}>
        {error}
      </div>
    );
  }

  return (
    <div style={{ display: 'flex', flexDirection: 'column', height: '100%', overflow: 'hidden' }}>
      {/* Header */}
      <div style={{ padding: '12px 16px', borderBottom: '1px solid var(--border)' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexWrap: 'wrap', gap: '8px' }}>
          <div>
            <h1 style={{ fontFamily: 'var(--font-display)', fontSize: '18px', fontWeight: 700, color: 'var(--text-primary)', marginBottom: '2px' }}>
              Source Health
            </h1>
            <p style={{ fontSize: '11px', color: 'var(--text-muted)' }}>
              {sources.length} registered · {(() => {
                const h = healthSummary(sources, loading);
                if (h.kind === 'loading') return <span>checking…</span>;
                if (h.kind === 'no_data') return <span style={{ color: 'var(--sev-p1)' }}>no source data</span>;
                if (h.kind === 'attention') return <span style={{ color: 'var(--sev-p1)' }}>{h.count} need attention</span>;
                return <span style={{ color: 'var(--status-ok)' }}>all healthy</span>;
              })()}
            </p>
          </div>
          {generatedAt && (
            <span style={{ fontSize: '10px', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>
              as of {formatDateTime(generatedAt)}
            </span>
          )}
        </div>
      </div>

      {/* Table */}
      <div style={{ flex: 1, overflowY: 'auto', padding: '12px 16px' }}>
        {loading && (
          <div style={{ color: 'var(--text-muted)', fontSize: '12px', fontFamily: 'var(--font-mono)', padding: '20px 0' }}>
            Loading…
          </div>
        )}
        {!loading && (
          <table
            style={{ width: '100%', borderCollapse: 'collapse', fontSize: '12px' }}
            aria-label="Source health table"
          >
            <thead>
              <tr style={{ borderBottom: '2px solid var(--border)' }}>
                {['Status', 'Source', 'Tier', 'Domain', 'Cadence', 'Items 24h', 'Last success', 'Last error'].map(h => (
                  <th key={h} scope="col" style={{
                    textAlign: 'left',
                    padding: '6px 10px',
                    fontSize: '10px',
                    fontWeight: 700,
                    color: 'var(--text-muted)',
                    letterSpacing: '0.08em',
                    whiteSpace: 'nowrap',
                    fontFamily: 'var(--font-body)',
                  }}>
                    {h}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {sources.map(src => {
                const sm = STATUS_META[src.status] ?? STATUS_META.disabled;
                return (
                  <tr
                    key={src.source_id}
                    style={{
                      borderBottom: '1px solid var(--border-soft)',
                      background: src.status === 'failing' ? 'rgba(239,68,68,0.04)' : 'none',
                    }}
                  >
                    {/* Status */}
                    <td style={{ padding: '8px 10px', whiteSpace: 'nowrap' }}>
                      <span
                        aria-label={`Status: ${sm.label}`}
                        style={{ color: sm.color, fontFamily: 'var(--font-mono)', fontSize: '11px', display: 'flex', alignItems: 'center', gap: '5px' }}
                      >
                        <span aria-hidden="true">{sm.shape}</span>
                        {sm.label}
                      </span>
                    </td>

                    {/* Name */}
                    <td style={{ padding: '8px 10px', color: 'var(--text-primary)', fontWeight: 500 }}>
                      {src.name}
                    </td>

                    {/* Tier */}
                    <td style={{ padding: '8px 10px' }}>
                      <span style={{
                        fontFamily: 'var(--font-mono)', fontSize: '10px',
                        color: src.tier === 'T1' ? 'var(--level-v3)' : src.tier === 'T2' ? 'var(--level-v2)' : 'var(--text-muted)',
                      }}>
                        {src.tier}
                      </span>
                    </td>

                    {/* Domain */}
                    <td style={{ padding: '8px 10px' }}>
                      <span style={{ fontSize: '10px', fontFamily: 'var(--font-mono)', color: DOMAIN_COLOR[src.domain] ?? 'var(--text-secondary)' }}>
                        {src.domain}
                      </span>
                    </td>

                    {/* Cadence */}
                    <td style={{ padding: '8px 10px', fontFamily: 'var(--font-mono)', color: 'var(--text-secondary)', fontSize: '11px' }}>
                      {src.cadence_min}m
                    </td>

                    {/* Items 24h */}
                    <td style={{ padding: '8px 10px', fontFamily: 'var(--font-mono)', color: src.items_24h > 0 ? 'var(--text-accent)' : 'var(--text-muted)', fontSize: '11px' }}>
                      {src.items_24h}
                    </td>

                    {/* Last success */}
                    <td style={{ padding: '8px 10px', fontFamily: 'var(--font-mono)', color: 'var(--text-secondary)', fontSize: '10px', whiteSpace: 'nowrap' }}>
                      {src.last_success ? formatDateTime(src.last_success) : '—'}
                    </td>

                    {/* Last error */}
                    <td style={{ padding: '8px 10px', fontSize: '11px', maxWidth: '200px' }}>
                      {src.last_error ? (
                        <span style={{ color: 'var(--sev-p0)', fontFamily: 'var(--font-mono)', fontSize: '10px' }} title={src.last_error}>
                          {src.last_error.length > 50 ? src.last_error.slice(0, 50) + '…' : src.last_error}
                        </span>
                      ) : (
                        <span style={{ color: 'var(--text-muted)' }}>—</span>
                      )}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}
