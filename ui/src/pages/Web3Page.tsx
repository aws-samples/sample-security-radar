import { useState } from 'react';
import { useEvents } from '@/hooks/useEvents';
import { EventCard } from '@/components/EventCard';
import { FilterBar } from '@/components/FilterBar';
import { sortEvents, applyFilters, DEFAULT_FILTERS } from '@/utils/filters';
import type { FilterState } from '@/utils/filters';
import { formatAmount } from '@/utils/formatters';

export function Web3Page() {
  const { events, loading, error } = useEvents();
  const [filters, setFilters] = useState<FilterState>({ ...DEFAULT_FILTERS, domain: 'web3' });

  const web3Events = events.filter(e => e.domain === 'web3');
  const filtered = sortEvents(applyFilters(events, filters));

  // Chain distribution
  const chainCount: Record<string, number> = {};
  for (const ev of web3Events) {
    for (const chain of ev.chains) {
      chainCount[chain] = (chainCount[chain] ?? 0) + 1;
    }
  }
  const chainsSorted = Object.entries(chainCount).sort((a, b) => b[1] - a[1]);

  // Total by amount
  const byAmount = web3Events
    .filter(e => e.amount_usd_latest !== null)
    .sort((a, b) => (b.amount_usd_latest ?? 0) - (a.amount_usd_latest ?? 0));

  // Aggregate KPIs
  const totalLoss = web3Events.reduce((s, e) => s + (e.amount_usd_latest ?? 0), 0);
  const p0Count = web3Events.filter(e => e.severity === 'P0').length;
  const chainCount2 = Object.keys(chainCount).length;

  if (error) {
    return (
      <div style={{ padding: '40px', color: 'var(--sev-p0)', fontFamily: 'var(--font-mono)' }}>
        {error}
      </div>
    );
  }

  return (
    <div style={{ display: 'flex', flexDirection: 'column', height: '100%', overflow: 'hidden' }}>

      {/* Hero header with mesh gradient background */}
      <div style={{
        padding: '16px 20px',
        borderBottom: '1px solid var(--border)',
        background: `
          radial-gradient(ellipse 60% 80% at 10% 0%, color-mix(in srgb, var(--domain-web3) 10%, transparent) 0%, transparent 70%),
          radial-gradient(ellipse 40% 60% at 90% 100%, color-mix(in srgb, var(--text-accent) 8%, transparent) 0%, transparent 70%),
          var(--bg-base)
        `,
        flexShrink: 0,
      }}>
        <div style={{ display: 'flex', alignItems: 'baseline', gap: '12px', marginBottom: '4px' }}>
          <h1 style={{
            fontFamily: 'var(--font-display)',
            fontSize: '20px',
            fontWeight: 700,
            background: 'linear-gradient(135deg, var(--domain-web3) 0%, var(--text-accent) 100%)',
            WebkitBackgroundClip: 'text',
            WebkitTextFillColor: 'transparent',
            backgroundClip: 'text',
            margin: 0,
          }}>
            Web3 Events
          </h1>
          <span style={{ fontSize: '11px', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>
            DeFi exploits · CEX hacks · bridge attacks · supply chain
          </span>
        </div>

        {/* KPI strip */}
        {!loading && (
          <div style={{ display: 'flex', gap: '10px', marginTop: '10px', flexWrap: 'wrap' }}>
            {/* Total loss */}
            <div style={{
              background: 'var(--bg-glass)',
              backdropFilter: 'blur(10px)',
              WebkitBackdropFilter: 'blur(10px)',
              border: '1px solid var(--border-glass)',
              borderTop: '2px solid var(--domain-web3)',
              borderRadius: 'var(--r-sm)',
              padding: '8px 16px',
              minWidth: '130px',
            }}>
              <div style={{
                fontFamily: 'var(--font-display)',
                fontSize: '20px',
                fontWeight: 700,
                background: 'linear-gradient(135deg, var(--domain-web3) 0%, var(--text-accent) 100%)',
                WebkitBackgroundClip: 'text',
                WebkitTextFillColor: 'transparent',
                backgroundClip: 'text',
                lineHeight: 1.1,
                fontVariantNumeric: 'tabular-nums',
              }}>
                {totalLoss > 0 ? formatAmount(totalLoss) : '—'}
              </div>
              <div style={{ fontSize: '9px', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)', letterSpacing: '0.08em', marginTop: '2px' }}>
                TOTAL TRACKED LOSS
              </div>
            </div>

            {/* P0 count */}
            <div style={{
              background: 'var(--bg-glass)',
              backdropFilter: 'blur(10px)',
              WebkitBackdropFilter: 'blur(10px)',
              border: '1px solid var(--border-glass)',
              borderTop: '2px solid var(--sev-p0)',
              borderRadius: 'var(--r-sm)',
              padding: '8px 16px',
              minWidth: '90px',
            }}>
              <div style={{
                fontFamily: 'var(--font-display)',
                fontSize: '20px',
                fontWeight: 700,
                color: 'var(--sev-p0)',
                lineHeight: 1.1,
                fontVariantNumeric: 'tabular-nums',
              }}>
                {p0Count}
              </div>
              <div style={{ fontSize: '9px', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)', letterSpacing: '0.08em', marginTop: '2px' }}>
                P0 CRITICAL
              </div>
            </div>

            {/* Chains hit */}
            <div style={{
              background: 'var(--bg-glass)',
              backdropFilter: 'blur(10px)',
              WebkitBackdropFilter: 'blur(10px)',
              border: '1px solid var(--border-glass)',
              borderTop: '2px solid var(--text-accent)',
              borderRadius: 'var(--r-sm)',
              padding: '8px 16px',
              minWidth: '90px',
            }}>
              <div style={{
                fontFamily: 'var(--font-display)',
                fontSize: '20px',
                fontWeight: 700,
                color: 'var(--text-accent)',
                lineHeight: 1.1,
                fontVariantNumeric: 'tabular-nums',
              }}>
                {chainCount2}
              </div>
              <div style={{ fontSize: '9px', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)', letterSpacing: '0.08em', marginTop: '2px' }}>
                CHAINS AFFECTED
              </div>
            </div>

            {/* Top loss entity */}
            {byAmount[0] && (
              <div style={{
                background: 'var(--bg-glass)',
                backdropFilter: 'blur(10px)',
                WebkitBackdropFilter: 'blur(10px)',
                border: '1px solid var(--border-glass)',
                borderTop: `2px solid color-mix(in srgb, var(--domain-web3) 60%, var(--text-accent))`,
                borderRadius: 'var(--r-sm)',
                padding: '8px 16px',
                minWidth: '140px',
              }}>
                <div style={{
                  fontFamily: 'var(--font-display)',
                  fontSize: '14px',
                  fontWeight: 700,
                  color: 'var(--text-primary)',
                  lineHeight: 1.2,
                  overflow: 'hidden',
                  textOverflow: 'ellipsis',
                  whiteSpace: 'nowrap',
                  maxWidth: '160px',
                }}>
                  {byAmount[0].entities[0] ?? byAmount[0].title.split(' ')[0]}
                </div>
                <div style={{
                  fontFamily: 'var(--font-mono)',
                  fontSize: '11px',
                  color: byAmount[0].amount_disputed ? 'var(--sev-p1)' : 'var(--domain-web3)',
                  fontWeight: 600,
                  marginTop: '1px',
                }}>
                  {formatAmount(byAmount[0].amount_usd_latest!)}
                  {byAmount[0].amount_disputed ? ' ⚠' : ''}
                </div>
                <div style={{ fontSize: '9px', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)', letterSpacing: '0.08em', marginTop: '2px' }}>
                  LARGEST SINGLE LOSS
                </div>
              </div>
            )}

            {/* Chain breakdown mini */}
            {chainsSorted.length > 0 && (
              <div style={{
                background: 'var(--bg-glass)',
                backdropFilter: 'blur(10px)',
                WebkitBackdropFilter: 'blur(10px)',
                border: '1px solid var(--border-glass)',
                borderRadius: 'var(--r-sm)',
                padding: '8px 16px',
                minWidth: '110px',
              }}>
                <div style={{ fontSize: '9px', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)', letterSpacing: '0.08em', marginBottom: '5px' }}>
                  TOP CHAINS
                </div>
                {chainsSorted.slice(0, 4).map(([chain, count]) => (
                  <div key={chain} style={{
                    display: 'flex', justifyContent: 'space-between', gap: '10px',
                    fontSize: '10px', fontFamily: 'var(--font-mono)', marginBottom: '2px',
                  }}>
                    <span style={{ color: 'var(--text-secondary)' }}>{chain}</span>
                    <span style={{ color: 'var(--domain-web3)', fontWeight: 600 }}>{count}</span>
                  </div>
                ))}
              </div>
            )}
          </div>
        )}
      </div>

      {/* Filters */}
      <FilterBar
        filters={filters}
        onChange={f => setFilters({ ...f, domain: 'web3' })}
        resultCount={filtered.length}
      />

      {/* List */}
      <div
        role="feed"
        aria-label="Web3 security events"
        aria-busy={loading}
        style={{ flex: 1, overflowY: 'auto', padding: '12px 16px', display: 'flex', flexDirection: 'column', gap: '8px' }}
      >
        {loading && <div style={{ color: 'var(--text-muted)', fontSize: '12px', fontFamily: 'var(--font-mono)', padding: '20px 0' }}>Loading…</div>}
        {filtered.map(ev => <EventCard key={ev.event_id} event={ev} />)}
        {!loading && filtered.length === 0 && (
          <div style={{ color: 'var(--text-muted)', fontSize: '13px', padding: '40px 0', textAlign: 'center' }}>
            No Web3 events match the current filters.
          </div>
        )}
      </div>
    </div>
  );
}
