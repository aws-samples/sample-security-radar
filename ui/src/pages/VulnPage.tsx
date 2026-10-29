import { useState } from 'react';
import { useEvents } from '@/hooks/useEvents';
import { EventCard } from '@/components/EventCard';
import { FilterBar } from '@/components/FilterBar';
import { sortEvents, applyFilters, DEFAULT_FILTERS } from '@/utils/filters';
import type { FilterState } from '@/utils/filters';

export function VulnPage() {
  const { events, loading, error } = useEvents();
  const [filters, setFilters] = useState<FilterState>({ ...DEFAULT_FILTERS, domain: 'vuln' });

  const filtered = sortEvents(applyFilters(events, filters));

  if (error) {
    return (
      <div style={{ padding: '40px', color: 'var(--sev-p0)', fontFamily: 'var(--font-mono)' }}>
        {error}
      </div>
    );
  }

  return (
    <div style={{ display: 'flex', flexDirection: 'column', height: '100%', overflow: 'hidden' }}>
      <div style={{ padding: '12px 16px 0', borderBottom: '1px solid var(--border)' }}>
        <h1 style={{ fontFamily: 'var(--font-display)', fontSize: '18px', fontWeight: 700, color: 'var(--domain-vuln)', marginBottom: '2px' }}>
          Vulnerabilities
        </h1>
        <p style={{ fontSize: '11px', color: 'var(--text-muted)', marginBottom: '10px' }}>
          0-days · KEV additions · active exploitation · PoC releases
        </p>
      </div>

      <FilterBar
        filters={filters}
        onChange={f => setFilters({ ...f, domain: 'vuln' })}
        resultCount={filtered.length}
      />

      <div
        role="feed"
        aria-label="Vulnerability events"
        aria-busy={loading}
        style={{ flex: 1, overflowY: 'auto', padding: '12px 16px', display: 'flex', flexDirection: 'column', gap: '8px' }}
      >
        {loading && <div style={{ color: 'var(--text-muted)', fontSize: '12px', fontFamily: 'var(--font-mono)', padding: '20px 0' }}>Loading…</div>}
        {filtered.map(ev => <EventCard key={ev.event_id} event={ev} />)}
        {!loading && filtered.length === 0 && (
          <div style={{ color: 'var(--text-muted)', fontSize: '13px', padding: '40px 0', textAlign: 'center' }}>
            No vulnerability events match the current filters.
          </div>
        )}
      </div>
    </div>
  );
}
