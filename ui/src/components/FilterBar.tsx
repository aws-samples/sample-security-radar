import type { Domain, Level, Severity, Exploitation } from '@/types/site-data';
import type { FilterState } from '@/utils/filters';
import { DEFAULT_FILTERS } from '@/utils/filters';

interface Props {
  filters: FilterState;
  onChange: (f: FilterState) => void;
  resultCount: number;
}

const inputBase: React.CSSProperties = {
  background: 'var(--bg-surface)',
  border: '1px solid var(--border)',
  borderRadius: 'var(--r-sm)',
  color: 'var(--text-primary)',
  fontSize: '12px',
  fontFamily: 'var(--font-body)',
  outline: 'none',
  transition: 'border-color 0.15s, box-shadow 0.15s',
};

const selectStyle: React.CSSProperties = {
  ...inputBase,
  padding: '5px 28px 5px 10px',
  cursor: 'pointer',
  appearance: 'none',
  backgroundImage: `url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='10' height='6' viewBox='0 0 10 6'%3E%3Cpath d='M0 0l5 6 5-6z' fill='%236080aa'/%3E%3C/svg%3E")`,
  backgroundRepeat: 'no-repeat',
  backgroundPosition: 'right 8px center',
  backgroundSize: '8px',
  minWidth: '120px',
};

function onFocus(e: React.FocusEvent<HTMLElement>) {
  (e.target as HTMLElement).style.borderColor = 'var(--text-accent)';
  (e.target as HTMLElement).style.boxShadow = '0 0 0 3px color-mix(in srgb, var(--text-accent) 18%, transparent)';
}
function onBlur(e: React.FocusEvent<HTMLElement>) {
  (e.target as HTMLElement).style.borderColor = 'var(--border)';
  (e.target as HTMLElement).style.boxShadow = 'none';
}

export function FilterBar({ filters, onChange, resultCount }: Props) {
  const set = <K extends keyof FilterState>(key: K, value: FilterState[K]) =>
    onChange({ ...filters, [key]: value });

  const hasActiveFilters =
    filters.domain !== 'all' || filters.level !== 'all' ||
    filters.severity !== 'all' || filters.exploitation !== 'all' || filters.stage !== 'all' || filters.search;

  return (
    <div style={{
      display: 'flex',
      gap: '8px',
      alignItems: 'center',
      flexWrap: 'wrap',
      padding: '10px 16px',
      borderBottom: '1px solid var(--border)',
      background: 'var(--bg-base)',
    }}>
      {/* Search */}
      <input
        type="search"
        placeholder="Search title, CVE, entity…"
        value={filters.search}
        onChange={e => set('search', e.target.value)}
        aria-label="Search events"
        style={{ ...inputBase, padding: '5px 10px', width: '220px' }}
        onFocus={onFocus}
        onBlur={onBlur}
      />

      {/* Domain */}
      <label style={{ display: 'flex', alignItems: 'center', gap: '5px', fontSize: '11px', color: 'var(--text-muted)' }}>
        Domain
        <select
          value={filters.domain}
          onChange={e => set('domain', e.target.value as Domain | 'all')}
          style={selectStyle}
          aria-label="Filter by domain"
          onFocus={onFocus}
          onBlur={onBlur}
        >
          <option value="all">All domains</option>
          <option value="vuln">Vulnerability</option>
          <option value="incident">Incident</option>
          <option value="web3">Web3</option>
        </select>
      </label>

      {/* Level */}
      <label style={{ display: 'flex', alignItems: 'center', gap: '5px', fontSize: '11px', color: 'var(--text-muted)' }}>
        Level
        <select
          value={filters.level}
          onChange={e => set('level', e.target.value as Level | 'all')}
          style={selectStyle}
          aria-label="Filter by level"
          onFocus={onFocus}
          onBlur={onBlur}
        >
          <option value="all">All levels</option>
          <option value="V0">V0 Rumor</option>
          <option value="V1">V1 Reported</option>
          <option value="V2">V2 Corroborated</option>
          <option value="V3">V3 Confirmed</option>
          <option value="V4">V4 Finalized</option>
          <option value="X">X Disputed</option>
        </select>
      </label>

      {/* Severity */}
      <label style={{ display: 'flex', alignItems: 'center', gap: '5px', fontSize: '11px', color: 'var(--text-muted)' }}>
        Severity
        <select
          value={filters.severity}
          onChange={e => set('severity', e.target.value as Severity | 'all')}
          style={selectStyle}
          aria-label="Filter by severity"
          onFocus={onFocus}
          onBlur={onBlur}
        >
          <option value="all">All severities</option>
          <option value="P0">P0 Critical</option>
          <option value="P1">P1 High</option>
          <option value="P2">P2 Medium</option>
        </select>
      </label>

      {/* Exploitation */}
      <label style={{ display: 'flex', alignItems: 'center', gap: '5px', fontSize: '11px', color: 'var(--text-muted)' }}>
        Exploitation
        <select
          value={filters.exploitation}
          onChange={e => set('exploitation', e.target.value as Exploitation | 'all')}
          style={selectStyle}
          aria-label="Filter by exploitation"
          onFocus={onFocus}
          onBlur={onBlur}
        >
          <option value="all">All</option>
          <option value="confirmed">Confirmed</option>
          <option value="reported">Reported</option>
          <option value="poc">PoC only</option>
          <option value="none">None</option>
        </select>
      </label>

      {/* Result count */}
      <span
        className="tabular"
        style={{ marginLeft: 'auto', fontSize: '11px', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}
        aria-live="polite"
        aria-atomic="true"
      >
        {resultCount} event{resultCount !== 1 ? 's' : ''}
      </span>

      {/* Clear */}
      {hasActiveFilters && (
        <button
          onClick={() => onChange({ ...DEFAULT_FILTERS })}
          style={{
            background: 'none',
            border: '1px solid var(--border)',
            borderRadius: 'var(--r-sm)',
            color: 'var(--text-secondary)',
            fontSize: '11px',
            padding: '4px 10px',
            transition: 'background 0.12s',
          }}
          onMouseEnter={e => ((e.currentTarget as HTMLElement).style.background = 'var(--bg-surface-2)')}
          onMouseLeave={e => ((e.currentTarget as HTMLElement).style.background = 'none')}
        >
          Clear filters
        </button>
      )}
    </div>
  );
}
