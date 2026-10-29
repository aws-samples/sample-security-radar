import type { EventSummary, Domain, Level, Severity, Exploitation } from '@/types/site-data';

export interface FilterState {
  domain: Domain | 'all';
  level: Level | 'all';
  severity: Severity | 'all';
  exploitation: Exploitation | 'all';
  /** Funnel drill-down (home L0): touched_24h = last_updated within 24 h; corroborated = level V2+. */
  stage: 'all' | 'touched_24h' | 'corroborated';
  search: string;
}

export const DEFAULT_FILTERS: FilterState = {
  domain: 'all',
  level: 'all',
  severity: 'all',
  exploitation: 'all',
  stage: 'all',
  search: '',
};

const CORROBORATED: ReadonlySet<Level> = new Set<Level>(['V2', 'V3', 'V4']);

/**
 * Apply all active filters to the event list.
 * Pure function — no side effects, fully testable.
 */
export function applyFilters(events: EventSummary[], filters: FilterState, nowMs: number = Date.now()): EventSummary[] {
  const dayAgo = nowMs - 24 * 60 * 60 * 1000;
  return events.filter(ev => {
    if (filters.stage === 'touched_24h' && !(Date.parse(ev.last_updated) >= dayAgo)) return false;
    if (filters.stage === 'corroborated' && !CORROBORATED.has(ev.level)) return false;
    if (filters.domain !== 'all' && ev.domain !== filters.domain) return false;
    if (filters.level !== 'all' && ev.level !== filters.level) return false;
    if (filters.severity !== 'all' && ev.severity !== filters.severity) return false;
    if (filters.exploitation !== 'all' && ev.exploitation !== filters.exploitation) return false;
    if (filters.search.trim()) {
      const q = filters.search.trim().toLowerCase();
      const haystack = [
        ev.title,
        ...ev.cves,
        ...ev.entities,
        ev.first_report_source,
        ev.event_id,
      ].join(' ').toLowerCase();
      if (!haystack.includes(q)) return false;
    }
    return true;
  });
}

/**
 * Sort events: P0 first, then by last_updated descending.
 * V3/V4 events with same severity sort above V0/V1.
 */
export function sortEvents(events: EventSummary[]): EventSummary[] {
  const sevOrder: Record<Severity, number> = { P0: 0, P1: 1, P2: 2 };
  return [...events].sort((a, b) => {
    const sevDiff = sevOrder[a.severity] - sevOrder[b.severity];
    if (sevDiff !== 0) return sevDiff;
    return new Date(b.last_updated).getTime() - new Date(a.last_updated).getTime();
  });
}
