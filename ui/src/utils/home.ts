/**
 * Home (#/) — single-source view logic for L0 (headline + funnel) → L1 (NOW) → L1' (monitor by lifecycle).
 * Every "how do we read this field" decision for the home page lives here once (degradation-and-guards §6),
 * so RadarPage / NowBoard / EventCard cannot each guess differently. Pure; tested in src/test/home.test.ts.
 */
import type { EventSummary, Funnel, Level, Lifecycle, NowItem, SourceHealth } from '@/types/site-data';
import type { FilterState } from '@/utils/filters';
import { DEFAULT_FILTERS, sortEvents } from '@/utils/filters';
import { agoZh } from '@/utils/timeZh';

const DAY_MS = 24 * 60 * 60 * 1000;

// ── L1' lifecycle groups ────────────────────────────────────────────────────────────────────────────────

/** Reading order of the monitor: what is moving first, what is settled last. */
export const LIFECYCLE_ORDER: readonly Lifecycle[] = ['escalating', 'active', 'cooling', 'finalized', 'dormant'];
export type LifecycleKey = Lifecycle | 'unknown';

export const LIFECYCLE_LABEL: Record<LifecycleKey, string> = {
  escalating: '升级中', active: '活跃', cooling: '冷却', finalized: '定稿', dormant: '休眠',
  unknown: '未分组',
};

export interface LifecycleGroup {
  key: LifecycleKey;
  label: string;
  /** Already sorted (P0 first, then last_updated desc — utils/filters.sortEvents). */
  events: EventSummary[];
  /** dormant (>14 d quiet) is folded by default: present, but not worth first-screen space. */
  folded: boolean;
}

/**
 * Bucket events by `lifecycle` in LIFECYCLE_ORDER. All five lifecycle groups are always returned (possibly
 * empty) so tab counts are stable; `unknown` is appended only when non-empty.
 * Dirty-data source: `lifecycle` is optional in the contract (M2 field; an older publisher omits it). Without
 * the `unknown` bucket those events would silently vanish from every tab — so they are kept and labelled.
 */
export function groupByLifecycle(events: EventSummary[]): LifecycleGroup[] {
  const buckets = new Map<LifecycleKey, EventSummary[]>();
  for (const k of LIFECYCLE_ORDER) buckets.set(k, []);
  const unknown: EventSummary[] = [];
  for (const ev of events) {
    const b = ev.lifecycle ? buckets.get(ev.lifecycle) : undefined;
    (b ?? unknown).push(ev);
  }
  const groups: LifecycleGroup[] = LIFECYCLE_ORDER.map(k => ({
    key: k, label: LIFECYCLE_LABEL[k], events: sortEvents(buckets.get(k)!), folded: k === 'dormant',
  }));
  if (unknown.length) groups.push({ key: 'unknown', label: LIFECYCLE_LABEL.unknown, events: sortEvents(unknown), folded: false });
  return groups;
}

// ── L1 NOW ──────────────────────────────────────────────────────────────────────────────────────────────

export interface NowCardModel {
  item: NowItem;
  /** null = now[] names an event the list does not carry (publisher race). Shown, never dropped. */
  event: EventSummary | null;
}

/**
 * Join `now[]` (backend-ranked, ≤3) to the summaries. Returns null when the `now` key is absent (older
 * publisher ⇒ "NOW 未生成"), [] when the backend says nothing must be handled. Backend order is kept: the
 * score is internal and never re-derived here.
 */
export function resolveNow(now: NowItem[] | null | undefined, events: EventSummary[]): NowCardModel[] | null {
  if (now == null) return null;
  const byId = new Map(events.map(e => [e.event_id, e]));
  return now.map(item => ({ item, event: byId.get(item.event_id) ?? null }));
}

// ── L0 funnel ───────────────────────────────────────────────────────────────────────────────────────────

/** Which monitor filter a funnel segment applies when clicked (null = informational only). */
export type FunnelAction = 'touched_24h' | 'corroborated' | 'p0' | null;

export interface FunnelSegment {
  key: keyof Omit<Funnel, 'window_hours'>;
  label: string;
  value: number;
  action: FunnelAction;
  /** 0..1 bar width on a log scale — 34,404 → 2 must stay readable; linear would make the last three 0 px. */
  frac: number;
}

export interface FunnelView {
  windowHours: number;
  segments: FunnelSegment[];
  /** fetched === 0 means collection itself is down — the funnel is not "quiet", it is blind. */
  blind: boolean;
}

const FUNNEL_DEF: ReadonlyArray<Pick<FunnelSegment, 'key' | 'label' | 'action'>> = [
  { key: 'fetched', label: '采集', action: null },
  { key: 'new_or_updated_items', label: '新/更新', action: null },
  { key: 'events_touched', label: '事件', action: 'touched_24h' },
  { key: 'corroborated', label: '证实', action: 'corroborated' },
  { key: 'p0', label: 'P0', action: 'p0' },
];

/** null when the publisher did not emit `funnel` — rendered as NoData, never as a row of zeros. */
export function funnelView(funnel: Funnel | null | undefined): FunnelView | null {
  if (!funnel) return null;
  const max = Math.max(1, ...FUNNEL_DEF.map(d => funnel[d.key]));
  const segments = FUNNEL_DEF.map(d => {
    const value = funnel[d.key];
    return { ...d, value, frac: value <= 0 ? 0 : Math.log10(value + 1) / Math.log10(max + 1) };
  });
  return { windowHours: funnel.window_hours, segments, blind: funnel.fetched === 0 };
}

/** Funnel click → monitor filter. One mapping, so the segment label and the filter can never disagree. */
export function applyFunnelAction(filters: FilterState, action: FunnelAction): FilterState {
  switch (action) {
    case 'touched_24h': return { ...filters, stage: 'touched_24h' };
    case 'corroborated': return { ...filters, stage: 'corroborated' };
    case 'p0': return { ...filters, severity: 'P0' };
    default: return filters;
  }
}

// ── Monitor row ─────────────────────────────────────────────────────────────────────────────────────────

/** Backfill threshold: first_seen this far before last_updated ⇒ an old incident freshly ingested. */
export const BACKFILL_GAP_MS = 30 * DAY_MS;

/**
 * Row time label. Dirty-data source: DeFiLlama batch backfills 2021 hacks with last_updated = now, so
 * "2 分钟前" alone reads as a fresh 2021 hack. When the gap is > 30 d say both: "首见 2021-05 · 更新 2 分钟前".
 */
export function eventTimeLabel(ev: Pick<EventSummary, 'first_seen' | 'last_updated'>, nowMs: number = Date.now()): { text: string; longRunning: boolean } {
  const first = Date.parse(ev.first_seen);
  const last = Date.parse(ev.last_updated);
  const updated = agoZh(ev.last_updated, nowMs);
  if (Number.isFinite(first) && Number.isFinite(last) && last - first > BACKFILL_GAP_MS) {
    return { text: `首见 ${ev.first_seen.slice(0, 7)} · 更新 ${updated}`, longRunning: true };
  }
  return { text: `更新 ${updated}`, longRunning: false };
}

const SIGNAL_STEPS: readonly Level[] = ['V0', 'V1', 'V2', 'V3', 'V4'];

/** 5-cell verification signal (replaces the mostly-empty 5-circle rail): V0 = 1 cell … V4 = 5; X = 0 + disputed. */
export function signalCells(level: Level): { filled: number; disputed: boolean } {
  if (level === 'X') return { filled: 0, disputed: true };
  return { filled: SIGNAL_STEPS.indexOf(level) + 1, disputed: false };
}

// ── L0 side stats ───────────────────────────────────────────────────────────────────────────────────────

/**
 * Web3 24h loss — same rule as the wall's "Web3 24h 损失" (WallPage, inline there; this is the tested copy):
 * web3 events whose first_seen is within 24 h, summing amount_usd_latest. Backfilled 2021 hacks are excluded
 * by construction (first_seen is the incident date). `count` lets the caller tell "$0 from 0 events" apart.
 */
export function web3Loss24h(events: EventSummary[], nowMs: number = Date.now()): { usd: number; count: number } {
  const cut = nowMs - DAY_MS;
  const hit = events.filter(e => e.domain === 'web3' && e.amount_usd_latest !== null && Date.parse(e.first_seen) >= cut);
  return { usd: hit.reduce((s, e) => s + (e.amount_usd_latest ?? 0), 0), count: hit.length };
}

/** "11/14 源正常" — denominator = enabled sources only (a disabled source is not a failure). null = unknown. */
export function sourceRatio(sources: SourceHealth[], loading: boolean): { ok: number; enabled: number } | null {
  if (loading) return null;
  const enabled = sources.filter(s => s.enabled);
  if (!enabled.length) return null;
  return { ok: enabled.filter(s => s.status === 'ok').length, enabled: enabled.length };
}

// ── URL state (UI-IA §1 rule 3: back from detail keeps the view) ───────────────────────────────────────

export type MonitorTab = 'all' | LifecycleKey;
const TABS: readonly MonitorTab[] = ['all', ...LIFECYCLE_ORDER, 'unknown'];

/**
 * URL query → home view state. Every value is checked against an allowlist: the query string is external
 * input (shared links, hand edits); an unknown value falls back to the default instead of reaching filters.
 */
export function parseHomeQuery(q: URLSearchParams): { filters: FilterState; tab: MonitorTab } {
  const pick = <T extends string>(key: string, allowed: readonly T[], dflt: T): T => {
    const v = q.get(key);
    return v !== null && (allowed as readonly string[]).includes(v) ? (v as T) : dflt;
  };
  const filters: FilterState = {
    domain: pick('domain', ['all', 'vuln', 'incident', 'web3'] as const, DEFAULT_FILTERS.domain),
    level: pick('level', ['all', 'V0', 'V1', 'V2', 'V3', 'V4', 'X'] as const, DEFAULT_FILTERS.level),
    severity: pick('sev', ['all', 'P0', 'P1', 'P2'] as const, DEFAULT_FILTERS.severity),
    exploitation: pick('exp', ['all', 'none', 'poc', 'reported', 'confirmed'] as const, DEFAULT_FILTERS.exploitation),
    stage: pick('stage', ['all', 'touched_24h', 'corroborated'] as const, DEFAULT_FILTERS.stage),
    search: (q.get('q') ?? '').slice(0, 200),
  };
  return { filters, tab: pick('tab', TABS, 'all') };
}

/** Inverse of parseHomeQuery; defaults are omitted so the bare #/ stays bare. */
export function toHomeQuery(filters: FilterState, tab: MonitorTab): URLSearchParams {
  const q = new URLSearchParams();
  const put = (k: string, v: string, d: string) => { if (v !== d) q.set(k, v); };
  put('tab', tab, 'all');
  put('domain', filters.domain, DEFAULT_FILTERS.domain);
  put('level', filters.level, DEFAULT_FILTERS.level);
  put('sev', filters.severity, DEFAULT_FILTERS.severity);
  put('exp', filters.exploitation, DEFAULT_FILTERS.exploitation);
  put('stage', filters.stage, DEFAULT_FILTERS.stage);
  put('q', filters.search, DEFAULT_FILTERS.search);
  return q;
}


/**
 * C5′ (replaces M2-PLAN A4 「多源率 ≥ 60%」, unreachable and the wrong proxy — measured 10-28: 25/125 = 20%, still 24%
 * without T1 first reports): a P0/P1 is *corroborated* when its code-computed level is ≥ V2 — a T1 authority (KEV /
 * vendor PSIRT ⇒ V3), ≥ 2 independent sources, or an attack tx confirmed on-chain (C6). The rest are single-source
 * high-severity events: the ones a human should look at first. One definition, computed from the published levels.
 */
export interface CorroborationView { high: number; corroborated: number; single: number; pct: number | null }
const CORROBORATED = new Set(['V2', 'V3', 'V4']);
export function corroborationView(events: { severity: string; level: string }[]): CorroborationView {
  const high = events.filter(e => e.severity === 'P0' || e.severity === 'P1');
  const ok = high.filter(e => CORROBORATED.has(e.level)).length;
  return { high: high.length, corroborated: ok, single: high.length - ok, pct: high.length ? Math.round((100 * ok) / high.length) : null };
}
