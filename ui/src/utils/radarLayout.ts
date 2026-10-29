/**
 * radarLayout.ts — pure functions for RadarScope geometry.
 * No React, no side effects: given the same events + now, returns the same layout.
 *
 * Coordinate convention: angles are degrees from top (0°), clockwise.
 * Radius fraction 0 = center (most recent), 1 = outer ring (7d old).
 */
import type { EventSummary } from '@/types/site-data';

// ── Constants ──────────────────────────────────────────────────────────────────

export const RADAR_MAX_AGE_MS = 7 * 24 * 60 * 60 * 1000; // 7 days
export const LOG_MAX = Math.log(7 * 24 + 1); // log(169) ≈ 5.128

/** The three 120° sectors. start/span in degrees (0 = top, clockwise). */
export const DOMAIN_SECTORS: Record<string, { start: number; span: number; label: string }> = {
  vuln:     { start: 0,   span: 120, label: 'VULN' },
  incident: { start: 120, span: 120, label: 'INCIDENT' },
  web3:     { start: 240, span: 120, label: 'WEB3' },
};

/** Distance rings: radius fraction for 1h / 24h / 7d labels. */
export const TIME_RINGS: { label: string; ageMsMax: number }[] = [
  { label: '1h',  ageMsMax: 1 * 60 * 60 * 1000 },
  { label: '24h', ageMsMax: 24 * 60 * 60 * 1000 },
  { label: '7d',  ageMsMax: 7 * 24 * 60 * 60 * 1000 },
];

// ── Pure math helpers ──────────────────────────────────────────────────────────

/** FNV-1a 32-bit hash → deterministic [0, 1). */
export function strHash(s: string): number {
  let h = 0x811c9dc5;
  for (let i = 0; i < s.length; i++) {
    h ^= s.charCodeAt(i);
    h = (h * 0x01000193) >>> 0;
  }
  return (h >>> 0) / 0xffffffff;
}

/**
 * Map event age to a radius fraction on a logarithmic scale.
 * - 0   → near center (most recent)
 * - 1   → outer ring (7 days old)
 * - null → event is older than 7d; should not appear on radar
 */
export function timeToRadiusFrac(firstSeen: string, now: number): number | null {
  const ageMs = now - new Date(firstSeen).getTime();
  if (ageMs > RADAR_MAX_AGE_MS) return null;
  const ageHours = Math.max(0, ageMs) / (60 * 60 * 1000);
  return Math.log(ageHours + 1) / LOG_MAX;
}

/**
 * Compute the radius fraction for the 1h / 24h / 7d ring labels.
 * Exported so tests and the component can share the same formula.
 */
export function ageMsToRadiusFrac(ageMs: number): number {
  const ageHours = Math.max(0, ageMs) / (60 * 60 * 1000);
  return Math.log(ageHours + 1) / LOG_MAX;
}

export type DotShape = 'hollow-circle' | 'circle' | 'diamond';

/** Map verification level to dot shape. */
export function levelToShape(level: string): DotShape {
  if (level === 'V0') return 'hollow-circle';
  if (level === 'V4') return 'diamond';
  return 'circle'; // V1, V2, V3, X
}

/**
 * Point radius in pixels: r = 3 + 2·√n, clamped to [3, 12].
 * n = independent source count.
 */
export function sourcesToDotR(n: number): number {
  const r = 3 + 2 * Math.sqrt(Math.max(0, n));
  return Math.min(12, Math.max(3, r));
}

// ── 2D scope geometry (RadarScope's SVG viewBox; single source so labels and dots agree) ───────────
export const SCOPE = { viewBox: 520, cx: 260, cy: 260, rMax: 195 } as const;

/** Polar radar position → px inside a RadarScope rendered at `size`×`size` (0° = top, clockwise). */
export function scopePointPx(angleDeg: number, radiusFrac: number, size: number): { x: number; y: number } {
  const k = size / SCOPE.viewBox;
  const rad = (angleDeg - 90) * (Math.PI / 180);
  const r = radiusFrac * SCOPE.rMax;
  return { x: (SCOPE.cx + r * Math.cos(rad)) * k, y: (SCOPE.cy + r * Math.sin(rad)) * k };
}

// ── Dot layout ────────────────────────────────────────────────────────────────

export interface RadarDot {
  eventId: string;
  angleDeg: number;   // 0° = top, clockwise
  radiusFrac: number; // 0–1 (never exactly 0; min ~0.01)
  shape: DotShape;
  severity: string;   // 'P0' | 'P1' | 'P2'
  level: string;      // 'V0'...'V4'|'X'
  domain: string;
  dotR: number;       // visual radius in px
  title: string;
  firstSeen: string;
  sourcesCount: number;
}

export interface RadarCluster {
  kind: 'cluster';
  angleDeg: number;
  radiusFrac: number;
  count: number;
  topSeverity: 'P0' | 'P1' | 'P2';
}

export type RadarItem = RadarDot | RadarCluster;

/** Maximum dots rendered before sampling (SVG default). Pass higher value for 3D scene. */
export const DEFAULT_MAX_DOTS = 150;

/**
 * Compute the full dot layout for a set of events.
 * Pure function: same events + now → same output.
 *
 * Rules:
 * - Events older than 7d are excluded.
 * - Radius = log-scale of age (0 = center = newest, 1 = 7d = outer).
 * - Angle = within domain sector, deterministically jittered by hash(event_id).
 * - Dot radius = f(independent_sources), capped at 12.
 * - Shape = f(level).
 *
 * @param maxDots - sampling ceiling. SVG passes 150 (default), 3D passes 2000.
 */
export function computeRadarLayout(
  events: EventSummary[],
  now: number = Date.now(),
  maxDots: number = DEFAULT_MAX_DOTS,
): RadarDot[] {
  // Priority-sample maxDots: P0 first, then P1, then P2
  const p0 = events.filter(e => e.severity === 'P0');
  const p1 = events.filter(e => e.severity === 'P1');
  const p2 = events.filter(e => e.severity === 'P2');
  const budgetP0 = Math.min(p0.length, Math.ceil(maxDots * 0.5));
  const budgetP1 = Math.min(p1.length, Math.ceil(maxDots * 0.35));
  const budgetP2 = Math.min(p2.length, maxDots - budgetP0 - budgetP1);
  const sampled = [...p0.slice(0, budgetP0), ...p1.slice(0, budgetP1), ...p2.slice(0, budgetP2)];

  const dots: RadarDot[] = [];

  for (const ev of sampled) {
    const sector = DOMAIN_SECTORS[ev.domain];
    if (!sector) continue;

    const radiusFrac = timeToRadiusFrac(ev.first_seen, now);
    if (radiusFrac === null) continue; // older than 7d → skip

    const h1 = strHash(ev.event_id);           // angular jitter seed
    const h2 = strHash(ev.event_id + '\x01r'); // radial jitter seed

    // Angular placement: within sector, 8% margin from edges
    const margin = sector.span * 0.08;
    const angleDeg = sector.start + margin + h1 * (sector.span - margin * 2);

    // Small radial jitter ±4%, clamped so dots never leave [0.01, 0.97]
    const jitter = (h2 - 0.5) * 0.08;
    const jitteredFrac = Math.min(0.97, Math.max(0.01, radiusFrac + jitter));

    // independent_sources may be absent on older mock data
    const sourcesCount: number = ((ev as unknown as Record<string, unknown>)['independent_sources'] as number) ?? 1;

    dots.push({
      eventId: ev.event_id,
      angleDeg,
      radiusFrac: jitteredFrac,
      shape: levelToShape(ev.level),
      severity: ev.severity,
      level: ev.level,
      domain: ev.domain,
      dotR: sourcesToDotR(sourcesCount),
      title: ev.title,
      firstSeen: ev.first_seen,
      sourcesCount,
    });
  }

  return dots;
}

/**
 * Cluster nearby dots to avoid visual overload.
 * If a group of dots is within `thresholdAngle`° AND `thresholdR` in radius,
 * and the group has more than `minCluster` members, merge them into a RadarCluster.
 *
 * Greedy O(n²) pass — acceptable for ≤150 dots.
 */
export function clusterDots(
  dots: RadarDot[],
  thresholdAngle = 5,   // degrees
  thresholdR = 0.05,    // fraction of R_MAX
  minCluster = 4,
): RadarItem[] {
  const used = new Set<number>();
  const result: RadarItem[] = [];

  for (let i = 0; i < dots.length; i++) {
    if (used.has(i)) continue;
    const a = dots[i];
    const members: RadarDot[] = [a];

    for (let j = i + 1; j < dots.length; j++) {
      if (used.has(j)) continue;
      const b = dots[j];
      const dAngle = Math.min(
        Math.abs(a.angleDeg - b.angleDeg),
        360 - Math.abs(a.angleDeg - b.angleDeg),
      );
      const dR = Math.abs(a.radiusFrac - b.radiusFrac);
      if (dAngle < thresholdAngle && dR < thresholdR) {
        members.push(b);
        used.add(j);
      }
    }

    used.add(i);

    if (members.length >= minCluster) {
      const topSev: 'P0' | 'P1' | 'P2' =
        members.some(d => d.severity === 'P0') ? 'P0'
          : members.some(d => d.severity === 'P1') ? 'P1' : 'P2';
      result.push({
        kind: 'cluster',
        angleDeg: a.angleDeg,
        radiusFrac: a.radiusFrac,
        count: members.length,
        topSeverity: topSev,
      } satisfies RadarCluster);
    } else {
      result.push(...members);
    }
  }

  return result;
}

// ── Hour bucket (block band) ──────────────────────────────────────────────────

export interface HourBucket {
  /** UTC "HH:00" */
  hourLabel: string;
  count: number;
  maxSeverity: 'P0' | 'P1' | 'P2' | null;
  confirmedCount: number; // V2, V3, V4
  pendingCount: number;   // V0, V1
}

/**
 * Bucket events into 24 one-hour slots ending at `now`.
 * Slot 0 = oldest (23h ago), slot 23 = most recent (<1h ago).
 * Pure function.
 */
export function computeHourBuckets(
  events: EventSummary[],
  now: number = Date.now(),
): HourBucket[] {
  const buckets: HourBucket[] = [];

  for (let i = 23; i >= 0; i--) {
    const slotEnd   = now - i * 60 * 60 * 1000;
    const slotStart = slotEnd - 60 * 60 * 1000;
    const d = new Date(slotEnd);
    const label = `${String(d.getUTCHours()).padStart(2, '0')}:00`;

    const inSlot = events.filter(ev => {
      const t = new Date(ev.first_seen).getTime();
      return t >= slotStart && t < slotEnd;
    });

    const maxSev: 'P0' | 'P1' | 'P2' | null =
      inSlot.some(e => e.severity === 'P0') ? 'P0'
        : inSlot.some(e => e.severity === 'P1') ? 'P1'
          : inSlot.length > 0 ? 'P2' : null;

    const confirmed = inSlot.filter(
      e => e.level === 'V2' || e.level === 'V3' || e.level === 'V4',
    ).length;

    buckets.push({
      hourLabel: label,
      count: inSlot.length,
      maxSeverity: maxSev,
      confirmedCount: confirmed,
      pendingCount: inSlot.length - confirmed,
    });
  }

  return buckets;
}
