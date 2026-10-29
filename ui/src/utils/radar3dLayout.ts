/**
 * radar3dLayout.ts — pure functions for the 3D radar scene.
 * Single source of truth for coordinate mapping shared with SVG RadarScope.
 *
 * Coordinate convention (three.js world units):
 *   - R_WORLD = 6 units = the outer ring radius
 *   - x = R · r · sin(θ)   where θ is the angle in radians from top (north), clockwise
 *   - z = −R · r · cos(θ)  (negative because three.js +z comes toward viewer)
 *   - y = 0 (disk plane); pillars grow upward along +y
 *
 * Same angle/radius semantics as radarLayout.ts so SVG and 3D render the same positions.
 */
import type { EventSummary } from '@/types/site-data';
import type { RadarDot } from '@/utils/radarLayout';

// ── Constants ─────────────────────────────────────────────────────────────────

/** World-space radius of the outer ring (R_MAX in SVG = 195px). */
export const R_WORLD = 6;

/**
 * UnrealBloomPass luminosity threshold — single source; createEngine.ts passes it to the pass.
 * The pass keeps a pixel when luminance(rgb) > threshold (three.js LuminosityHighPassShader, Rec.709 weights).
 */
export const BLOOM_THRESHOLD = 1.0;

/**
 * P0 red-channel lift (B1, spec 01 §6.3). Only R is pushed above 1.0; G/B stay at the token's linear value, so
 *  - the clamped on-screen body colour is exactly the design token #FF5C74 (not a white blob), and
 *  - luminance lands just above BLOOM_THRESHOLD (≈1.07), so the halo is red and its energy is capped.
 * History: was 4 on all three channels ⇒ (4.0, 1.44, 1.82), luminance ≈2.0 ⇒ every channel saturated through
 * the bloom and neighbouring P0 halos merged into a white column (docs/screenshots/mock-wall-3d-before-b1b2-dark.png).
 * Deviation from the spec's "×1.35": the high-pass tests luminance, not channels — R×1.35 never crosses 1.0.
 */
export const P0_HDR = 4.6;

/** Rec.709 luminance — the exact weights three.js' bloom high-pass uses to decide what glows. */
export function bloomLuminance([r, g, b]: readonly [number, number, number]): number {
  return 0.2126729 * r + 0.7151522 * g + 0.072175 * b;
}

/** sRGB-encoded channel (0–1) → linear. Instance colours are linear (three.js working colour space). */
export function srgbToLinear(c: number): number {
  return c <= 0.04045 ? c / 12.92 : ((c + 0.055) / 1.055) ** 2.4;
}

/** Severity design tokens (UI-BRIEF §3.1) — the same hexes as --p0 / --p1 / --p2. */
export const SEVERITY_TOKEN = { P0: 0xFF5C74, P1: 0xFFB547, P2: 0x5CC8F5 } as const;

function tokenLinear(hex: number): [number, number, number] {
  return [srgbToLinear(((hex >> 16) & 0xff) / 255), srgbToLinear(((hex >> 8) & 0xff) / 255), srgbToLinear((hex & 0xff) / 255)];
}

// ── Coordinate conversion ─────────────────────────────────────────────────────

/**
 * Convert polar radar coordinates (same origin as SVG) to three.js world XZ.
 *
 * @param angleDeg  - degrees from top (north), clockwise (matches radarLayout convention)
 * @param radiusFrac - 0 (center) … 1 (outer ring)
 * @param R         - world-space radius of the outer ring (default R_WORLD = 6)
 */
export function polarToXZ(
  angleDeg: number,
  radiusFrac: number,
  R: number = R_WORLD,
): { x: number; z: number } {
  const rad = angleDeg * (Math.PI / 180);
  return {
    x:  R * radiusFrac * Math.sin(rad),
    z: -R * radiusFrac * Math.cos(rad),
  };
}

// ── Pillar geometry ────────────────────────────────────────────────────────────

/**
 * Pillar height from independent_sources count.
 * h = clamp(0.25 + 0.35·√n, 0.25, 2.0)
 */
export function pillarHeight(sourcesCount: number): number {
  const h = 0.25 + 0.35 * Math.sqrt(Math.max(0, sourcesCount));
  return Math.min(2.0, Math.max(0.25, h));
}

// ── Severity / colour mapping ─────────────────────────────────────────────────

/**
 * Severity → linear RGB for the pillar instance colour; only P0's R channel exceeds 1.0.
 * P1/P2 are the plain tokens (luminance ≈0.55 / 0.50, well under BLOOM_THRESHOLD ⇒ they never bloom).
 * Previously the sRGB byte values were fed in as if linear, which washed every pillar out (P1 read pale yellow).
 */
export function severityColorHDR(severity: string): [number, number, number] {
  switch (severity) {
    case 'P0': {
      const [r, g, b] = tokenLinear(SEVERITY_TOKEN.P0);
      return [r * P0_HDR, g, b];
    }
    case 'P1': return tokenLinear(SEVERITY_TOKEN.P1);
    default:   return tokenLinear(SEVERITY_TOKEN.P2);
  }
}

// ── Shape bucket ──────────────────────────────────────────────────────────────

/**
 * Map verification level to shape bucket index (same scheme as SVG DotShape).
 *   0 = V0 → torus (hollow ring, like hollow-circle in SVG)
 *   1 = V1–V3 → cylinder
 *   2 = V4 → cylinder + octahedron cap (diamond in SVG)
 */
export function shapeBucket(level: string): 0 | 1 | 2 {
  if (level === 'V0') return 0;
  if (level === 'V4') return 2;
  return 1;
}

// ── Event diffing ─────────────────────────────────────────────────────────────

/**
 * Return event IDs that are in `next` but not in `prev`.
 * Used to identify newly arrived events for entry animations.
 * Pure function; always stable given the same sets.
 */
export function diffNewEvents(
  prev: ReadonlyArray<{ event_id: string }>,
  next: ReadonlyArray<{ event_id: string }>,
): string[] {
  const prevIds = new Set(prev.map(e => e.event_id));
  return next.map(e => e.event_id).filter(id => !prevIds.has(id));
}

// ── Layout snapshot for 3D scene ──────────────────────────────────────────────

export interface Dot3D {
  eventId:      string;
  x:            number;  // three.js world X
  z:            number;  // three.js world Z
  y:            number;  // base of pillar (always 0)
  height:       number;  // pillar height (world units)
  colorHDR:     [number, number, number];
  shape:        0 | 1 | 2;
  severity:     string;
  level:        string;
  domain:       string;
  title:        string;
  firstSeen:    string;
  sourcesCount: number;
}

/**
 * Convert a flat RadarDot array (from computeRadarLayout) into Dot3D positions.
 * This is the single authoritative conversion so SVG and 3D remain pixel-accurate.
 */
export function radarDotsTo3D(dots: RadarDot[]): Dot3D[] {
  return dots.map(dot => {
    const { x, z } = polarToXZ(dot.angleDeg, dot.radiusFrac);
    return {
      eventId:      dot.eventId,
      x,
      z,
      y:            0,
      height:       pillarHeight(dot.sourcesCount),
      colorHDR:     severityColorHDR(dot.severity),
      shape:        shapeBucket(dot.level),
      severity:     dot.severity,
      level:        dot.level,
      domain:       dot.domain,
      title:        dot.title,
      firstSeen:    dot.firstSeen,
      sourcesCount: dot.sourcesCount,
    };
  });
}

// ── Chain orbit layout ────────────────────────────────────────────────────────

export interface ChainOrbitNode {
  chain:     string;
  count:     number;
  angleDeg:  number; // placement angle along web3 outer arc (240–360°)
  r:         number; // world-space node radius ∝ √count
}

/**
 * Lay out chain nodes along the outer arc of the web3 sector (240–360°).
 * Returns a stable ordered list (descending count).
 */
export function chainOrbitLayout(
  events: ReadonlyArray<EventSummary>,
  maxNodes = 8,
): ChainOrbitNode[] {
  const counts: Record<string, number> = {};
  for (const ev of events) {
    if (ev.domain === 'web3') {
      for (const c of ev.chains) counts[c] = (counts[c] ?? 0) + 1;
    }
  }
  const sorted = Object.entries(counts)
    .sort((a, b) => b[1] - a[1])
    .slice(0, maxNodes);

  const WEB3_START = 240;
  const WEB3_SPAN  = 120;
  const margin     = WEB3_SPAN * 0.1;

  return sorted.map(([chain, count], i) => {
    const t = sorted.length === 1
      ? 0.5
      : i / (sorted.length - 1);
    const angleDeg = WEB3_START + margin + t * (WEB3_SPAN - margin * 2);
    const maxCount = sorted[0][1];
    const rNode    = 0.04 + 0.04 * Math.sqrt(count / maxCount);
    return { chain, count, angleDeg, r: rNode };
  });
}

// ── Bezier control point (for meteor entry arcs) ─────────────────────────────

/**
 * Mid-point control point for a quadratic Bézier arc between two world-space XZ points.
 * Arcs upward to give a "meteor entering the dome" feel.
 */
export function bezierControl(
  x0: number, z0: number,
  x1: number, z1: number,
  arcHeight = 3,
): { cx: number; cy: number; cz: number } {
  return {
    cx: (x0 + x1) / 2,
    cy: arcHeight,
    cz: (z0 + z1) / 2,
  };
}
