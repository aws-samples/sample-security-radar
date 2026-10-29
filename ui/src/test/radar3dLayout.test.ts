/**
 * Tests for radar3dLayout.ts pure functions.
 *
 * Contracts tested:
 *  1. polarToXZ matches SVG RadarScope coordinate convention exactly.
 *  2. pillarHeight clamps correctly.
 *  3. P0: only R > 1.0, luminance just over the bloom threshold; P1/P2 ≤ 1.0; on-screen colour = token.
 *  4. shapeBucket maps level to correct bucket index.
 *  5. diffNewEvents returns correct delta.
 *  6. radarDotsTo3D produces positions consistent with SVG layout
 *     (same angleDeg + radiusFrac → same XZ).
 */
import { describe, it, expect } from 'vitest';
import {
  polarToXZ,
  pillarHeight,
  severityColorHDR,
  shapeBucket,
  diffNewEvents,
  radarDotsTo3D,
  R_WORLD,
  P0_HDR,
  BLOOM_THRESHOLD,
  SEVERITY_TOKEN,
  bloomLuminance,
} from '@/utils/radar3dLayout';
import { computeRadarLayout } from '@/utils/radarLayout';
import type { EventSummary } from '@/types/site-data';

// ── Fixture ───────────────────────────────────────────────────────────────────
const NOW = new Date('2026-10-23T12:00:00Z').getTime();

function makeEvent(overrides: Partial<EventSummary> = {}): EventSummary {
  return {
    event_id:            'ev_test_0001',
    title:               'Test Event',
    domain:              'vuln',
    severity:            'P1',
    level:               'V2',
    first_seen:          new Date(NOW - 2 * 60 * 60 * 1000).toISOString(), // 2h ago
    last_updated:        new Date(NOW - 1 * 60 * 60 * 1000).toISOString(),
    sources_count:       3,
    status:              'active',
    cves:                [],
    entities:            [],
    chains:              [],
    amount_usd_latest:   null,
    amount_disputed:     false,
    ...overrides,
  };
}

// ── 1. polarToXZ ──────────────────────────────────────────────────────────────

describe('polarToXZ', () => {
  it('angle 0° (north) → x=0, z=-R', () => {
    const { x, z } = polarToXZ(0, 1);
    expect(x).toBeCloseTo(0, 5);
    expect(z).toBeCloseTo(-R_WORLD, 5);
  });

  it('angle 90° (east) → x=R, z=0', () => {
    const { x, z } = polarToXZ(90, 1);
    expect(x).toBeCloseTo(R_WORLD, 5);
    expect(z).toBeCloseTo(0, 5);
  });

  it('angle 180° (south) → x=0, z=+R', () => {
    const { x, z } = polarToXZ(180, 1);
    expect(x).toBeCloseTo(0, 5);
    expect(z).toBeCloseTo(R_WORLD, 5);
  });

  it('angle 270° (west) → x=-R, z=0', () => {
    const { x, z } = polarToXZ(270, 1);
    expect(x).toBeCloseTo(-R_WORLD, 5);
    expect(z).toBeCloseTo(0, 5);
  });

  it('radius 0 → origin', () => {
    const { x, z } = polarToXZ(45, 0);
    expect(x).toBeCloseTo(0, 5);
    expect(z).toBeCloseTo(0, 5);
  });

  it('radius 0.5 → half R_WORLD from origin', () => {
    const { x, z } = polarToXZ(0, 0.5);
    expect(Math.sqrt(x * x + z * z)).toBeCloseTo(R_WORLD * 0.5, 4);
  });
});

// ── 2. pillarHeight ───────────────────────────────────────────────────────────

describe('pillarHeight', () => {
  it('minimum (0 sources) = 0.25', () => {
    expect(pillarHeight(0)).toBeCloseTo(0.25);
  });

  it('grows with √sources', () => {
    const h1 = pillarHeight(1);
    const h4 = pillarHeight(4);
    const h9 = pillarHeight(9);
    // h = 0.25 + 0.35·√n
    expect(h1).toBeCloseTo(0.25 + 0.35 * 1, 4);
    expect(h4).toBeCloseTo(0.25 + 0.35 * 2, 4);
    expect(h9).toBeCloseTo(0.25 + 0.35 * 3, 4);
  });

  it('maximum caps at 2.0', () => {
    expect(pillarHeight(1000)).toBe(2.0);
    expect(pillarHeight(100)).toBe(2.0);
  });

  it('typical 3-source event stays between bounds', () => {
    const h = pillarHeight(3);
    expect(h).toBeGreaterThanOrEqual(0.25);
    expect(h).toBeLessThanOrEqual(2.0);
  });
});

// ── 3. severityColorHDR ───────────────────────────────────────────────────────

describe('severityColorHDR', () => {
  // B1 (spec 01 §6.3): the P0 bloom must be a red halo, not a white blob. Live check: restore the old
  // "all channels × 4" formula ⇒ the G/B and luminance-cap assertions go red.
  it('P0: only R exceeds 1.0 (G, B < 1 < R) — a channel above 1 on G/B is what bleached the halo white', () => {
    const [r, g, b] = severityColorHDR('P0');
    expect(r).toBeGreaterThan(1);
    expect(g).toBeLessThan(1);
    expect(b).toBeLessThan(1);
    expect(r).toBeCloseTo(P0_HDR, 3);
  });

  it('P0 luminance crosses BLOOM_THRESHOLD (it glows) but by ≤15% (bloom energy capped)', () => {
    const lum = bloomLuminance(severityColorHDR('P0'));
    expect(lum).toBeGreaterThan(BLOOM_THRESHOLD + 0.01); // + UnrealBloomPass smoothWidth
    expect(lum).toBeLessThanOrEqual(BLOOM_THRESHOLD * 1.15);
  });

  it('P1/P2 stay under BLOOM_THRESHOLD with margin (only P0 blooms)', () => {
    expect(bloomLuminance(severityColorHDR('P1'))).toBeLessThan(BLOOM_THRESHOLD * 0.8);
    expect(bloomLuminance(severityColorHDR('P2'))).toBeLessThan(BLOOM_THRESHOLD * 0.8);
  });

  it('P0 hue (HSV) within 10° of the #FF5C74 token (≈351°)', () => {
    const hue = ([r, g, b]: number[]) => {
      const mx = Math.max(r, g, b), mn = Math.min(r, g, b);
      const h = mx === r ? ((g - b) / (mx - mn)) * 60 : mx === g ? (2 + (b - r) / (mx - mn)) * 60 : (4 + (r - g) / (mx - mn)) * 60;
      return (h + 360) % 360;
    };
    const token = hue([0xFF, 0x5C, 0x74]);
    expect(token).toBeCloseTo(351.2, 0);
    const d = Math.abs(hue(severityColorHDR('P0')) - token);
    expect(Math.min(d, 360 - d)).toBeLessThanOrEqual(10);
  });

  it('on-screen (clamped, sRGB-encoded) pillar colour is exactly the design token for every severity', () => {
    const encode = (c: number) => {
      const x = Math.min(1, c);
      return Math.round(255 * (x <= 0.0031308 ? x * 12.92 : 1.055 * x ** (1 / 2.4) - 0.055));
    };
    for (const sev of ['P0', 'P1', 'P2'] as const) {
      const hex = SEVERITY_TOKEN[sev];
      const want = [(hex >> 16) & 0xff, (hex >> 8) & 0xff, hex & 0xff];
      expect(severityColorHDR(sev).map(encode), sev).toEqual(want);
    }
  });

  it('P1 all channels ≤ 1 (SDR, no bloom)', () => {
    const [r, g, b] = severityColorHDR('P1');
    expect(r).toBeLessThanOrEqual(1);
    expect(g).toBeLessThanOrEqual(1);
    expect(b).toBeLessThanOrEqual(1);
  });

  it('P2 all channels ≤ 1 (SDR, no bloom)', () => {
    const [r, g, b] = severityColorHDR('P2');
    expect(r).toBeLessThanOrEqual(1);
    expect(g).toBeLessThanOrEqual(1);
    expect(b).toBeLessThanOrEqual(1);
  });

  it('Unknown severity defaults to P2 colours', () => {
    // Should not throw
    const result = severityColorHDR('P9');
    expect(result).toHaveLength(3);
    expect(result[0]).toBeLessThanOrEqual(1);
  });
});

// ── 4. shapeBucket ────────────────────────────────────────────────────────────

describe('shapeBucket', () => {
  it('V0 → 0 (torus / hollow ring)', () => {
    expect(shapeBucket('V0')).toBe(0);
  });

  it('V1 → 1 (cylinder)', () => {
    expect(shapeBucket('V1')).toBe(1);
  });

  it('V2 → 1', () => {
    expect(shapeBucket('V2')).toBe(1);
  });

  it('V3 → 1', () => {
    expect(shapeBucket('V3')).toBe(1);
  });

  it('V4 → 2 (cylinder + cap)', () => {
    expect(shapeBucket('V4')).toBe(2);
  });

  it('X → 1 (default)', () => {
    expect(shapeBucket('X')).toBe(1);
  });
});

// ── 5. diffNewEvents ──────────────────────────────────────────────────────────

describe('diffNewEvents', () => {
  it('returns events in next but not in prev', () => {
    const prev = [{ event_id: 'a' }, { event_id: 'b' }];
    const next = [{ event_id: 'b' }, { event_id: 'c' }, { event_id: 'd' }];
    const result = diffNewEvents(prev, next);
    expect(result).toEqual(['c', 'd']);
  });

  it('empty prev → all next events are new', () => {
    const next = [{ event_id: 'x' }, { event_id: 'y' }];
    expect(diffNewEvents([], next)).toEqual(['x', 'y']);
  });

  it('identical sets → no new events', () => {
    const evs = [{ event_id: 'a' }, { event_id: 'b' }];
    expect(diffNewEvents(evs, evs)).toHaveLength(0);
  });

  it('empty next → no new events', () => {
    expect(diffNewEvents([{ event_id: 'a' }], [])).toHaveLength(0);
  });

  it('is pure / deterministic', () => {
    const prev = [{ event_id: 'a' }];
    const next = [{ event_id: 'a' }, { event_id: 'b' }];
    expect(diffNewEvents(prev, next)).toEqual(diffNewEvents(prev, next));
  });
});

// ── 6. SVG ↔ 3D position consistency ─────────────────────────────────────────

describe('radarDotsTo3D — SVG/3D position consistency', () => {
  const events: EventSummary[] = [
    makeEvent({ event_id: 'ev_v', domain: 'vuln',     severity: 'P0', level: 'V0' }),
    makeEvent({ event_id: 'ev_i', domain: 'incident', severity: 'P1', level: 'V2',
                first_seen: new Date(NOW - 30 * 60 * 60 * 1000).toISOString() }),
    makeEvent({ event_id: 'ev_w', domain: 'web3',     severity: 'P2', level: 'V4',
                first_seen: new Date(NOW - 100 * 60 * 60 * 1000).toISOString() }),
  ];

  const svgDots  = computeRadarLayout(events, NOW);
  const dots3d   = radarDotsTo3D(svgDots);

  it('same number of dots', () => {
    expect(dots3d.length).toBe(svgDots.length);
  });

  it('eventId preserved', () => {
    const ids3d = dots3d.map(d => d.eventId);
    const idsSvg = svgDots.map(d => d.eventId);
    expect(ids3d).toEqual(idsSvg);
  });

  it('SVG angle + radius → same XZ as polarToXZ(angleDeg, radiusFrac)', () => {
    for (let i = 0; i < svgDots.length; i++) {
      const svg = svgDots[i];
      const d3  = dots3d[i];
      const expected = polarToXZ(svg.angleDeg, svg.radiusFrac);
      expect(d3.x).toBeCloseTo(expected.x, 4);
      expect(d3.z).toBeCloseTo(expected.z, 4);
    }
  });

  it('all pillars have y = 0 (base on disk plane)', () => {
    dots3d.forEach(d => expect(d.y).toBe(0));
  });

  it('all heights within [0.25, 2.0]', () => {
    dots3d.forEach(d => {
      expect(d.height).toBeGreaterThanOrEqual(0.25);
      expect(d.height).toBeLessThanOrEqual(2.0);
    });
  });
});

// ── 7. quality.ts state machine ───────────────────────────────────────────────
// Imported separately to keep file focused.

import { initialQualityState, advanceQuality, tierSettings } from
  '@/components/wall3d/engine/quality';

describe('quality state machine', () => {
  const WINDOW = 50;
  const DT_GOOD = 1000 / 60;  // 60fps
  const DT_BAD  = 1000 / 20;  // 20fps — well below 55.5fps threshold

  it('starts at tier 0', () => {
    expect(initialQualityState().tier).toBe(0);
  });

  it('downgrades to T1 after 50 bad frames', () => {
    let state = initialQualityState();
    let now = 0;
    for (let i = 0; i < WINDOW; i++) {
      state = advanceQuality(state, DT_BAD, now += DT_BAD);
    }
    expect(state.tier).toBe(1);
  });

  it('stays at T0 on good fps', () => {
    let state = initialQualityState();
    let now = 0;
    for (let i = 0; i < WINDOW * 2; i++) {
      state = advanceQuality(state, DT_GOOD, now += DT_GOOD);
    }
    expect(state.tier).toBe(0);
  });

  it('T1 settings have bloom:true', () => {
    let state = initialQualityState();
    let now = 0;
    for (let i = 0; i < WINDOW; i++) {
      state = advanceQuality(state, DT_BAD, now += DT_BAD);
    }
    expect(tierSettings(state).bloom).toBe(true);
    expect(state.tier).toBe(1);
  });

  it('T2 settings have bloom:false', () => {
    let state = initialQualityState();
    let now = 0;
    // Two rounds of bad frames to reach T2
    for (let round = 0; round < 2; round++) {
      for (let i = 0; i < WINDOW; i++) {
        state = advanceQuality(state, DT_BAD, now += DT_BAD);
      }
    }
    expect(state.tier).toBeGreaterThanOrEqual(2);
    if (state.tier >= 2) {
      // T2 or beyond
      const TIER_2_SETTINGS = tierSettings({ ...state, tier: 2 });
      expect(TIER_2_SETTINGS.bloom).toBe(false);
    }
  });

  it('ignores frames with impossible dt', () => {
    let state = initialQualityState();
    const before = state.tier;
    state = advanceQuality(state, -100, 0);
    expect(state.tier).toBe(before);
    state = advanceQuality(state, 5000, 0);
    expect(state.tier).toBe(before);
  });
});

// ── 8. capability.ts parseRenderer ────────────────────────────────────────────

import { parseRenderer } from '@/components/wall3d/engine/capability';

describe('parseRenderer', () => {
  it('SwiftShader → software', () => {
    expect(parseRenderer('ANGLE (SwiftShader Device (Subzero) (0x0000C0DE))')).toBe('software');
  });

  it('llvmpipe → software', () => {
    expect(parseRenderer('llvmpipe (LLVM 12.0.0, 128 bits)')).toBe('software');
  });

  it('Apple M5 Max → gpu', () => {
    expect(parseRenderer('ANGLE Metal Renderer: Apple M5 Max')).toBe('gpu');
  });

  it('Intel UHD → gpu', () => {
    expect(parseRenderer('ANGLE (Intel, Intel(R) UHD Graphics 770 Direct3D11 vs_5_0 ps_5_0, D3D11)')).toBe('gpu');
  });

  it('NVIDIA → gpu', () => {
    expect(parseRenderer('ANGLE (NVIDIA GeForce RTX 4090 Direct3D11)')).toBe('gpu');
  });

  it('empty string → unknown', () => {
    expect(parseRenderer('')).toBe('unknown');
  });

  it('Microsoft Basic Render Driver → software', () => {
    expect(parseRenderer('Microsoft Basic Render Driver')).toBe('software');
  });
});
