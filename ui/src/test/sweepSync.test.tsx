/**
 * Neo 2026-11-19: 「雷达扫描还没有扫到这些圈圈，它自己先不要做一些变化，否则看起来很奇怪。只有扫掉之后，它才会做一些变化」.
 * On the wall every circle is still until the sweep reaches it: no effect runs on its own clock.
 */
import { describe, it, expect } from 'vitest';
import { readFileSync } from 'fs';
import { resolve } from 'path';
import { renderToStaticMarkup } from 'react-dom/server';
import { RadarScope } from '@/components/radar/RadarScope';
import type { RadarDot } from '@/utils/radarLayout';

const ENGINE = readFileSync(resolve(__dirname, '../components/wall3d/engine/createEngine.ts'), 'utf8');
const SCOPE = readFileSync(resolve(__dirname, '../components/radar/RadarScope.tsx'), 'utf8');
const shader = (name: string) => ENGINE.split(`const ${name} = /* glsl */\``)[1].split('`;')[0];

const P0: RadarDot = { eventId: 'ev_0000000000000001', angleDeg: 150, radiusFrac: 0.6, shape: 'circle', severity: 'P0',
  level: 'V2', domain: 'incident', dotR: 6, title: 'A P0', firstSeen: '2026-11-19T00:00:00Z', sourcesCount: 2 };

describe('2D: a P0 halo moves only when the sweep passes', () => {
  it('rests without an animation and swells once under .radar-dot-pinging', () => {
    const html = renderToStaticMarkup(<RadarScope points={[P0 as never]} onSelect={() => {}} />);
    const halo = html.match(/<circle class="p0-halo"[^>]*>/)?.[0] ?? '';
    expect(halo).not.toBe('');
    expect(halo).not.toMatch(/animation/);
    expect(SCOPE).toMatch(/\.radar-dot-pinging \.p0-halo \{\s*animation: pulse-ring 900ms ease-out 1 !important;/);
    expect(SCOPE).not.toMatch(/infinite/);
  });
});

describe('3D: P0 effects follow the sweep, not their own clock', () => {
  it('the ground ring and the light shaft are timed by sinceSweep()', () => {
    for (const v of ['WAVE_VERT', 'SHAFT_VERT']) expect(shader(v), v).toMatch(/vSince = sinceSweep\(instanceMatrix \* vec4\(0\.0, 0\.0, 0\.0, 1\.0\)\);/);
    expect(shader('WAVE_FRAG')).toMatch(/float t = vSince \/ 1\.8;\s*if \(t >= 1\.0\) discard;/);
    expect(shader('WAVE_FRAG')).not.toMatch(/uTime \/ 2\.4/);
    expect(shader('SHAFT_FRAG')).not.toMatch(/sin\(uTime/);
    expect(ENGINE).toMatch(/fx\(WAVE_VERT, WAVE_FRAG, \{ uColor: \{ value: P0_LIN \}, uSweep: sweepU \}\)/);
    expect(ENGINE).toMatch(/fx\(SHAFT_VERT, SHAFT_FRAG, \{ uColor: \{ value: P0_LIN \}, uSweep: sweepU \}\)/);
  });

  it('no ring leaves the core on a timer', () => {
    expect(shader('SCAN_FRAG')).not.toMatch(/rippleA/);
  });
});
