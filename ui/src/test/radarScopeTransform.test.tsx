/**
 * Live 2026-11-19 (Neo's screenshot): on #/wall the P0 halos drew as big faint circles far from their dots and the P0
 * crosshair jumped whenever the sweep passed. Cause: a CSS scale() on an SVG shape with the default transform-box
 * (view-box) scales about the canvas origin. Every animated shape must scale about itself.
 */
import { describe, it, expect } from 'vitest';
import { renderToStaticMarkup } from 'react-dom/server';
import { RadarScope } from '@/components/radar/RadarScope';
import type { RadarDot } from '@/utils/radarLayout';

const P0: RadarDot = { eventId: 'ev_0000000000000001', angleDeg: 150, radiusFrac: 0.6, shape: 'circle', severity: 'P0',
  level: 'V2', domain: 'incident', dotR: 6, title: 'A P0', firstSeen: '2026-11-19T00:00:00Z', sourcesCount: 2 };

describe('RadarScope animated shapes', () => {
  it('scale about their own centre (transform-box: fill-box), never the canvas origin', () => {
    const html = renderToStaticMarkup(<RadarScope points={[P0 as never]} onSelect={() => {}} />);
    // the four animated shapes of a P0 dot: 2 ping rings, the crosshair group, the ambient halo
    const tags = [...html.matchAll(/<(circle|g)\b[^>]*>/g)].map(m => m[0])
      .filter(t => /ping-ring|lockout-crosshair|p0-halo/.test(t));
    expect(tags.length).toBe(4);
    for (const t of tags) expect(t, t.slice(0, 90)).toMatch(/transform-box:fill-box;transform-origin:center/);
  });
});
