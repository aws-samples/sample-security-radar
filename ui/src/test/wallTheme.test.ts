/**
 * R9.3 (Neo 2026-11-19, 「切换深色、浅色主题的时候，雷达中间这部分保持不变的颜色」): the wall's centre stage follows
 * the page theme. The 3D scene's effects are additive light on a near-black floor; in the light theme each one must
 * turn into ink (emit() + normal blending) or it disappears on the light floor. Structural: every light-emitting
 * fragment shader writes through emit(), and every effect material is registered for the blending swap.
 */
import { describe, it, expect } from 'vitest';
import { readFileSync } from 'fs';
import { resolve } from 'path';
import { STAGE_PALETTE } from '@/components/wall3d/engine/createEngine';

const ENGINE = readFileSync(resolve(__dirname, '../components/wall3d/engine/createEngine.ts'), 'utf8');
const STAGE = readFileSync(resolve(__dirname, '../components/WallCenterStage.tsx'), 'utf8');
const SCENE = readFileSync(resolve(__dirname, '../components/wall3d/WallScene3D.tsx'), 'utf8');

describe('wall stage theme', () => {
  it('the stage no longer forces the dark theme', () => {
    expect(STAGE).not.toMatch(/data-theme="dark"/);
  });

  it('the 3D scene is told the page theme on mount and on every switch', () => {
    expect(SCENE).toMatch(/useEffect\(\(\) => \{ engineRef\.current\?\.setTheme\(theme\); \}, \[theme\]\);/);
  });

  it('every effect fragment shader writes through emit() (light → ink in the light theme)', () => {
    for (const name of ['SCAN_FRAG', 'CURTAIN_FRAG', 'SHAFT_FRAG', 'WAVE_FRAG', 'LINK_FRAG']) {
      const body = ENGINE.split(`const ${name} = /* glsl */\``)[1].split('`;')[0];
      expect(body, name).toContain('${INK_GLSL}');
      expect(body, name).toMatch(/gl_FragColor = emit\(/);
      expect(body, name).not.toMatch(/gl_FragColor = vec4\(/);
    }
  });

  it('every additive material is registered for the theme switch', () => {
    const additive = (ENGINE.match(/blending: THREE\.AdditiveBlending/g) ?? []).length;
    // fx() registers its materials; the scan plane is registered by hand — both swap with setTheme
    expect(additive).toBe(2);
    expect(ENGINE).toMatch(/lightFx\.push\(m\)/);
    expect(ENGINE).toMatch(/lightFx\.push\(scanMat\)/);
  });

  it('the light palette is a light floor without bloom and stars; dark keeps the instrument look', () => {
    const lum = (hex: number) => ((hex >> 16) & 255) * 0.299 + ((hex >> 8) & 255) * 0.587 + (hex & 255) * 0.114;
    expect(lum(STAGE_PALETTE.light.background)).toBeGreaterThan(220);
    expect(lum(STAGE_PALETTE.dark.background)).toBeLessThan(20);
    expect(STAGE_PALETTE.light.bloom).toBe(false);
    expect(STAGE_PALETTE.light.stars).toBe(false);
    expect(STAGE_PALETTE.dark.bloom).toBe(true);
    // the core must stay readable on its floor (dark ink on light, light on dark)
    expect(lum(STAGE_PALETTE.light.core)).toBeLessThan(120);
    expect(lum(STAGE_PALETTE.dark.core)).toBeGreaterThan(150);
  });
});
