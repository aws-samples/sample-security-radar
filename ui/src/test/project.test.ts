/**
 * B2 criterion (spec 01 §6.4): labels are projected with the engine's own orbit camera.
 * Live check: give projectToScreen a y flip error or the old fixed (0, 8.5, 10.5) pose ⇒ red.
 */
import { describe, it, expect } from 'vitest';
import { PerspectiveCamera } from 'three';
import { projectToScreen, orbitPosition, CAM_DIST } from '@/components/wall3d/engine/project';

function orbitCam(az: number, aspect = 16 / 9) {
  const cam = new PerspectiveCamera(46, aspect, 0.1, 100);
  const p = orbitPosition(az);
  cam.position.set(p.x, p.y, p.z);
  cam.lookAt(0, 0, 0);
  return cam;
}

describe('projectToScreen', () => {
  it('the point the camera looks at lands in the viewport centre ±1 px', () => {
    for (const az of [-12, 0, 7.5, 12]) {
      const [p] = projectToScreen(orbitCam(az), [{ x: 0, y: 0, z: 0 }], 1200, 800);
      expect(Math.abs(p.x - 600)).toBeLessThanOrEqual(1);
      expect(Math.abs(p.y - 400)).toBeLessThanOrEqual(1);
      expect(p.visible).toBe(true);
    }
  });

  it('screen y grows downward: a pillar top is above its base', () => {
    const [base, top] = projectToScreen(orbitCam(0), [{ x: 2, y: 0, z: 1 }, { x: 2, y: 2, z: 1 }], 1200, 800);
    expect(top.y).toBeLessThan(base.y);
  });

  it('the orbit pose differs from the old fixed label camera — a label projected with (0, 8.5, 10.5) misses', () => {
    const old = new PerspectiveCamera(46, 16 / 9, 0.1, 100);
    old.position.set(0, 8.5, 10.5);
    old.lookAt(0, 0, 0);
    const pt = [{ x: 4, y: 1, z: -3 }];
    const [a] = projectToScreen(orbitCam(0), pt, 1200, 800);
    const [b] = projectToScreen(old, pt, 1200, 800);
    expect(Math.hypot(a.x - b.x, a.y - b.y)).toBeGreaterThan(10);
  });

  it('orbitPosition keeps CAM_DIST and the centred pose is (0, 11, 9)', () => {
    const p = orbitPosition(0);
    expect(p.x).toBeCloseTo(0);
    expect(p.y).toBeCloseTo(11);
    expect(p.z).toBeCloseTo(9);
    const q = orbitPosition(12);
    expect(Math.hypot(q.x, q.y, q.z)).toBeLessThanOrEqual(CAM_DIST + 1e-9);
  });

  it('a point behind the camera is not visible', () => {
    const [p] = projectToScreen(orbitCam(0), [{ x: 0, y: 22, z: 18 }], 1200, 800);
    expect(p.visible).toBe(false);
  });
});
