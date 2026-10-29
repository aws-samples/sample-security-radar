/**
 * project.ts — world → CSS-pixel projection and the orbit camera pose, shared by the engine and its tests.
 *
 * B2 root cause (spec 01 §6.4): LeaderLabels built its own camera at (0, 8.5, 10.5) while the engine orbits at
 * CAM_DIST ≈ 14.2 ⇒ labels pointed at empty space and never followed the swing. Everything that needs a screen
 * position must now go through the engine's camera via projectToScreen(); orbitPosition() is the single pose
 * definition (the initial pose used to differ from the orbit pose, a one-frame jump).
 */
import { Vector3 } from 'three';
import type { Camera } from 'three';

export interface ScreenPoint {
  x: number;
  y: number;
  /** In front of the camera and inside the viewport. */
  visible: boolean;
}

/** Orbit radius and elevation: camera sits at (0, 11, 9) when the swing is centred. */
export const CAM_DIST = Math.sqrt(9 * 9 + 11 * 11); // ≈ 14.2
export const CAM_ELEV = Math.atan2(9, 11);

export function orbitPosition(azimuthDeg: number): { x: number; y: number; z: number } {
  const az = azimuthDeg * (Math.PI / 180);
  return {
    x: CAM_DIST * Math.sin(az) * Math.sin(CAM_ELEV),
    y: CAM_DIST * Math.cos(CAM_ELEV),
    z: CAM_DIST * Math.cos(az) * Math.sin(CAM_ELEV),
  };
}

const _v = new Vector3();

/** Project world points with `camera` into a w×h CSS-pixel viewport (origin top-left). */
export function projectToScreen(
  camera: Camera,
  points: ReadonlyArray<{ x: number; y: number; z: number }>,
  w: number,
  h: number,
): ScreenPoint[] {
  camera.updateMatrixWorld();
  return points.map(p => {
    _v.set(p.x, p.y, p.z).project(camera);
    const visible = _v.z > -1 && _v.z < 1 && Math.abs(_v.x) <= 1 && Math.abs(_v.y) <= 1;
    return { x: (_v.x * 0.5 + 0.5) * w, y: (-_v.y * 0.5 + 0.5) * h, visible };
  });
}
