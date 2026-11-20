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
/** Camera target, pulled toward the viewer so the near rim and the floating core both fit the stage (at the origin
 * the near rim was cut off by the stage's bottom edge once the core went up to y = 1.5). */
export const LOOK_AT = { x: 0, y: 0.35, z: 0.9 } as const;

/** How far the reader may tilt by dragging (Neo 2026-11-19: 「围绕中轴线…像地球一样搓一下」): angle from the vertical axis,
 *  from nearly top-down to a low side view — never past the floor, never upside down. */
export const ELEV_MIN = 0.18;
export const ELEV_MAX = 1.15;

export function orbitPosition(azimuthDeg: number, elev: number = CAM_ELEV): { x: number; y: number; z: number } {
  const az = azimuthDeg * (Math.PI / 180);
  const e = Math.min(ELEV_MAX, Math.max(ELEV_MIN, elev));
  return {
    x: CAM_DIST * Math.sin(az) * Math.sin(e),
    y: CAM_DIST * Math.cos(e),
    z: CAM_DIST * Math.cos(az) * Math.sin(e),
  };
}

/** One pointer drag → the new view: dx turns about the vertical axis (full turns), dy tilts within the limits. */
export function dragView(view: { az: number; elev: number }, dx: number, dy: number): { az: number; elev: number } {
  return { az: (view.az - dx * 0.4) % 360, elev: Math.min(ELEV_MAX, Math.max(ELEV_MIN, view.elev - dy * 0.005)) };
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
