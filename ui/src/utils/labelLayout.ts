/**
 * labelLayout.ts — NOW leader-label placement for the wall radar (2D SVG and 3D dome share it; spec 01 §6.4, B2).
 *
 * Pure and three-free on purpose: it lives in the main bundle (the 3D chunk gate counts three-* / WallScene3D-*
 * / wall3d* only) and is unit-tested in src/test/labelLayout.test.ts.
 *
 * Why it exists: the old LeaderLabels offset label i by a fixed `-i*18px` with no collision check, so the three
 * NOW labels stacked on top of each other (docs/screenshots/mock-wall-3d-before-b1b2-dark.png, 2026-10-23).
 */

export interface LabelAnchor {
  id: string;
  /** Anchor in viewport px (pillar top / dot centre). */
  x: number;
  y: number;
  /** false = not on the radar (older than 7 d, behind the camera, outside the viewport) ⇒ goes to the rail. */
  visible: boolean;
}

export interface LabelBox { w: number; h: number }
export interface Viewport { w: number; h: number }

export type PlacementMode =
  /** floating next to its anchor with a short leader line */
  | 'float'
  /** anchor on screen but no free spot around it ⇒ stacked at the viewport edge, leader drawn to the anchor */
  | 'rail'
  /** anchor not on the radar ⇒ stacked at the viewport edge, no leader (label says so) */
  | 'offscreen';

export interface LabelPlacement {
  id: string;
  mode: PlacementMode;
  /** Box top-left + size, viewport px. */
  x: number; y: number; w: number; h: number;
  /** Anchor point and the leader's end on the box edge (nearest point to the anchor). Equal for 'offscreen'. */
  ax: number; ay: number; lx: number; ly: number;
}

export const LAYOUT = {
  /** Minimum free space between two label boxes (px). */
  gap: 4,
  /** Labels never cover any anchor's 8 px circle — the thing being labelled must stay visible. */
  anchorClear: 8,
  /** Keep labels this far from the viewport edge. */
  pad: 6,
  /** Leader lengths tried in order: shortest readable leader first. */
  leaderLengths: [28, 56, 96] as const,
} as const;

interface Rect { x: number; y: number; w: number; h: number }

/** Axis-aligned rects overlap, with `gap` of required clearance. Exported for the test's mutation guard. */
export function rectsOverlap(a: Rect, b: Rect, gap = 0): boolean {
  return a.x < b.x + b.w + gap && b.x < a.x + a.w + gap && a.y < b.y + b.h + gap && b.y < a.y + a.h + gap;
}

function rectHitsCircle(r: Rect, cx: number, cy: number, rad: number): boolean {
  const nx = Math.max(r.x, Math.min(cx, r.x + r.w));
  const ny = Math.max(r.y, Math.min(cy, r.y + r.h));
  return (nx - cx) ** 2 + (ny - cy) ** 2 < rad * rad;
}

function insideViewport(r: Rect, vp: Viewport, pad: number): boolean {
  return r.x >= pad && r.y >= pad && r.x + r.w <= vp.w - pad && r.y + r.h <= vp.h - pad;
}

/** 8 directions in preference order (spec 01 §6.4): up-right, up-left, right, left, down-right, down-left, up, down. */
function candidate(dir: number, L: number, ax: number, ay: number, b: LabelBox): Rect {
  const d = L * 0.7; // diagonal offset per axis ≈ L / √2
  switch (dir) {
    case 0: return { x: ax + d, y: ay - d - b.h, ...b };
    case 1: return { x: ax - d - b.w, y: ay - d - b.h, ...b };
    case 2: return { x: ax + L, y: ay - b.h / 2, ...b };
    case 3: return { x: ax - L - b.w, y: ay - b.h / 2, ...b };
    case 4: return { x: ax + d, y: ay + d, ...b };
    case 5: return { x: ax - d - b.w, y: ay + d, ...b };
    case 6: return { x: ax - b.w / 2, y: ay - L - b.h, ...b };
    default: return { x: ax - b.w / 2, y: ay + L, ...b };
  }
}

/**
 * Place one label per anchor, in the given order (= NOW rank: rank 1 gets first pick of the free space).
 *
 * Guarantees (asserted by the unit test over 1000 random inputs): every returned box lies inside the viewport
 * (minus `pad`) and no two boxes intersect. Floating boxes also clear every anchor's 8 px circle.
 * Fallback order: float (24 candidates) → rail at the right edge, then the left edge, top to bottom.
 * An anchor that cannot be placed anywhere (viewport smaller than ~2 boxes) is omitted rather than overlapped —
 * the NOW board beside the radar always lists all three, so the label is a pointer, not the only copy.
 */
export function layoutLeaderLabels(anchors: readonly LabelAnchor[], box: LabelBox, vp: Viewport): LabelPlacement[] {
  const { gap, anchorClear, pad, leaderLengths } = LAYOUT;
  const placed: LabelPlacement[] = [];
  const onScreen = anchors.filter(a => a.visible);
  const free = (r: Rect, clearAnchors: boolean) =>
    insideViewport(r, vp, pad)
    && placed.every(p => !rectsOverlap(r, p, gap))
    && (!clearAnchors || onScreen.every(a => !rectHitsCircle(r, a.x, a.y, anchorClear)));

  const leaderEnd = (r: Rect, ax: number, ay: number) => ({
    lx: Math.max(r.x, Math.min(ax, r.x + r.w)),
    ly: Math.max(r.y, Math.min(ay, r.y + r.h)),
  });

  const railSpot = (): Rect | null => {
    const step = box.h + gap;
    for (const clear of [true, false]) {
      for (const x of [vp.w - pad - box.w, pad]) {
        for (let y = pad; y + box.h <= vp.h - pad; y += step) {
          const r = { x, y, ...box };
          if (free(r, clear)) return r;
        }
      }
    }
    return null;
  };

  for (const a of anchors) {
    let spot: Rect | null = null;
    if (a.visible) {
      search: for (const L of leaderLengths) {
        for (let dir = 0; dir < 8; dir++) {
          const r = candidate(dir, L, a.x, a.y, box);
          if (free(r, true)) { spot = r; break search; }
        }
      }
    }
    if (spot) {
      placed.push({ id: a.id, mode: 'float', ...spot, ax: a.x, ay: a.y, ...leaderEnd(spot, a.x, a.y) });
      continue;
    }
    const rail = railSpot();
    if (!rail) continue;
    if (a.visible) placed.push({ id: a.id, mode: 'rail', ...rail, ax: a.x, ay: a.y, ...leaderEnd(rail, a.x, a.y) });
    else placed.push({ id: a.id, mode: 'offscreen', ...rail, ax: rail.x, ay: rail.y, lx: rail.x, ly: rail.y });
  }
  return placed;
}
