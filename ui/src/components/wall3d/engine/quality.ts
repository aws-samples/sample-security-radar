/**
 * quality.ts — FPS-based quality tier state machine (pure functions).
 *
 * Tiers match §3.6 of 08-webgl-wall-options.md:
 *   T0 — DPR 1.5, bloom, 3000 stars, dome, camera orbit
 *   T1 — DPR 1.0
 *   T2 — no bloom (P0 keeps sprite), 1000 stars, no dome
 *   T3 — no camera orbit, scan at 30 fps
 *   T4 — fallback to SVG (caller's responsibility to swap)
 *
 * Hysteresis: downgrade at <55.5 fps (GitHub threshold), upgrade only after
 * 10 s at >58 fps AND only once (avoids oscillation).
 */

export type QualityTier = 0 | 1 | 2 | 3 | 4;

export interface QualityState {
  tier:            QualityTier;
  /** Rolling buffer of recent frame-time samples (ms) */
  samples:         number[];
  /** Timestamp (performance.now()) when we last upgraded tier */
  lastUpgradeAt:   number;
  /** Whether we have already upgraded once since the last downgrade */
  hasUpgraded:     boolean;
}

export interface QualitySettings {
  dpr:          number;   // devicePixelRatio cap
  bloom:        boolean;
  stars:        number;   // star count
  dome:         boolean;
  cameraOrbit:  boolean;
  scanFps:      30 | 60;
  fallback:     boolean;  // T4: switch to SVG
}

export const TIER_SETTINGS: Record<QualityTier, QualitySettings> = {
  0: { dpr: 1.5, bloom: true,  stars: 3000, dome: true,  cameraOrbit: true,  scanFps: 60, fallback: false },
  1: { dpr: 1.0, bloom: true,  stars: 3000, dome: true,  cameraOrbit: true,  scanFps: 60, fallback: false },
  2: { dpr: 1.0, bloom: false, stars: 1000, dome: false, cameraOrbit: true,  scanFps: 60, fallback: false },
  3: { dpr: 1.0, bloom: false, stars: 1000, dome: false, cameraOrbit: false, scanFps: 30, fallback: false },
  4: { dpr: 1.0, bloom: false, stars:    0, dome: false, cameraOrbit: false, scanFps: 30, fallback: true  },
};

const WINDOW_SIZE      = 50;   // rolling buffer length (frames)
const DOWN_THRESHOLD   = 55.5; // fps; downgrade if average below this
const UP_THRESHOLD     = 58.0; // fps; candidate for upgrade
const UP_SUSTAIN_MS    = 10_000; // must stay above UP_THRESHOLD for 10 s before upgrading

/** Create a fresh initial state. */
export function initialQualityState(): QualityState {
  return {
    tier:          0,
    samples:       [],
    lastUpgradeAt: 0,
    hasUpgraded:   false,
  };
}

/**
 * Record a new frame and return the updated state (immutable update).
 * @param state    - current state
 * @param dtMs     - frame delta time in milliseconds
 * @param nowMs    - current timestamp (performance.now())
 */
export function advanceQuality(
  state: QualityState,
  dtMs: number,
  nowMs: number,
): QualityState {
  if (dtMs <= 0 || dtMs > 2000) return state; // clamp bad samples

  const fps = 1000 / dtMs;

  // Keep rolling window
  const samples = [...state.samples, fps].slice(-WINDOW_SIZE);
  const avgFps  = samples.reduce((s, v) => s + v, 0) / samples.length;

  let { tier, lastUpgradeAt, hasUpgraded } = state;

  // Only evaluate once we have enough samples
  if (samples.length < WINDOW_SIZE) {
    return { ...state, samples };
  }

  if (avgFps < DOWN_THRESHOLD && tier < 4) {
    // Downgrade
    const newTier = (tier + 1) as QualityTier;
    return {
      tier:          newTier,
      samples:       [],          // reset window after tier change
      lastUpgradeAt: 0,
      hasUpgraded:   false,
    };
  }

  if (avgFps >= UP_THRESHOLD && tier > 0 && !hasUpgraded) {
    if (lastUpgradeAt === 0) {
      // Start timing sustained good performance
      return { ...state, samples, lastUpgradeAt: nowMs };
    }
    if (nowMs - lastUpgradeAt >= UP_SUSTAIN_MS) {
      // Upgrade one tier
      const newTier = (tier - 1) as QualityTier;
      return {
        tier:          newTier,
        samples:       [],
        lastUpgradeAt: 0,
        hasUpgraded:   true, // only one upgrade allowed per downgrade
      };
    }
  }

  // Reset timer if we dipped below UP_THRESHOLD again
  if (avgFps < UP_THRESHOLD && lastUpgradeAt !== 0) {
    return { ...state, samples, lastUpgradeAt: 0 };
  }

  return { ...state, samples };
}

/** Return the settings for the current tier. */
export function tierSettings(state: QualityState): QualitySettings {
  return TIER_SETTINGS[state.tier];
}

/** Human-readable reason for the current tier (for status bar display). */
export function tierReason(tier: QualityTier): string {
  switch (tier) {
    case 0: return '';
    case 1: return '已降低分辨率 (T1)';
    case 2: return '已关闭 bloom 和穹顶 (T2)';
    case 3: return '已关闭相机环绕 (T3)';
    case 4: return '已降级为 2D（FPS 不足）';
    default: return '';
  }
}
