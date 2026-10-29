/**
 * WallCenterStage — layout slot and render-mode router for the wall center area.
 *
 * - If useRenderMode() returns 'webgl': lazily loads WallScene3D inside a Suspense
 *   boundary, with the SVG RadarScope as the loading fallback.
 * - If 'svg' (prefers-reduced-motion / no WebGL2 / software renderer / gl-off):
 *   renders the SVG RadarScope directly and shows a status tag.
 * - WallScene3D can call onFallback() at runtime (T4 FPS guardian) to force SVG.
 * - A manual 3D/2D toggle in the status bar overrides capability detection.
 *   Choice is persisted to localStorage key 'sr-render-mode-override'.
 */
import { Suspense, lazy, useState, useRef, useEffect, useCallback } from 'react';
import { useRenderMode } from '@/hooks/useRenderMode';
import type { Dot3D } from '@/utils/radar3dLayout';
import type { LeaderLabelItem } from '@/components/radar/LeaderLabels';

// Lazy import — Vite will split this into a separate chunk via manualChunks
const WallScene3D = lazy(() => import('./wall3d/WallScene3D'));

const LS_KEY = 'sr-render-mode-override';

export interface WallCenterStageProps {
  /** SVG fallback scene (always rendered while 3D loads or when WebGL unavailable). */
  svgScene: React.ReactNode;
  /** Pre-computed 3D dot data. */
  dots3d: Dot3D[];
  /** NOW leader labels for the 3D scene (the SVG scene brings its own, see ScopeWithLabels). */
  labels: LeaderLabelItem[];
  /** Called when user picks an event (both 3D and SVG call this). */
  onSelect: (eventId: string) => void;
  selectedEventId?: string | null;
}

export function WallCenterStage({
  svgScene,
  dots3d,
  labels,
  onSelect,
  selectedEventId,
}: WallCenterStageProps) {
  const { mode: detectedMode, reason: detectedReason } = useRenderMode();

  // Runtime fallback (T4 FPS guardian)
  const [runtimeFallback, setRuntimeFallback] = useState(false);
  const [fallbackReason, setFallbackReason]   = useState('');

  const handleFallback = (reason: string) => {
    setRuntimeFallback(true);
    setFallbackReason(reason);
  };

  // Manual toggle — reads from localStorage, overrides capability detection.
  // null = no override; 'webgl' | 'svg' = user choice.
  const [manualOverride, setManualOverride] = useState<'webgl' | 'svg' | null>(() => {
    try {
      const v = localStorage.getItem(LS_KEY);
      return v === 'webgl' || v === 'svg' ? v : null;
    } catch { return null; }
  });

  const toggleMode = useCallback(() => {
    const effectiveMode = manualOverride ?? detectedMode;
    // If WebGL is unavailable, don't allow toggling to 3D
    if (detectedMode === 'svg' && effectiveMode === 'svg' && !runtimeFallback) {
      return; // capability not available, toggle is disabled
    }
    const next = effectiveMode === 'webgl' ? 'svg' : 'webgl';
    setManualOverride(next);
    setRuntimeFallback(false); // reset FPS fallback when user forces 3D
    try { localStorage.setItem(LS_KEY, next); } catch {}
  }, [manualOverride, detectedMode, runtimeFallback]);

  const resolvedMode = manualOverride ?? (runtimeFallback ? 'svg' : detectedMode);
  const useWebGL = resolvedMode === 'webgl';

  // Reason shown in status tag
  let degradeReason = '';
  if (!useWebGL) {
    if (manualOverride === 'svg') degradeReason = '已降级为 2D（手动切换）';
    else if (runtimeFallback)     degradeReason = fallbackReason;
    else                          degradeReason = detectedReason;
  }

  // Measure container for 3D canvas sizing.
  // The container uses width:100% so the parent's flex layout provides the width.
  // If the first measurement reads 0 (layout not yet flushed), retry each rAF
  // until a non-zero size is available.
  const containerRef = useRef<HTMLDivElement>(null);
  const [size, setSize] = useState({ w: 800, h: 600 });

  useEffect(() => {
    const el = containerRef.current;
    if (!el) return;

    function applySize(w: number, h: number) {
      if (w > 1 && h > 1) {
        setSize({ w, h });
        return true;
      }
      return false;
    }

    const ro = new ResizeObserver(entries => {
      const r = entries[0].contentRect;
      applySize(Math.floor(r.width), Math.floor(r.height));
    });
    ro.observe(el);

    // Initial measurement — if layout hasn't flushed yet, retry each frame.
    // Capture a typed non-null alias so the closure doesn't re-narrow.
    const node: HTMLDivElement = el;
    let rafId: number;
    function tryMeasure() {
      if (!applySize(node.clientWidth, node.clientHeight)) {
        rafId = requestAnimationFrame(tryMeasure);
      }
    }
    tryMeasure();

    return () => {
      ro.disconnect();
      cancelAnimationFrame(rafId);
    };
  }, []);

  // data-render-mode / data-render-reason for Playwright and debugging
  const renderMode = useWebGL ? 'webgl' : 'svg';
  const renderReason = degradeReason;

  const canToggle = detectedMode === 'webgl' || manualOverride === 'svg';

  return (
    <div
      ref={containerRef}
      data-render-mode={renderMode}
      data-render-reason={renderReason || undefined}
      style={{
        flex: 1,
        // width:100% + minWidth:0 ensure this div fills the parent even when
        // the parent has alignItems:'center' (which would otherwise shrink to
        // intrinsic width — zero in WebGL mode where children are position:absolute).
        width: '100%',
        minWidth: 0,
        position: 'relative',
        minHeight: 0,
        overflow: 'hidden',
      }}
    >
      {useWebGL ? (
        <Suspense fallback={
          <div style={{ position: 'absolute', inset: 0 }}>{svgScene}</div>
        }>
          <WallScene3D
            dots={dots3d}
            labels={labels}
            selectedEventId={selectedEventId}
            onSelect={onSelect}
            onFallback={handleFallback}
            width={size.w}
            height={size.h}
          />
        </Suspense>
      ) : (
        <div style={{ position: 'absolute', inset: 0 }}>{svgScene}</div>
      )}

      {/* Radial vignette — fades the hard canvas edge to background */}
      <div
        aria-hidden="true"
        style={{
          position: 'absolute',
          inset: 0,
          pointerEvents: 'none',
          background: 'radial-gradient(ellipse 72% 72% at 50% 46%, transparent 62%, var(--bg-0) 100%)',
          zIndex: 2,
        }}
      />

      {/* Status tag + manual toggle */}
      <div
        style={{
          position: 'absolute',
          bottom: 6,
          left: '50%',
          transform: 'translateX(-50%)',
          display: 'flex',
          alignItems: 'center',
          gap: 6,
          zIndex: 10,
          pointerEvents: 'none',
        }}
      >
        {degradeReason && (
          <div
            role="status"
            aria-live="polite"
            style={{
              fontFamily: 'var(--font-mono)',
              fontSize: 9,
              color: 'var(--text-3)',
              background: 'var(--bg-1)',
              border: '1px solid var(--line)',
              borderRadius: 4,
              padding: '2px 8px',
              whiteSpace: 'nowrap',
            }}
          >
            {degradeReason}
          </div>
        )}
        {canToggle && (
          <button
            type="button"
            aria-label={useWebGL ? '切换到 2D 模式' : '切换到 3D 模式'}
            data-testid="render-mode-toggle"
            onClick={toggleMode}
            style={{
              pointerEvents: 'auto',
              fontFamily: 'var(--font-mono)',
              fontSize: 9,
              color: 'var(--text-3)',
              background: 'var(--bg-1)',
              border: '1px solid var(--line)',
              borderRadius: 4,
              padding: '2px 8px',
              cursor: 'pointer',
              whiteSpace: 'nowrap',
              opacity: 0.75,
            }}
          >
            {useWebGL ? '2D' : '3D'}
          </button>
        )}
      </div>
    </div>
  );
}
