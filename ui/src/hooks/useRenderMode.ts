/**
 * useRenderMode — determine whether to use the 3D WebGL scene or fall back to SVG.
 *
 * Runs capability detection once on mount.  Returns the render mode and a human-
 * readable reason string for the status bar (non-empty when degraded).
 *
 * ?force3d=1 is honoured **only** in import.meta.env.DEV builds; the param is
 * inert in production so it cannot be used to bypass checks on a deployed site.
 */
import { useState, useEffect } from 'react';
import { detect } from '@/components/wall3d/engine/capability';

export type RenderMode = 'webgl' | 'svg';

export interface RenderModeResult {
  mode: RenderMode;
  /** Non-empty string when in SVG fallback; suitable for status bar. */
  reason: string;
}

export function useRenderMode(): RenderModeResult {
  const [result, setResult] = useState<RenderModeResult>({
    mode: 'svg',  // safe default before detection runs
    reason: '',
  });

  useEffect(() => {
    // Hash-routed app: query params appear after the hash fragment (e.g. /#/wall?force3d=1)
    // so window.location.search is always empty — parse from hash instead.
    const hashQuery = window.location.hash.split('?')[1] ?? '';
    const params = new URLSearchParams(hashQuery);
    const forceEnabled =
      import.meta.env.DEV && params.get('force3d') === '1';

    const detected = detect(forceEnabled);

    if (detected.canRender3D) {
      setResult({ mode: 'webgl', reason: '' });
    } else {
      const labels: Record<string, string> = {
        'reduced-motion': '已降级为 2D（减少动效模式）',
        'no-webgl2':      '已降级为 2D（WebGL2 不可用）',
        'software':       '已降级为 2D（软件渲染器）',
        'gl-off':         '已降级为 2D（手动关闭）',
      };
      setResult({
        mode: 'svg',
        reason: labels[detected.reason] ?? '已降级为 2D',
      });
    }
  }, []);

  return result;
}
