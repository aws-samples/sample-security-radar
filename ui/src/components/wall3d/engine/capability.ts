/**
 * capability.ts — WebGL2 capability detection (pure / side-effect-free logic).
 *
 * parseRenderer() is a pure function so it can be unit-tested without a DOM.
 * detect() performs the actual GL probe and must only be called in the browser.
 *
 * Fallback hierarchy (§3.7 of 08-webgl-wall-options.md):
 *  1. prefers-reduced-motion       → SVG
 *  2. webgl2 context fails or
 *     failIfMajorPerformanceCaveat → SVG
 *  3. renderer string matches
 *     software pattern             → SVG
 *  4. ?gl=off URL param            → SVG (manual override)
 *  5. ?force3d=1 in DEV builds     → skip checks (screenshot helper)
 */

export type RendererKind = 'gpu' | 'software' | 'unknown';

/**
 * Classify a WebGL renderer string.
 * Pure function — safe to test in Node.js without DOM.
 */
export function parseRenderer(rendererStr: string): RendererKind {
  if (!rendererStr) return 'unknown';
  const lower = rendererStr.toLowerCase();
  const softwarePattern = /swiftshader|llvmpipe|software|basic render|microsoft basic/i;
  if (softwarePattern.test(lower)) return 'software';
  // Known GPU vendors
  if (/apple|intel|amd|nvidia|qualcomm|arm mali|imaginations|angle/i.test(lower)) return 'gpu';
  return 'unknown';
}

export interface DetectResult {
  canRender3D: boolean;
  /** Why 3D was rejected, or empty string if allowed. */
  reason: 'reduced-motion' | 'no-webgl2' | 'software' | 'gl-off' | '';
  /** Raw renderer string (empty if not available). */
  rendererStr: string;
}

/**
 * Run all pre-flight checks and return whether 3D rendering should be used.
 * Call once on mount inside a browser context.
 *
 * @param forceEnabled - bypass all checks (only active in import.meta.env.DEV with ?force3d=1).
 */
export function detect(forceEnabled = false): DetectResult {
  if (forceEnabled) {
    return { canRender3D: true, reason: '', rendererStr: 'forced' };
  }

  // 1. prefers-reduced-motion
  if (typeof window !== 'undefined' &&
      window.matchMedia('(prefers-reduced-motion: reduce)').matches) {
    return { canRender3D: false, reason: 'reduced-motion', rendererStr: '' };
  }

  // 2. ?gl=off manual override
  // Hash-routed app: query params live after '#' (e.g. /#/wall?gl=off).
  if (typeof window !== 'undefined') {
    const hashQuery = window.location.hash.split('?')[1] ?? '';
    const params = new URLSearchParams(hashQuery || window.location.search);
    if (params.get('gl') === 'off') {
      return { canRender3D: false, reason: 'gl-off', rendererStr: '' };
    }
  }

  // 3. WebGL2 context + performance caveat check
  if (typeof document === 'undefined') {
    // SSR / non-browser — default safe
    return { canRender3D: false, reason: 'no-webgl2', rendererStr: '' };
  }

  const canvas = document.createElement('canvas');
  let rendererStr = '';

  const gl = canvas.getContext('webgl2', {
    failIfMajorPerformanceCaveat: true,
  }) as WebGL2RenderingContext | null;

  if (!gl) {
    return { canRender3D: false, reason: 'no-webgl2', rendererStr: '' };
  }

  // 4. Software renderer check
  try {
    const ext = gl.getExtension('WEBGL_debug_renderer_info');
    if (ext) {
      rendererStr = gl.getParameter(ext.UNMASKED_RENDERER_WEBGL) as string ?? '';
      if (parseRenderer(rendererStr) === 'software') {
        // Clean up before returning
        gl.getExtension('WEBGL_lose_context')?.loseContext();
        return { canRender3D: false, reason: 'software', rendererStr };
      }
    }
  } catch {
    // Extension unavailable — proceed; not a hard failure
  }

  // Clean up probe canvas
  try { gl.getExtension('WEBGL_lose_context')?.loseContext(); } catch { /* ignore */ }

  return { canRender3D: true, reason: '', rendererStr };
}
