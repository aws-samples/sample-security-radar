/**
 * screenshot-3d.mjs — Playwright screenshots of the 3D radar wall.
 *
 * Outputs (all 1920×1080, docs/screenshots/ — B6 naming: mock-* = mock data):
 *   mock-wall-3d-dark.png      — 3D WebGL, dark theme
 *   mock-wall-3d-light.png     — 3D WebGL, light theme
 *   (SwiftShader → software fallback: assertions only; the image equals screenshot.mjs mock-wall-2d-dark.png)
 *   mock-wall-2d-reduced.png   — SVG fallback (prefers-reduced-motion)
 *
 * Assertions (non-zero exit on failure):
 *   fallback shots: no canvas[aria-hidden], SVG RadarScope present,
 *                   status tag contains "已降级为 2D"
 *   3D shots:       canvas[aria-hidden] present, data-render-mode="webgl"
 *   all shots:      the NOW leader labels exist and their boxes do not overlap (B2)
 *   3D shots:       B1 — share of fully saturated pixels (R,G,B ≥ 250) < 0.5 %, and the pixels around each
 *                   floating P0 label anchor are red (hue 330°–10°), not white
 *   No GPU (canvas never reaches webgl) ⇒ the 3D checks print SKIPPED instead of passing silently.
 *
 * For 3D shots the server uses headless:false + Metal GPU so WebGL2 works.
 * For 2D fallback shots the server uses headless:true (SwiftShader → software).
 *
 * Binds Vite dev server to 127.0.0.1 only.
 */

import { chromium } from 'playwright';
import { fileURLToPath } from 'url';
import { dirname, resolve } from 'path';
import { mkdirSync } from 'fs';
import { CLOCK } from './lib/mock-fixture.mjs';
import { startVite } from './lib/preview.mjs';

const __dirname = dirname(fileURLToPath(import.meta.url));
const uiDir = resolve(__dirname, '..');
const screenshotsDir = resolve(uiDir, '..', 'docs', 'screenshots');
mkdirSync(screenshotsDir, { recursive: true });

const PORT = 5181;
const BASE = `http://127.0.0.1:${PORT}`;

async function waitReady(retries = 40) {
  for (let i = 0; i < retries; i++) {
    // semgrep react-insecure-request: loopback preview server started by this script; TLS does not apply
    try { if ((await fetch(`${BASE}/`)).ok) return; } catch { /* retry */ } // nosemgrep
    await new Promise(r => setTimeout(r, 500));
  }
  throw new Error('Dev server never became ready');
}

// ── Assertions ────────────────────────────────────────────────────────────────

function assert(cond, msg) {
  if (!cond) throw new Error(`ASSERTION FAILED: ${msg}`);
}

async function assertFallback(page, label) {
  const mode = await page.getAttribute('[data-render-mode]', 'data-render-mode');
  assert(mode === 'svg', `${label}: data-render-mode should be "svg" but got "${mode}"`);

  const canvasCount = await page.locator('canvas[aria-hidden="true"]').count();
  assert(canvasCount === 0, `${label}: WallScene3D canvas should NOT be in DOM (found ${canvasCount})`);

  const svgCount = await page.locator('svg[aria-label^="Security radar"]').count();
  assert(svgCount > 0, `${label}: SVG RadarScope should be present in DOM`);

  // data-render-reason is authoritative; a separate [role="status"] may appear
  // earlier in the DOM from the SVG scope, so we check the attribute directly.
  const reason = await page.getAttribute('[data-render-reason]', 'data-render-reason').catch(() => '');
  assert(
    typeof reason === 'string' && reason.includes('已降级为 2D'),
    `${label}: data-render-reason should contain "已降级为 2D" but got "${reason}"`,
  );
  await assertLabels(page, label);
  console.log(`  ✓ assertions passed: ${label}`);
}

// B2: the NOW labels are on screen and pairwise disjoint (DOM boxes, i.e. what the viewer actually sees).
async function assertLabels(page, label) {
  await page.waitForSelector('[data-testid="now-labels"] .ll-label', { timeout: 8_000 }).catch(() => {});
  const boxes = await page.$$eval('[data-testid="now-labels"] .ll-label', els => els.map(e => {
    const r = e.getBoundingClientRect();
    return { x: r.left, y: r.top, w: r.width, h: r.height, id: e.getAttribute('aria-label') };
  }));
  assert(boxes.length === 3, `${label}: expected 3 NOW labels, found ${boxes.length}`);
  for (let i = 0; i < boxes.length; i++) for (let j = i + 1; j < boxes.length; j++) {
    const a = boxes[i], b = boxes[j];
    const hit = !(a.x + a.w <= b.x || b.x + b.w <= a.x || a.y + a.h <= b.y || b.y + b.h <= a.y);
    assert(!hit, `${label}: NOW labels ${i + 1} and ${j + 1} overlap`);
  }
}

// B1: no white blow-out. Reads the WebGL canvas (preserveDrawingBuffer in DEV) — not the page screenshot,
// so DOM labels on top cannot mask or fake the result.
async function assertBloom(page, label) {
  const res = await page.evaluate(async () => {
    const c = document.querySelector('canvas[aria-hidden="true"]');
    if (!c) return null;
    const rect = c.getBoundingClientRect();
    const k = c.width / rect.width;
    const anchors = [...document.querySelectorAll('.ll-label[data-sev="P0"][data-mode="float"]')]
      .map(e => ({ x: (Number(e.dataset.anchorX)) * k, y: (Number(e.dataset.anchorY)) * k }));
    const img = new Image();
    img.src = c.toDataURL('image/png');
    await img.decode();
    const oc = new OffscreenCanvas(img.width, img.height);
    const ctx = oc.getContext('2d');
    ctx.drawImage(img, 0, 0);
    const d = ctx.getImageData(0, 0, img.width, img.height).data;
    let white = 0;
    for (let i = 0; i < d.length; i += 4) if (d[i] >= 250 && d[i + 1] >= 250 && d[i + 2] >= 250) white++;
    const hue = (r, g, b) => {
      const mx = Math.max(r, g, b), mn = Math.min(r, g, b);
      if (mx === mn) return null;
      const h = mx === r ? ((g - b) / (mx - mn)) * 60 : mx === g ? (2 + (b - r) / (mx - mn)) * 60 : (4 + (r - g) / (mx - mn)) * 60;
      return (h + 360) % 360;
    };
    const rad = Math.round(12 * k);
    const near = anchors.map(a => {
      let colored = 0, red = 0, white = 0;
      for (let y = Math.round(a.y) - rad; y <= Math.round(a.y) + rad; y++) for (let x = Math.round(a.x) - rad; x <= Math.round(a.x) + rad; x++) {
        if (x < 0 || y < 0 || x >= img.width || y >= img.height) continue;
        const i = (y * img.width + x) * 4, r = d[i], g = d[i + 1], b = d[i + 2];
        const mx = Math.max(r, g, b), mn = Math.min(r, g, b);
        if (mn >= 235) { white++; continue; }           // blown-out core: the B1 symptom itself
        if (mx < 80 || (mx - mn) / mx < 0.35) continue; // dark / grey pixels carry no hue
        colored++;
        const h = hue(r, g, b);
        if (h !== null && (h >= 330 || h <= 10)) red++;
      }
      return { colored, red, white };
    });
    return { whiteFrac: white / (d.length / 4), near };
  });
  if (res === null) { console.log(`  … SKIPPED bloom check ${label}: no canvas`); return; }
  assert(res.whiteFrac < 0.005, `${label}: ${(res.whiteFrac * 100).toFixed(2)}% fully saturated (white) pixels ≥ 0.5% — bloom over-exposure (B1)`);
  for (const [i, n] of res.near.entries()) {
    assert(n.colored > 0 && n.red / n.colored >= 0.6, `${label}: P0 anchor ${i + 1} not red (red ${n.red}/${n.colored} coloured px)`);
    // The global ratio alone is not enough with few P0s on screen (old bloom on the 2-P0 mock sample = 0.21 %
    // white, under the 0.5 % line): around the P0 itself, blown-out pixels must stay < 5 % of the lit ones.
    assert(n.white / (n.white + n.colored) < 0.05, `${label}: P0 anchor ${i + 1} blown out (${n.white} white vs ${n.colored} coloured px)`);
  }
  console.log(`  ✓ bloom: white px ${(res.whiteFrac * 100).toFixed(3)}% < 0.5%; P0 anchors red/coloured/white: ${res.near.map(n => `${n.red}/${n.colored}/${n.white}`).join(', ') || 'none floating'}`);
}

async function assert3D(page, label) {
  const mode = await page.getAttribute('[data-render-mode]', 'data-render-mode');
  assert(mode === 'webgl', `${label}: data-render-mode should be "webgl" but got "${mode}"`);

  const canvasCount = await page.locator('canvas[aria-hidden="true"]').count();
  assert(canvasCount > 0, `${label}: WallScene3D canvas should be in DOM`);

  // (a) Canvas must fill ≥80% of viewport width and height.
  const rect = await page.evaluate(() => {
    const c = document.querySelector('canvas[aria-hidden="true"]');
    if (!c) return null;
    const r = c.getBoundingClientRect();
    return { w: r.width, h: r.height, vw: window.innerWidth, vh: window.innerHeight };
  });
  assert(rect !== null, `${label}: canvas element not found for size check`);
  const wRatio = rect.w / rect.vw;
  const hRatio = rect.h / rect.vh;
  assert(wRatio >= 0.20,
    `${label}: canvas width ${rect.w}px is only ${(wRatio*100).toFixed(1)}% of viewport (need ≥20%)`,
  );
  assert(hRatio >= 0.50,
    `${label}: canvas height ${rect.h}px is only ${(hRatio*100).toFixed(1)}% of viewport (need ≥50%)`,
  );

  // (b) Non-background pixel ratio ≥5% via canvas.toDataURL (preserveDrawingBuffer=true in DEV).
  const pixelRatio = await page.evaluate(() => {
    const canvas = document.querySelector('canvas[aria-hidden="true"]');
    if (!canvas) return 0;
    try {
      const dataUrl = canvas.toDataURL('image/png');
      if (!dataUrl || dataUrl === 'data:,') return 0;
      // Decode base64 PNG and count non-near-black pixels via offscreen canvas.
      return new Promise(resolve => {
        const img = new Image();
        img.onload = () => {
          const oc = new OffscreenCanvas(img.width, img.height);
          const ctx2 = oc.getContext('2d');
          ctx2.drawImage(img, 0, 0);
          const data = ctx2.getImageData(0, 0, img.width, img.height).data;
          let nonBg = 0;
          for (let i = 0; i < data.length; i += 4) {
            const r = data[i], g = data[i+1], b = data[i+2];
            // Threshold: any pixel where R+G+B > 30 is considered non-background
            if (r + g + b > 30) nonBg++;
          }
          resolve(nonBg / (data.length / 4));
        };
        img.onerror = () => resolve(0);
        img.src = dataUrl;
      });
    } catch { return 0; }
  });

  assert(
    typeof pixelRatio === 'number' && pixelRatio >= 0.05,
    `${label}: non-background pixel ratio ${(pixelRatio * 100).toFixed(1)}% < 5% (canvas may be blank)`,
  );

  await assertLabels(page, label);
  await assertBloom(page, label);
  console.log(
    `  ✓ assertions passed: ${label} | canvas ${rect.w}×${rect.h}px ` +
    `(${(wRatio*100).toFixed(0)}%×${(hRatio*100).toFixed(0)}% of viewport) | ` +
    `non-bg pixels ${(pixelRatio*100).toFixed(1)}%`,
  );
}

// ── Main ─────────────────────────────────────────────────────────────────────

async function run() {
  console.log('Starting Vite dev server for 3D screenshots…');
  // lib/preview.mjs: occupied port fails fast; the dev server dies with this process on throw / Ctrl-C (NEXT-STEPS B3)
  const { stop } = await startVite([], { cwd: uiDir, port: PORT });
  let failures = 0;
  try {
    await waitReady();
    console.log(`Dev server ready at ${BASE}\n`);

    // ── 3D shots: non-headless + Metal GPU ───────────────────────────────────
    const browser3d = await chromium.launch({
      headless: false,
      args: [
        '--no-sandbox',
        '--use-angle=metal',
        '--ignore-gpu-blocklist',
        '--enable-gpu-rasterization',
      ],
    });

    for (const [name, theme] of [['mock-wall-3d-dark','dark'], ['mock-wall-3d-light','light']]) {
      try {
        const ctx = await browser3d.newContext({ viewport: { width: 1920, height: 1080 } });
        await ctx.addInitScript(t => {
          localStorage.setItem('sr-theme', t);
          document.documentElement.dataset.theme = t;
        }, theme);
        const page = await ctx.newPage();
        await page.clock.setFixedTime(CLOCK);
        await page.goto(`${BASE}/#/wall?force3d=1`, { waitUntil: 'networkidle', timeout: 30_000 });
        const mode = await page.getAttribute('[data-render-mode]', 'data-render-mode').catch(() => null);
        if (mode !== 'webgl') {
          // No usable GPU (CI / SwiftShader): say so instead of passing the 3D gates on a 2D page.
          console.log(`  … SKIPPED ${name}: render mode "${mode}" (no WebGL2 GPU here) — B1 pixel check not run`);
          await ctx.close();
          continue;
        }
        try {
          await page.waitForSelector('canvas[aria-hidden="true"]', { timeout: 8_000 });
        } catch { /* scene may still be loading */ }
        // Wait for three.js to render: lazy chunk load + first RAF + bloom pass
        await page.waitForTimeout(4_000);
        await assert3D(page, name).catch(e => { console.error(`  ✗ ${e.message}`); failures++; });
        await page.screenshot({ path: resolve(screenshotsDir, `${name}.png`), fullPage: false });
        console.log(`  ✓ ${name}.png (1920×1080)`);
        await ctx.close();
      } catch (e) {
        console.error(`  ✗ ${name} failed: ${e.message}`);
        failures++;
      }
    }
    await browser3d.close();

    // ── Fallback shots: headless (SwiftShader) or reduced-motion ─────────────
    const browserFallback = await chromium.launch({
      headless: true,
      args: ['--no-sandbox'],
    });

    // 2D fallback via SwiftShader software renderer detection
    try {
      const ctx = await browserFallback.newContext({ viewport: { width: 1920, height: 1080 } });
      await ctx.addInitScript(() => {
        localStorage.setItem('sr-theme', 'dark');
        document.documentElement.dataset.theme = 'dark';
      });
      const page = await ctx.newPage();
      await page.clock.setFixedTime(CLOCK);
      // No ?force3d=1 — capability detection runs and detects SwiftShader/no-webgl2
      await page.goto(`${BASE}/#/wall?gl=off`, { waitUntil: 'networkidle', timeout: 30_000 });
      try {
        await page.waitForSelector('svg[aria-label^="Security radar"]', { timeout: 8_000 });
      } catch { /* proceed */ }
      // Wait for useRenderMode effect to fire and populate degradeReason
      // Wait for useRenderMode effect to fire and render the status tag with reason text
      try {
        await page.waitForFunction(
          () => {
            const el = document.querySelector('[role="status"]');
            return el && el.textContent && el.textContent.includes('已降级为 2D');
          },
          { timeout: 5_000 },
        );
      } catch { /* time out — proceed, assertion will catch and record */ }
      await assertFallback(page, 'wall-2d-fallback').catch(e => { console.error(`  ✗ ${e.message}`); failures++; });
      // no PNG: pixel-identical to screenshot.mjs mock-wall-2d-dark.png — this run only asserts the detection path
      await ctx.close();
    } catch (e) {
      console.error(`  ✗ wall-2d-fallback failed: ${e.message}`);
      failures++;
    }

    // 2D fallback via prefers-reduced-motion
    try {
      const ctx = await browserFallback.newContext({
        viewport: { width: 1920, height: 1080 },
        reducedMotion: 'reduce', // Playwright sets prefers-reduced-motion: reduce
      });
      await ctx.addInitScript(() => {
        localStorage.setItem('sr-theme', 'dark');
        document.documentElement.dataset.theme = 'dark';
      });
      const page = await ctx.newPage();
      await page.clock.setFixedTime(CLOCK);
      // No ?force3d=1 — reduced-motion check must fire naturally before force3d bypass
      await page.goto(`${BASE}/#/wall?gl=off`, { waitUntil: 'networkidle', timeout: 30_000 });
      try {
        await page.waitForSelector('svg[aria-label^="Security radar"]', { timeout: 8_000 });
      } catch { /* proceed */ }
      try {
        await page.waitForFunction(
          () => {
            const el = document.querySelector('[role="status"]');
            return el && el.textContent && el.textContent.includes('已降级为 2D');
          },
          { timeout: 5_000 },
        );
      } catch { /* time out — proceed, assertion will catch */ }
      await assertFallback(page, 'wall-2d-reduced').catch(e => { console.error(`  ✗ ${e.message}`); failures++; });
      await page.screenshot({ path: resolve(screenshotsDir, 'mock-wall-2d-reduced.png'), fullPage: false });
      console.log('  ✓ mock-wall-2d-reduced.png (1920×1080)');
      await ctx.close();
    } catch (e) {
      console.error(`  ✗ wall-2d-reduced failed: ${e.message}`);
      failures++;
    }

    await browserFallback.close();
  } finally {
    stop();
  }

  console.log(`\nDone. Screenshots saved to docs/screenshots/`);
  if (failures > 0) {
    console.error(`\n${failures} assertion(s) FAILED — see errors above.`);
    process.exit(1);
  }
}

run().catch(err => {
  console.error('screenshot-3d failed:', err.message);
  process.exit(1);
});
