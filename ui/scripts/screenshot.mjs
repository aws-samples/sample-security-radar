/**
 * screenshot.mjs — captures screenshots of all pages in both themes.
 * Waits for data to actually render before capturing.
 * Saves to docs/screenshots/mock-<page>-<theme>.png (B6 naming: mock-* = mock data, live-* = live site).
 * Optional filter: node scripts/screenshot.mjs detail detail-env   (only those page names)
 * Regular pages: 1440×900. Wall page: 1920×1080.
 *
 * Usage: node scripts/screenshot.mjs
 */

import { chromium } from 'playwright';
import { fileURLToPath } from 'url';
import { dirname, resolve } from 'path';
import { mkdirSync, existsSync } from 'fs';
import { CLOCK, DETAIL_ID, DETAIL_NO_ENV_ID } from './lib/mock-fixture.mjs';
import { startVite } from './lib/preview.mjs';

const __dirname = dirname(fileURLToPath(import.meta.url));
const uiDir = resolve(__dirname, '..');
const screenshotsDir = resolve(uiDir, '..', 'docs', 'screenshots');
const distDir = resolve(uiDir, 'dist');

if (!existsSync(distDir)) {
  console.error('ERROR: dist/ not found. Run `npm run build` before taking screenshots.');
  process.exit(1);
}

mkdirSync(screenshotsDir, { recursive: true });

const PORT = 4175;
const BASE = `http://127.0.0.1:${PORT}`;

const PAGES = [
  { name: 'home',    path: '/#/',       viewport: { width: 1440, height: 900 },  waitFor: '.now-card' },
  // whole reading chain L0 → L1 → L1' in one image (monitor rows grouped by lifecycle)
  { name: 'home-full', path: '/#/',     viewport: { width: 1440, height: 2100 }, waitFor: '.now-card' },
  { name: 'detail',  path: `/#/events/${DETAIL_ID}`, viewport: { width: 1440, height: 900 }, waitFor: '[data-testid="verdict-panel"]' },
  { name: 'detail-env', path: `/#/events/${DETAIL_ID}?section=env`, viewport: { width: 1440, height: 900 }, waitFor: '.diff-pre' },
  // whole reading order in one image (the app scrolls inside <main>, so playwright fullPage would only see 900px)
  { name: 'detail-full', path: `/#/events/${DETAIL_ID}?section=env`, viewport: { width: 1440, height: 5200 }, waitFor: '.diff-pre' },
  { name: 'detail-noenv', path: `/#/events/${DETAIL_NO_ENV_ID}`, viewport: { width: 1440, height: 900 }, waitFor: '[data-testid="verdict-panel"]' },
  { name: 'web3',    path: '/#/web3',   viewport: { width: 1440, height: 900 },  waitFor: 'article' },
  { name: 'vuln',    path: '/#/vuln',   viewport: { width: 1440, height: 900 },  waitFor: 'article' },
  { name: 'sources', path: '/#/sources', viewport: { width: 1440, height: 900 }, waitFor: 'table' },
  { name: 'continuum', path: '/#/continuum', viewport: { width: 1440, height: 900 }, waitFor: '[data-page="continuum"] .ring-pct' },
  // whole reading order L0 → capability flow → L1 targets → L2 recent → resources in one image
  { name: 'continuum-full', path: '/#/continuum', viewport: { width: 1440, height: 2000 }, waitFor: '[data-page="continuum"] .ring-pct' },
  { name: 'wall',    path: '/#/wall',   viewport: { width: 1920, height: 1080 }, waitFor: '[data-testid="wall-now-card"]' },
  // the 2D path (CI / software GL / reduced motion) with the NOW leader labels (B2); 3D shots: screenshot-3d.mjs
  { name: 'wall-2d', path: '/#/wall',   viewport: { width: 1920, height: 1080 }, waitFor: '[data-testid="now-labels"] .ll-label', storage: { 'sr-render-mode-override': 'svg' } },
  { name: 'wall-drawer', path: `/#/wall?event=${DETAIL_ID}`, viewport: { width: 1920, height: 1080 }, waitFor: '[data-testid="event-drawer"] .wd-env.tone-loss', storage: { 'sr-render-mode-override': 'svg' } },
];

const THEMES = ['light', 'dark'];
const ONLY = process.argv.slice(2);

async function waitForServer(retries = 20) {
  for (let i = 0; i < retries; i++) {
    try {
      // semgrep react-insecure-request: loopback preview server started by this script; TLS does not apply
      if ((await fetch(`${BASE}/`)).ok) return; // nosemgrep
    } catch { /* not ready yet */ }
    await new Promise(r => setTimeout(r, 500));
  }
  throw new Error('Server did not start');
}

async function run() {
  console.log('Starting vite preview for screenshots…');
  // lib/preview.mjs: occupied port fails fast; the preview dies with this process on throw / Ctrl-C (NEXT-STEPS B3)
  const { stop } = await startVite(['preview'], { cwd: uiDir, port: PORT });
  const captured = [];
  let browser;
  try {
    await waitForServer();
    console.log(`Preview on ${BASE}\n`);

    browser = await chromium.launch({ args: ['--no-sandbox'] });

    for (const theme of THEMES) {
      for (const pg of PAGES.filter(p => ONLY.length === 0 || ONLY.includes(p.name))) {
        const context = await browser.newContext({ viewport: pg.viewport });

        await context.addInitScript((t) => {
          localStorage.setItem('sr-theme', t);
          document.documentElement.dataset.theme = t;
        }, theme);
        if (pg.storage) {
          await context.addInitScript(kv => { for (const [k, v] of Object.entries(kv)) localStorage.setItem(k, v); }, pg.storage);
        }

        const page = await context.newPage();
        await page.clock.setFixedTime(CLOCK);
        await page.goto(`${BASE}${pg.path}`, { waitUntil: 'networkidle', timeout: 30_000 });

        // Wait for real content — not just the loading state
        if (pg.waitFor) {
          try {
            await page.waitForSelector(pg.waitFor, { timeout: 12_000, state: 'visible' });
          } catch {
            // A blank screenshot is not a screenshot: fail loudly instead of saving it as success.
            throw new Error(`${pg.name}-${theme}: content never rendered (${pg.waitFor})`);
          }
        }

        // Extra wait to let animations settle
        await page.waitForTimeout(600);

        const filename = resolve(screenshotsDir, `mock-${pg.name}-${theme}.png`);
        await page.screenshot({ path: filename, fullPage: false });
        console.log(`  ✓ mock-${pg.name}-${theme}.png  (${pg.viewport.width}×${pg.viewport.height})`);
        captured.push(filename);

        await context.close();
      }
    }

  } finally {
    await browser?.close();
    stop();
  }

  console.log(`\n${captured.length} screenshots saved to docs/screenshots/`);
}

run().catch(err => {
  console.error('screenshot failed:', err.message);
  process.exit(1);
});
