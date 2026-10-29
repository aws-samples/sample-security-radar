/**
 * a11y.mjs — accessibility audit using @axe-core/playwright.
 * Tests every entry of PAGES × 2 themes (15 × 2 = 30 today). Checks color-contrast and wcag2aa.
 * Clock and detail events are derived from mock-data (scripts/lib/mock-fixture.mjs).
 * Starts vite preview via lib/preview.mjs (requires dist/ — run `npm run build` first). An occupied port fails fast
 * instead of auditing a stray server, and the preview dies with this process on throw / Ctrl-C (NEXT-STEPS B3).
 * Exits with code 1 if any violations are found.
 *
 * Usage: node scripts/a11y.mjs
 */

import { chromium } from 'playwright';
import AxeBuilder from '@axe-core/playwright';
import { fileURLToPath } from 'url';
import { dirname, resolve } from 'path';
import { existsSync } from 'fs';
import { CLOCK, DETAIL_ID, DETAIL_NO_ENV_ID } from './lib/mock-fixture.mjs';
import { startVite } from './lib/preview.mjs';

const __dirname = dirname(fileURLToPath(import.meta.url));
const uiDir = resolve(__dirname, '..');
const distDir = resolve(uiDir, 'dist');

if (!existsSync(distDir)) {
  console.error('ERROR: dist/ not found. Run `npm run build` before `npm run a11y`.');
  process.exit(1);
}

const PORT = 4174;
const BASE = `http://127.0.0.1:${PORT}`;

// Pages to audit (hash routes — use #/ prefix)
const PAGES = [
  { name: 'home',    path: '/#/', expect: '.now-card' },
  // funnel drill-down applied + single lifecycle tab: pressed states, filter chip, ungrouped rows with impact chip
  { name: 'home-filtered', path: '/#/?tab=active&stage=corroborated', expect: '.row .impact-chip' },
  { name: 'detail',  path: `/#/events/${DETAIL_ID}`, expect: '[data-testid="verdict-panel"]' },
  // M3 缓解（快路） with the rule JSON fold open (copy button + pre under audit)
  { name: 'detail-mitigation', path: `/#/events/${DETAIL_ID}`, expect: '[data-testid="mitigation-panel"] .mt-plan', open: '[data-testid="mitigation-panel"] details' },
  // deep link into 在你的环境中 with the patch viewer open (diff lines, copy buttons, lanes all under audit)
  { name: 'detail-env', path: `/#/events/${DETAIL_ID}?section=env`, expect: '.diff-pre' },
  // response: null ⇒ the 未触发 explanation state
  { name: 'detail-noenv', path: `/#/events/${DETAIL_NO_ENV_ID}`, expect: '[data-testid="verdict-panel"]' },
  { name: 'web3',    path: '/#/web3'         },
  { name: 'vuln',    path: '/#/vuln'         },
  { name: 'sources', path: '/#/sources'      },
  // D/M3 ops view: error / warn / info rows (left-border level + text label, never colour alone)
  { name: 'ops',     path: '/#/ops', expect: '.ops-row' },
  // M3 mitigate station: note, web ACLs, DNS, Inspector baselines (state label + left-border tone), applied history
  { name: 'mitigate', path: '/#/mitigate', expect: '[data-page="mitigate"] .mt-plan' },
  // AWS Continuum 融入: coverage ring (SVG text under contrast audit), gap list, capability flow, targets, recent, resources
  { name: 'continuum', path: '/#/continuum', expect: '[data-page="continuum"] h1 ~ .ct-legend + .ct-gap, [data-page="continuum"] .ring-pct' },
  { name: 'wall',    path: '/#/wall'         },
  // the 2D SVG radar is what CI (software GL) and reduced-motion users get — test it everywhere,
  // not only where the machine happens to fall back (macOS headless gets a GPU ⇒ 3D ⇒ SVG untested)
  // + the 3 NOW leader labels (B2) must be on the 2D scope
  { name: 'wall-2d', path: '/#/wall', storage: { 'sr-render-mode-override': 'svg' }, expect: '[data-testid="now-labels"] .ll-label' },
  // L2 drawer opened from the URL (refresh-restorable): dialog, BLUF, impact chip, env line, links
  { name: 'wall-drawer', path: `/#/wall?event=${DETAIL_ID}`, storage: { 'sr-render-mode-override': 'svg' }, expect: '[data-testid="event-drawer"] .wd-env.tone-loss' },
];

const THEMES = ['light', 'dark'];

async function waitForServer(retries = 20) {
  for (let i = 0; i < retries; i++) {
    try {
      // semgrep react-insecure-request: loopback preview server started by this script; TLS does not apply
      const r = await fetch(`${BASE}/`); // nosemgrep
      if (r.ok) return;
    } catch { /* not ready yet */ }
    await new Promise(r => setTimeout(r, 500));
  }
  throw new Error('Server never became ready');
}

async function run() {
  console.log('Starting vite preview…');
  const { stop } = await startVite(['preview'], { cwd: uiDir, port: PORT });
  let totalViolations = 0;
  const report = [];
  let browser;
  try {
    await waitForServer();
    console.log(`Preview running on ${BASE} (clock ${CLOCK.toISOString()}, detail ${DETAIL_ID})\n`);

    browser = await chromium.launch({ args: ['--no-sandbox'] });

    for (const theme of THEMES) {
      for (const pg of PAGES) {
        const label = `[${theme}] ${pg.name}`;
        const context = await browser.newContext({ viewport: { width: 1440, height: 900 } });

        // Set theme before React mounts by pre-seeding localStorage
        await context.addInitScript((t) => {
          localStorage.setItem('sr-theme', t);
          document.documentElement.dataset.theme = t;
        }, theme);

        if (pg.storage) {
          await context.addInitScript(kv => { for (const [k, v] of Object.entries(kv)) localStorage.setItem(k, v); }, pg.storage);
        }
        const page = await context.newPage();
        // Freeze Date one pipeline tick after the mock's generated_at (lib/mock-fixture.mjs) so the audited state is one
        // that occurs live, and the radar's 7-day window (hence the interactive point set) never depends on run time.
        await page.clock.setFixedTime(CLOCK);
        const url = `${BASE}${pg.path}`;
        await page.goto(url, { waitUntil: 'networkidle', timeout: 30_000 });

        // Wait for content to render — look for at least one meaningful element
        try {
          if (pg.name === 'home' || pg.name === 'web3' || pg.name === 'vuln') {
            await page.waitForSelector('article, [role="feed"]', { timeout: 10_000 });
          } else if (pg.name === 'sources') {
            await page.waitForSelector('table, [aria-label="Source health table"]', { timeout: 10_000 });
          } else if (pg.expect) {
            await page.waitForSelector(pg.expect, { timeout: 10_000 });
            // `open`: unfold <details> so the folded content (e.g. rule JSON + copy button) is audited too
            if (pg.open) await page.$$eval(pg.open, els => { for (const el of els) el.open = true; });
          } else if (pg.name === 'wall') {
            // Wall may take a moment to render KPI tiles
            await page.waitForSelector('[role="region"], [aria-label]', { timeout: 10_000 });
          }
        } catch (waitErr) {
          console.log(`    wait error: ${String(waitErr).split("\n")[0]}`);
          // An empty page has zero violations — that is a false pass, not a pass.
          console.log(`  ✗ FAIL  ${label}: expected content never rendered`);
          totalViolations += 1;
          report.push({ label, violations: 1 });
          await context.close();
          continue;
        }

        const results = await new AxeBuilder({ page })
          .withTags(['wcag2a', 'wcag2aa', 'wcag21aa'])
          .analyze();

        const violations = results.violations;
        const count = violations.reduce((n, v) => n + v.nodes.length, 0);
        totalViolations += count;

        const status = count === 0 ? '✓ PASS' : `✗ FAIL (${count} node${count !== 1 ? 's' : ''})`;
        console.log(`  ${status}  ${label}`);

        if (violations.length > 0) {
          for (const v of violations) {
            console.log(`    ↳ [${v.impact}] ${v.id}: ${v.description}`);
            for (const node of v.nodes.slice(0, 2)) {
              console.log(`       ${node.target.join(', ')}`);
              if (node.failureSummary) {
                console.log(`       ${node.failureSummary.split('\n')[0]}`);
              }
            }
          }
        }

        report.push({ label, violations: count });
        await context.close();
      }
    }

    // Drawer keyboard contract (spec 01 §6.5 #2): open from a NOW card ⇒ dialog + ?event= in the URL;
    // Esc closes it and focus returns to the card that opened it. A broken focus return is an a11y failure.
    {
      const context = await browser.newContext({ viewport: { width: 1920, height: 1080 } });
      await context.addInitScript(() => localStorage.setItem('sr-render-mode-override', 'svg'));
      const page = await context.newPage();
      await page.clock.setFixedTime(CLOCK);
      let problem = null;
      try {
        await page.goto(`${BASE}/#/wall`, { waitUntil: 'networkidle', timeout: 30_000 });
        const card = page.locator('[data-testid="wall-now-card"]').nth(1);
        await card.focus();
        await page.keyboard.press('Enter');
        await page.waitForSelector('[role="dialog"][data-testid="event-drawer"]', { timeout: 5_000 });
        if (!page.url().includes('?event=')) problem = `URL lacks ?event= (${page.url()})`;
        await page.keyboard.press('Escape');
        await page.waitForSelector('[data-testid="event-drawer"]', { state: 'detached', timeout: 5_000 });
        const back = await page.evaluate(() => document.activeElement?.getAttribute('data-testid'));
        if (!problem && back !== 'wall-now-card') problem = `focus did not return to the NOW card (got ${back})`;
      } catch (e) { problem = String(e).split('\n')[0]; }
      console.log(problem ? `  ✗ FAIL  drawer keyboard: ${problem}` : '  ✓ PASS  drawer keyboard (open → ?event= → Esc → focus back)');
      report.push({ label: 'drawer-keyboard', violations: problem ? 1 : 0 });
      if (problem) totalViolations += 1;
      await context.close();
    }

  } finally {
    await browser?.close();
    stop();
  }

  console.log(`\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━`);
  const passed = report.filter(r => r.violations === 0).length;
  console.log(`Passed: ${passed}/${report.length}  Violations: ${totalViolations}`);

  if (totalViolations > 0) {
    console.log('\nFAIL — accessibility violations found. Fix before shipping.');
    process.exit(1);
  } else {
    console.log('\nPASS — zero violations across all pages and themes.');
    process.exit(0);
  }
}

run().catch(err => {
  console.error('a11y audit failed:', err.message);
  process.exit(1);
});
