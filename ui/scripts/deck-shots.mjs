// Deck screenshots from MOCK data (deck v11, 2026-11-19): the local preview of dist/ on 127.0.0.1 (strict port, fails
// fast on a stray server), the fixture clock, dark theme. Never the live site — no credentials anywhere. The 2D
// scope is forced: headless Chrome without a GPU falls back to it anyway, and a shot must not depend on the machine.
//   npm run build && node scripts/deck-shots.mjs   → ../docs/screenshots/mock-deck-*.png
import { chromium } from 'playwright';
import { fileURLToPath } from 'url';
import { dirname, resolve } from 'path';
import { CLOCK } from './lib/mock-fixture.mjs';
import { startVite } from './lib/preview.mjs';

const uiDir = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const OUT = resolve(uiDir, '..', 'docs', 'screenshots');
const PORT = 4176;
const BASE = `http://127.0.0.1:${PORT}`;
const ATTACK = 'ev_bb65db3b8694e5f4';   // the mock event that carries an attack_path

const SHOTS = [
  // [name, hash, wait-for, viewport, storage, part]
  ['wall-2d', '/#/wall', '[data-testid="now-labels"] .ll-label', [1920, 1080], { 'sr-render-mode-override': 'svg' }],
  ['detail-attack', `/#/events/${ATTACK}`, '[data-testid="attack-path"]', [1600, 1000], {}, '[data-testid="attack-path"]'],
  ['phone-home', '/#/', '.now-card', [390, 844], {}],
];

const { stop } = await startVite(['preview'], { cwd: uiDir, port: PORT });
const browser = await chromium.launch();
let bad = 0;
try {
  for (const [name, hash, sel, [w, h], storage, part] of SHOTS) {
    const ctx = await browser.newContext({ viewport: { width: w, height: h }, colorScheme: 'dark', deviceScaleFactor: 2 });
    await ctx.addInitScript(kv => {
      localStorage.setItem('sr-theme', 'dark'); document.documentElement.dataset.theme = 'dark';
      for (const [k, v] of Object.entries(kv)) localStorage.setItem(k, v);
    }, storage);
    const pg = await ctx.newPage();
    await pg.clock.setFixedTime(CLOCK);
    await pg.goto(BASE + hash, { waitUntil: 'networkidle' });
    const ok = await pg.waitForSelector(sel, { timeout: 15000 }).then(() => true, () => false);
    if (!ok) { console.error(`FAIL ${name}: ${sel} never appeared`); bad++; await ctx.close(); continue; }
    await pg.waitForTimeout(2500);
    const path = resolve(OUT, `mock-deck-${name}.png`);
    if (part) await pg.locator(part).first().screenshot({ path });
    else await pg.screenshot({ path });
    console.log(`ok ${name} → ${path}`);
    await ctx.close();
  }
} finally {
  await browser.close();
  stop();
}
process.exit(bad ? 1 : 0);
