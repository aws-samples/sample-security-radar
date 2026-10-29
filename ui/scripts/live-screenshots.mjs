// Live E2E screenshots behind Basic auth (real data). Credentials come from env U/P (set by
// ../scripts/live-shots.sh from Secrets Manager) — never from argv or this file.
import { chromium } from 'playwright';
const BASE = process.env.SITE_URL || (() => { throw new Error('set SITE_URL to your deployed site'); })();
const pages = [['home', '#/', '[data-testid="event-card"], article, .event-card'], ['detail', null, null],
  ['web3', '#/web3', 'article, .event-card, svg'], ['sources', '#/sources', 'table'], ['wall', '#/wall', 'svg'],
  ['continuum', '#/continuum', 'main'],
  // the two showcase responses: PHP2Shell (P0) and AlpsCon (Web3) — "在你的环境中" section, full page
  ['env-php2shell', '#/events/ev_bb65db3b8694e5f4?section=env', 'main', true],
  ['env-alpscon', '#/events/ev_7875c36932b3dc41?section=env', 'main', true]];
const b = await chromium.launch();
for (const theme of ['light', 'dark']) {
  const ctx = await b.newContext({ httpCredentials: { username: process.env.U, password: process.env.P },
    viewport: { width: 1920, height: 1080 }, colorScheme: theme });
  const pg = await ctx.newPage();
  for (const [name, hash, sel, full] of pages) {
    if (name === 'detail') {
      await pg.goto(BASE + '#/', { waitUntil: 'networkidle' });
      const link = pg.locator('a[href*="event"]').first();
      if (!(await link.count())) continue;
      await link.click();
    } else {
      await pg.goto(BASE + hash, { waitUntil: 'networkidle' });
      await pg.reload({ waitUntil: 'networkidle' });
    }
    if (sel) await pg.waitForSelector(sel, { timeout: 15000 }).catch(() => {});
    await pg.waitForTimeout(1500);
    await pg.screenshot({ path: `${process.env.OUT}/live-${name}-${theme}.png`, fullPage: Boolean(full) });
  }
  await ctx.close();
}
{
  const ctx = await b.newContext({ httpCredentials: { username: process.env.U, password: process.env.P },
    viewport: { width: 1920, height: 1080 }, colorScheme: 'dark', reducedMotion: 'reduce' });
  const pg = await ctx.newPage();
  await pg.goto(BASE + '#/wall', { waitUntil: 'networkidle' }); await pg.reload({ waitUntil: 'networkidle' });
  await pg.waitForTimeout(2000);
  await pg.screenshot({ path: `${process.env.OUT}/live-wall-reduced-motion.png` });
  await ctx.close();
}
await b.close();
