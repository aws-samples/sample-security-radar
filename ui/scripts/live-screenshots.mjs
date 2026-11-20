// Live E2E screenshots behind Basic auth (real data). Credentials come from env U/P (set by
// ../scripts/live-shots.sh from Secrets Manager) — never from argv or this file.
import { chromium } from 'playwright';
const BASE = process.env.SITE_URL || (() => { throw new Error('set SITE_URL to your deployed site'); })();
const pages = [['home', '#/', '[data-testid="event-card"], article, .event-card'], ['detail', null, null],
  ['web3', '#/web3', 'article, .event-card, svg'], ['sources', '#/sources', 'table'], ['wall', '#/wall', 'svg'],
  ['continuum', '#/continuum', 'main'],
  // the two showcase responses: PHP2Shell (P0) and AlpsCon (Web3) — the "在你的环境中" section only, capped (2026-11-18:
  // a full-page shot had grown to 1920×20180 in the README)
  ['env-php2shell', '#/events/ev_9d36bf8dfb16f83c?section=env', 'main', false, 'section#env', { maxH: 1500, click: '#dt-tab-env' }],
  ['env-alpscon', '#/events/ev_7875c36932b3dc41?section=env', 'main', false, 'section#env', { maxH: 1500, click: '#dt-tab-env' }],
  // M4: an incident followed minute by minute — attack flow, on-chain reconstruction, loss / frozen kept apart
  // attack flow + 链上复盘 — the 29 attack-tx cards hidden (they are the Tranche shot's subject), capped
  ['incident-binance', '#/events/ev_0a4e5c3e0fce8be9', '.oc-table', false, 'section:has(#dt-h-flow)',
   { maxH: 1400, hide: '.oc-panel:has(.atx-card)' }],
  ['incident-binance-top', '#/events/ev_0a4e5c3e0fce8be9', '.dt-tabs'],
  // M4.1: a contract exploit — the attack-tx breakdown (Tranche Vault, $1.013M USDC to the sender)
  ['incident-tranche', '#/events/ev_455fc4965a8fa20b', '.atx-card', false, 'section:has(#dt-h-flow)'],
  // 2026-11-02: CVE published (CNA) vs radar first seen — CVE-2026-98432, published 10-15, first seen 10-29
  ['cve-disclosure', '#/events/ev_73cf1ec6a7cf368e', '[data-testid="disclosure"]', false, '[data-testid="verdict-panel"]'],
  ['ops', '#/ops', 'main']];
// An element shot of a page that scrolls inside <main> renders only what is on screen — the rest comes out black
// (live 2026-11-18: the Binance shot). Let the window scroll instead, hide what the shot is not about, cap the height.
async function shootPart(pg, part, path, { maxH = 0, hide = '', click = '' } = {}) {
  if (click) { await pg.locator(click).first().click().catch(() => {}); await pg.waitForTimeout(1000); }
  await pg.addStyleTag({ content: `html,body,#root,main{height:auto!important;max-height:none!important;overflow:visible!important}`
    + (hide ? `${hide}{display:none!important}` : '') });
  await pg.waitForTimeout(500);
  const el = pg.locator(part).first();
  await el.scrollIntoViewIfNeeded().catch(() => {});
  await pg.evaluate(() => window.scrollTo(0, 0));
  const box = await el.boundingBox();
  if (!box) return;
  const y = box.y + (await pg.evaluate(() => window.scrollY));
  const height = maxH ? Math.min(box.height, maxH) : box.height;
  await pg.screenshot({ path, fullPage: true, clip: { x: box.x, y, width: box.width, height } });
}
const b = await chromium.launch();
for (const theme of ['light', 'dark']) {
  const ctx = await b.newContext({ httpCredentials: { username: process.env.U, password: process.env.P },
    viewport: { width: 1920, height: 1080 }, colorScheme: theme });
  const pg = await ctx.newPage();
  for (const [name, hash, sel, full, part, opt = {}] of pages) {
    if (process.env.ONLY && !process.env.ONLY.split(',').includes(name)) continue;
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
    const path = `${process.env.OUT}/live-${name}-${theme}.png`;
    if (part) await shootPart(pg, part, path, opt);
    else await pg.screenshot({ path, fullPage: Boolean(full) });
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
