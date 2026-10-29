// Full-page dark screenshots of every radar page for the README gallery (real data, behind Basic auth).
// Credentials come from env U/P (scripts/gallery.sh reads them from Secrets Manager) — never from argv or this file.
import { chromium } from 'playwright';
const BASE = process.env.BASE;
const pages = [
  ['01-home', '#/', 'main'], ['02-wall', '#/wall', 'svg'], ['03-continuum', '#/continuum', 'main'],
  ['04-env-php2shell', '#/events/ev_bb65db3b8694e5f4?section=env', 'main'],
  ['05-env-alpscon', '#/events/ev_7875c36932b3dc41?section=env', 'main'],
  ['06-vulns', '#/vuln', 'main'], ['07-web3', '#/web3', 'main'], ['08-sources', '#/sources', 'table'],
];
const b = await chromium.launch();
const ctx = await b.newContext({ httpCredentials: { username: process.env.U, password: process.env.P },
  viewport: { width: 1440, height: 900 }, colorScheme: 'dark', deviceScaleFactor: 1 });
const pg = await ctx.newPage();
for (const [name, hash, sel] of pages) {
  await pg.goto(BASE + hash, { waitUntil: 'networkidle' });
  await pg.reload({ waitUntil: 'networkidle' });
  await pg.waitForSelector(sel, { timeout: 15000 }).catch(() => {});
  await pg.waitForTimeout(2500);
  if (name !== '02-wall') {
    // the app scrolls inside a container, not the document ⇒ unroll every scroll box so fullPage sees the content
    await pg.evaluate(() => {
      for (const el of document.querySelectorAll('*')) {
        const cs = getComputedStyle(el);
        if (/(auto|scroll)/.test(cs.overflowY) && el.scrollHeight > el.clientHeight + 40) {
          let n = el;
          while (n && n !== document.documentElement) {
            n.style.height = 'auto'; n.style.maxHeight = 'none'; n.style.overflow = 'visible'; n = n.parentElement;
          }
        }
      }
      document.documentElement.style.height = 'auto'; document.body.style.height = 'auto';
    });
    await pg.waitForTimeout(800);
  }
  await pg.screenshot({ path: `${process.env.OUT}/${name}.png`, fullPage: name !== '02-wall' });
}
await b.close();
