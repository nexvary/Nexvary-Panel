import { chromium } from 'playwright';
import fs from 'node:fs';

const base = process.env.NVP_BASE_URL || 'http://127.0.0.1:8000';
const password = process.env.NVP_TEST_PASSWORD;
if (!password) throw new Error('NVP_TEST_PASSWORD is required');
const out = process.env.NVP_SCREENSHOT_DIR || 'tests/artifacts';
fs.mkdirSync(out, { recursive: true });

async function enterPanel(page) {
  await page.goto(`${base}/login`, { waitUntil: 'networkidle' });
  await page.locator('input[name="username"]').fill('admin');
  await page.locator('input[name="password"]').fill(password);
  await page.locator('button').filter({ hasText: 'دخول آمن' }).click();
  await page.waitForURL(url => url.pathname === '/' || url.pathname === '', { timeout: 15000 });
  await page.locator('h1').filter({ hasText: 'لوحة القيادة' }).waitFor({ state: 'visible' });
}

const browser = await chromium.launch({ headless: true });
const failures = [];
const desktop = await browser.newPage({ viewport: { width: 1440, height: 1100 } });
desktop.on('pageerror', e => failures.push(`desktop: ${e.message}`));
await enterPanel(desktop);
for (const id of ['dashboard','sites','databases','backups','security','services','docker','users','audit']) {
  if (await desktop.locator(`#${id}`).count() !== 1) throw new Error(`Missing section #${id}`);
}
if (await desktop.locator('.ui-icon').count() < 20) throw new Error('Electric icon system missing or incomplete');
if (await desktop.locator('.metric-card').count() !== 4) throw new Error('Premium metric cards missing');
if (await desktop.locator('.command-search').count() !== 1) throw new Error('Command search missing');
if (await desktop.evaluate(() => document.documentElement.scrollWidth > document.documentElement.clientWidth + 2)) throw new Error('Desktop overflow');
await desktop.screenshot({ path: `${out}/nexvary-panel-electric-desktop.png`, fullPage: true });

const mobile = await browser.newPage({ viewport: { width: 390, height: 844 } });
mobile.on('pageerror', e => failures.push(`mobile: ${e.message}`));
await enterPanel(mobile);
if (await mobile.locator('#sidebar.open').count() !== 0) throw new Error('Mobile sidebar must start closed');
if (await mobile.evaluate(() => document.documentElement.scrollWidth > document.documentElement.clientWidth + 2)) throw new Error('Mobile overflow');
await mobile.screenshot({ path: `${out}/nexvary-panel-electric-mobile.png`, fullPage: true });
await mobile.locator('#mobileMenu').click();
await mobile.locator('#sidebar.open').waitFor({ state: 'visible' });
await mobile.screenshot({ path: `${out}/nexvary-panel-electric-mobile-drawer.png`, fullPage: false });
await mobile.keyboard.press('Escape');
await mobile.locator('#sidebar.open').waitFor({ state: 'detached' }).catch(async()=>{if(await mobile.locator('#sidebar.open').count())throw new Error('Escape did not close mobile drawer')});
await browser.close();
if (failures.length) throw new Error(failures.join('\n'));
console.log('Nexvary Panel Electric UI Release Gate: PASS');
