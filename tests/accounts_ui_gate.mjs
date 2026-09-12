import { chromium } from 'playwright';
import fs from 'node:fs';

const base = process.env.NVP_BASE_URL || 'http://127.0.0.1:8000';
const password = process.env.NVP_TEST_PASSWORD;
if (!password) throw new Error('NVP_TEST_PASSWORD is required');
const out = process.env.NVP_SCREENSHOT_DIR || 'tests/artifacts';
fs.mkdirSync(out, { recursive: true });

const browser = await chromium.launch({ headless: true });
const page = await browser.newPage({ viewport: { width: 1600, height: 1050 } });
await page.goto(`${base}/login`, { waitUntil: 'networkidle' });
await page.locator('input[name="username"]').fill('admin');
await page.locator('input[name="password"]').fill(password);
await page.locator('button').filter({ hasText: 'دخول آمن' }).click();
await page.waitForURL(url => url.pathname === '/' || url.pathname === '', { timeout: 15000 });

if (await page.locator('link[href="/static/accounts.css"]').count() !== 1) throw new Error('Accounts stylesheet missing');
if (await page.locator('script[src="/static/accounts.js"]').count() !== 1) throw new Error('Accounts controller missing');
const nav = page.locator('#nav a[href="#accounts"]');
if (await nav.count() !== 1) throw new Error('Account & Reseller navigation missing');
await nav.click();
await page.locator('#accounts.active-view').waitFor({ state: 'visible' });

for (const id of ['hostingAccountForm','accountUsername','accountDomain','accountPackage','accountPassword','accountList','accountLimit','resellerForm','resellerList']) {
  if (await page.locator(`#${id}`).count() !== 1) throw new Error(`Account workspace control missing: ${id}`);
}
const hero = page.locator('#accounts .workspace-hero');
if (await hero.count() !== 1) throw new Error('Account workspace Royal hero missing');
if (!(await hero.innerText()).includes('الحسابات والموزعون')) throw new Error('Account workspace title missing');

const api = await page.evaluate(async () => {
  const a = await fetch('/api/accounts', { credentials:'same-origin' });
  const b = await fetch('/api/resellers', { credentials:'same-origin' });
  return { accountsStatus:a.status, accounts:await a.json(), resellersStatus:b.status, resellers:await b.json() };
});
if (api.accountsStatus !== 200 || api.accounts.ok !== true) throw new Error('Accounts API is not operational for admin');
if (!Array.isArray(api.accounts.packages) || api.accounts.packages.length < 2) throw new Error('Hosting packages not available in Account Manager');
if (api.resellersStatus !== 200 || api.resellers.ok !== true) throw new Error('Reseller API is not operational for admin');

if (await page.evaluate(() => document.documentElement.scrollWidth > document.documentElement.clientWidth + 2)) throw new Error('Account workspace has horizontal overflow');
await page.screenshot({ path: `${out}/nexvary-panel-0.7-accounts-resellers-desktop.png`, fullPage: true });

await page.setViewportSize({ width: 390, height: 844 });
await page.evaluate(() => { location.hash = '#accounts'; });
await page.waitForTimeout(250);
if (await page.evaluate(() => document.documentElement.scrollWidth > document.documentElement.clientWidth + 2)) throw new Error('Account workspace has mobile horizontal overflow');
await page.screenshot({ path: `${out}/nexvary-panel-0.7-accounts-resellers-mobile.png`, fullPage: false });

await browser.close();
console.log('Nexvary Panel Account & Reseller Chromium Gate: PASS');
