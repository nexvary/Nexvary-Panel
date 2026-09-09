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
await page.locator('#dashboard.active-view').waitFor({ state: 'visible' });

if (await page.locator('link[href="/static/approved-theme.css"]').count() !== 1) throw new Error('Approved theme stylesheet missing');
if (await page.locator('.trust-center-card').count() !== 1) throw new Error('Trust Center card missing');
const scoreText = (await page.locator('.trust-score > strong').innerText()).replace(/\s/g, '');
const score = Number.parseInt(scoreText, 10);
if (!Number.isFinite(score) || score < 0 || score > 100) throw new Error(`Invalid trust score: ${scoreText}`);

const trustFixes = page.locator('.trust-checks .trust-check[data-open-view]');
if (await trustFixes.count() !== 7) throw new Error('Trust Center must expose seven guided fix/review paths');
const trustTargets = await trustFixes.evaluateAll(nodes => nodes.map(n => n.getAttribute('data-open-view')));
for (const target of trustTargets) {
  if (!target || await page.locator(`#${target}`).count() !== 1) throw new Error(`Trust fix path has no workspace target: ${target}`);
}
const firstTarget = await trustFixes.first().getAttribute('data-open-view');
await trustFixes.first().click();
await page.locator(`#${firstTarget}.active-view`).waitFor({ state:'visible' });
await page.locator('#nav a[href="#dashboard"]').click();
await page.locator('#dashboard.active-view').waitFor({ state:'visible' });

const nav = page.locator('#nav a[href="#sites"]');
const navStyle = await nav.evaluate(el => { const s = getComputedStyle(el); return { color:s.color, family:s.fontFamily, shadow:s.textShadow, border:s.borderWidth }; });
if (!navStyle.family.includes('Noto Kufi Arabic')) throw new Error(`Kufi font stack missing: ${navStyle.family}`);
if (navStyle.color !== 'rgb(55, 255, 154)') throw new Error(`Sidebar text is not electric green: ${navStyle.color}`);
if (!navStyle.shadow || navStyle.shadow === 'none') throw new Error('Sidebar electric glow missing');

const iconColors = await page.evaluate(() => {
  const refs=['dashboard','sites','databases','backups','fusion','integrations','dns','vault','files','deploy','wordpress','security','services','docker'];
  return refs.map(id => {
    const el=document.querySelector(`#nav a[href="#${id}"] .ui-icon`);
    return el ? getComputedStyle(el).color : null;
  }).filter(Boolean);
});
if (new Set(iconColors).size < 8) throw new Error(`Sidebar icon palette is not expressive enough: ${new Set(iconColors).size} colors`);
if (iconColors.every(c => c === 'rgb(55, 255, 154)')) throw new Error('Sidebar icons must not all be green');

const silver = await page.locator('.frame-silver').first().evaluate(el => getComputedStyle(el).borderColor);
const electricBlack = await page.locator('.frame-electric-black').first().evaluate(el => getComputedStyle(el).borderColor);
if (silver === electricBlack) throw new Error('Silver and electric-black internal frames are not visually distinct');

const shell = await page.locator('#dashboard.active-view').evaluate(el => { const s=getComputedStyle(el); return { width:parseFloat(s.borderTopWidth), color:s.borderTopColor, shadow:s.boxShadow }; });
if (shell.width < 1 || shell.color === 'rgba(0, 0, 0, 0)' || shell.shadow === 'none') throw new Error('Gold structural frame missing');

if (await page.evaluate(() => document.documentElement.scrollWidth > document.documentElement.clientWidth + 2)) throw new Error('Approved dashboard has horizontal overflow');
await page.screenshot({ path: `${out}/nexvary-panel-0.6-approved-dashboard-desktop.png`, fullPage: true });
await browser.close();
console.log('Nexvary Panel approved Royal Control Center UI Gate: PASS');
