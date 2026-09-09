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

for (const asset of ['/static/approved-theme.css','/static/reference-dashboard.css','/static/royal-ornaments.css','/static/security-intelligence.css']) {
  if (await page.locator(`link[href="${asset}"]`).count() !== 1) throw new Error(`Required approved stylesheet missing: ${asset}`);
}

const basmala = page.locator('.basmala-seal');
if (await basmala.count() !== 1) throw new Error('Royal Basmala seal missing');
const basmalaText = (await basmala.innerText()).replace(/\s+/g, ' ');
if (!basmalaText.includes('بِسْمِ اللهِ الرَّحْمٰنِ الرَّحِيمِ')) throw new Error(`Basmala copy missing: ${basmalaText}`);
const basmalaStyle = await basmala.evaluate(el => { const s=getComputedStyle(el); return {top:parseFloat(s.borderTopWidth),bottom:parseFloat(s.borderBottomWidth),shadow:s.boxShadow}; });
if (basmalaStyle.top < 1 || basmalaStyle.bottom < 1 || basmalaStyle.shadow === 'none') throw new Error('Basmala royal frame/glow missing');

if (await page.locator('.ref-hero').count() !== 1) throw new Error('Reference hero missing');
if (await page.locator('.ref-hero img[src*="nexvary-panel-primary.jpg"]').count() !== 1) throw new Error('Reference hero brand icon missing');
if (await page.locator('.ref-stat-grid .ref-stat').count() !== 6) throw new Error('Reference dashboard must render six summary cards');
if (await page.locator('.ref-mid-grid > .ref-panel').count() !== 3) throw new Error('Reference dashboard middle band must contain three panels');
if (await page.locator('.ref-bottom-grid > .ref-panel').count() !== 3) throw new Error('Reference dashboard bottom band must contain three panels');
if (await page.locator('.ref-resource.metric-card').count() !== 4) throw new Error('Live CPU/RAM/Disk/Uptime resource rows missing');
if (await page.locator('.ref-trust-ring').count() !== 1) throw new Error('Trust ring missing');
const score = Number.parseInt((await page.locator('.ref-trust-ring strong').innerText()).replace(/\D/g,''),10);
if (!Number.isFinite(score) || score < 0 || score > 100) throw new Error(`Invalid trust score: ${score}`);

const trustFixes = page.locator('.ref-trust-list .trust-check[data-open-view]');
if (await trustFixes.count() !== 7) throw new Error('Trust Center must expose seven guided paths');
for (const target of await trustFixes.evaluateAll(nodes => nodes.map(n => n.getAttribute('data-open-view')))) {
  if (!target || await page.locator(`#${target}`).count() !== 1) throw new Error(`Dead trust path: ${target}`);
}

const nav = page.locator('#nav a[href="#sites"]');
const navStyle = await nav.evaluate(el => { const s=getComputedStyle(el); return {color:s.color,family:s.fontFamily,shadow:s.textShadow}; });
if (!navStyle.family.includes('Noto Kufi Arabic')) throw new Error(`Kufi font stack missing: ${navStyle.family}`);
if (navStyle.color !== 'rgb(55, 255, 154)') throw new Error(`Sidebar text is not electric green: ${navStyle.color}`);
if (!navStyle.shadow || navStyle.shadow === 'none') throw new Error('Sidebar electric glow missing');

const expectedOrder=['dashboard','hosting','accounts','mail','transfers','sites','webtools','schedules','databases','files','security','backups'];
const firstLinks=await page.locator('#nav a').evaluateAll(nodes=>nodes.slice(0,12).map(n=>n.getAttribute('href')?.replace('#','')));
if (JSON.stringify(firstLinks)!==JSON.stringify(expectedOrder)) throw new Error(`Sidebar primary order mismatch: ${firstLinks.join(',')}`);
const iconColors=await page.evaluate(()=>Array.from(document.querySelectorAll('#nav a .ui-icon')).map(el=>getComputedStyle(el).color));
if(new Set(iconColors).size<8) throw new Error(`Sidebar icon palette too limited: ${new Set(iconColors).size}`);

if (await page.evaluate(() => document.documentElement.scrollWidth > document.documentElement.clientWidth + 2)) throw new Error('Reference dashboard has horizontal overflow');
await page.screenshot({ path: `${out}/nexvary-panel-0.7-approved-dashboard-desktop.png`, fullPage: true });

await page.locator('#nav a[href="#services"]').click();
await page.locator('#services.active-view').waitFor({ state:'visible' });
if (await page.locator('#services .security-intelligence').count() !== 1) throw new Error('Security Intelligence panel missing');
if (await page.locator('#services .defense-provider').count() !== 2) throw new Error('CrowdSec/Fail2Ban cards missing');
await page.screenshot({ path: `${out}/nexvary-panel-0.7-security-intelligence-desktop.png`, fullPage: true });

await browser.close();
console.log('Nexvary Panel 0.7 approved reference dashboard UI Gate: PASS');
