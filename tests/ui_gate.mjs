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
  await page.locator('#pageTitle').filter({ hasText: 'لوحة القيادة' }).waitFor({ state: 'visible' });
}
async function assertNoOverflow(page,label){if(await page.evaluate(()=>document.documentElement.scrollWidth>document.documentElement.clientWidth+2))throw new Error(`${label} overflow`)}
async function openView(page,id){await page.locator(`#nav a[href="#${id}"]`).click();await page.locator(`#${id}.active-view`).waitFor({state:'visible'});const active=await page.locator('#workspaceStage > section.active-view').count();if(active!==1)throw new Error(`Expected exactly one active workspace, got ${active}`);}

const browser = await chromium.launch({ headless: true });
const failures = [];
const desktop = await browser.newPage({ viewport: { width: 1440, height: 1050 } });
desktop.on('pageerror', e => failures.push(`desktop: ${e.message}`));
await enterPanel(desktop);
for (const id of ['dashboard','sites','databases','backups','security','services','docker','users','audit']) if (await desktop.locator(`#${id}`).count() !== 1) throw new Error(`Missing workspace #${id}`);
if (await desktop.locator('.ui-icon').count() < 35) throw new Error('Original icon system missing or incomplete');
if (await desktop.locator('.metric-card').count() !== 4) throw new Error('Live telemetry cards missing');
if (await desktop.locator('.command-search').count() !== 1) throw new Error('Command search missing');
if (await desktop.locator('#workspaceStage > section.active-view').count() !== 1) throw new Error('Workspace isolation failed on load');
await assertNoOverflow(desktop,'Dashboard desktop');
await desktop.screenshot({ path: `${out}/nexvary-panel-0.4-dashboard-desktop.png`, fullPage: true });

await openView(desktop,'sites');
if(await desktop.locator('.application-grid').count()!==1||await desktop.locator('.creation-panel').count()<1)throw new Error('Sites workspace structure missing');
await assertNoOverflow(desktop,'Sites desktop');
await desktop.screenshot({ path: `${out}/nexvary-panel-0.4-sites-desktop.png`, fullPage: true });

await openView(desktop,'security');
if(await desktop.locator('.security-posture-grid .posture-card').count()!==4)throw new Error('Security posture cards missing');
await assertNoOverflow(desktop,'Security desktop');
await desktop.screenshot({ path: `${out}/nexvary-panel-0.4-security-desktop.png`, fullPage: true });

await openView(desktop,'services');
if(await desktop.locator('.doctor-command-center').count()!==1)throw new Error('Doctor command center missing');
await assertNoOverflow(desktop,'Services desktop');
await desktop.screenshot({ path: `${out}/nexvary-panel-0.4-services-desktop.png`, fullPage: true });

const mobile = await browser.newPage({ viewport: { width: 390, height: 844 } });
mobile.on('pageerror', e => failures.push(`mobile: ${e.message}`));
await enterPanel(mobile);
if (await mobile.locator('#sidebar.open').count() !== 0) throw new Error('Mobile drawer must start closed');
await assertNoOverflow(mobile,'Mobile dashboard');
await mobile.screenshot({ path: `${out}/nexvary-panel-0.4-mobile.png`, fullPage: true });
await mobile.locator('#mobileMenu').click();
await mobile.locator('#sidebar.open').waitFor({ state: 'visible' });
await mobile.waitForTimeout(300);
await mobile.screenshot({ path: `${out}/nexvary-panel-0.4-mobile-drawer.png`, fullPage: false });
await mobile.keyboard.press('Escape');
await mobile.waitForTimeout(250);
if(await mobile.locator('#sidebar.open').count())throw new Error('Escape did not close mobile drawer');
await browser.close();
if (failures.length) throw new Error(failures.join('\n'));
console.log('Nexvary Panel 0.4 Workspace UI Release Gate: PASS');
