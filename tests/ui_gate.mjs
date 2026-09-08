import { chromium } from 'playwright';
import fs from 'node:fs';

const base = process.env.NVP_BASE_URL || 'http://127.0.0.1:8000';
const password = process.env.NVP_TEST_PASSWORD;
if (!password) throw new Error('NVP_TEST_PASSWORD is required');
const out = process.env.NVP_SCREENSHOT_DIR || 'tests/artifacts';
fs.mkdirSync(out, { recursive: true });

async function enterPanel(page) {
  await page.goto(`${base}/login`, { waitUntil: 'networkidle' });
  if (await page.locator('img[src*="nexvary-panel-primary.jpg"]').count() < 1) throw new Error('Approved Nexvary brand icon missing from login');
  await page.locator('input[name="username"]').fill('admin');
  await page.locator('input[name="password"]').fill(password);
  await page.locator('button').filter({ hasText: 'دخول آمن' }).click();
  await page.waitForURL(url => url.pathname === '/' || url.pathname === '', { timeout: 15000 });
  await page.locator('#pageTitle').filter({ hasText: 'لوحة القيادة' }).waitFor({ state: 'visible' });
}
async function assertNoOverflow(page,label){if(await page.evaluate(()=>document.documentElement.scrollWidth>document.documentElement.clientWidth+2))throw new Error(`${label} overflow`)}
async function openView(page,id){await page.locator(`#nav a[href="#${id}"]`).click();await page.locator(`#${id}.active-view`).waitFor({state:'visible'});const active=await page.locator('#workspaceStage > section.active-view').count();if(active!==1)throw new Error(`Expected exactly one active workspace, got ${active}`);await assertNoOverflow(page,`${id} desktop`)}
async function assertRoyalFrame(page, selector, label){const el=page.locator(selector).first();if(await el.count()!==1)throw new Error(`${label} target missing: ${selector}`);const style=await el.evaluate(node=>{const s=getComputedStyle(node);return {border:s.borderColor,borderStyle:s.borderStyle,shadow:s.boxShadow}});if(!style.border||style.borderStyle==='none'||style.border==='rgba(0, 0, 0, 0)')throw new Error(`${label} gold border missing`);if(!style.shadow||style.shadow==='none')throw new Error(`${label} luminous shadow missing`)}

const browser = await chromium.launch({ headless: true });
const failures = [];
const desktop = await browser.newPage({ viewport: { width: 1440, height: 1050 } });
desktop.on('pageerror', e => failures.push(`desktop: ${e.message}`));
await enterPanel(desktop);
const workspaces=['dashboard','sites','databases','backups','fusion','files','deploy','wordpress','security','services','docker','notifications','users','audit'];
for (const id of workspaces) if (await desktop.locator(`#${id}`).count() !== 1) throw new Error(`Missing workspace #${id}`);
if (await desktop.locator('.ui-icon').count() < 45) throw new Error('Original icon system missing or incomplete');
if (await desktop.locator('.metric-card').count() !== 4) throw new Error('Live telemetry cards missing');
if (await desktop.locator('.command-search').count() !== 1) throw new Error('Command search missing');
if (await desktop.locator('img[src*="nexvary-panel-primary.jpg"]').count() < 2) throw new Error('Approved Nexvary brand icon not integrated into shell/footer');
for(const asset of ['/static/platform-controls.css','/static/fusion.css'])if(await desktop.locator(`link[href="${asset}"]`).count()!==1)throw new Error(`Stylesheet missing: ${asset}`);
for(const asset of ['/static/platform-controls.js','/static/fusion.js'])if(await desktop.locator(`script[src="${asset}"]`).count()!==1)throw new Error(`Script missing: ${asset}`);
if (await desktop.locator('#healthDialog').count() !== 1 || await desktop.locator('#healthReport').count() !== 1 || await desktop.locator('#closeHealth').count() !== 1) throw new Error('Site Health Inspector shell missing');
if (await desktop.locator('#workspaceStage > section.active-view').count() !== 1) throw new Error('Workspace isolation failed on load');

await assertRoyalFrame(desktop,'.workspace-topbar','Header');
await assertRoyalFrame(desktop,'#nav a.active','Active navigation item');
await assertRoyalFrame(desktop,'#workspaceStage > section.active-view','Active workspace page');
await assertRoyalFrame(desktop,'.metric-card','Dashboard card');
await assertRoyalFrame(desktop,'#quickCreate','Primary action button');
await assertRoyalFrame(desktop,'.command-search','Command field');
await assertRoyalFrame(desktop,'#healthDialog','Site Health dialog');
await assertNoOverflow(desktop,'Dashboard desktop');
await desktop.screenshot({ path: `${out}/nexvary-panel-0.6-dashboard-desktop.png`, fullPage: true });

await openView(desktop,'sites');
if(await desktop.locator('#sites .application-grid').count()!==1||await desktop.locator('#sites .creation-panel').count()<1)throw new Error('Sites workspace structure missing');
await assertRoyalFrame(desktop,'#sites .creation-panel','Creation panel');
await assertRoyalFrame(desktop,'#sites .creation-panel input','Creation input');
await desktop.screenshot({ path: `${out}/nexvary-panel-0.6-sites-desktop.png`, fullPage: true });

await openView(desktop,'fusion');
await desktop.locator('.fusion-provider-card').first().waitFor({state:'visible',timeout:10000});
await desktop.locator('.fusion-capability-card').first().waitFor({state:'visible',timeout:10000});
if(await desktop.locator('.fusion-provider-card').count()<10)throw new Error('Fusion provider registry did not render expected providers');
if(await desktop.locator('.fusion-capability-card').count()!==6)throw new Error('Capability Matrix did not render six capability groups');
if(await desktop.locator('.fusion-policy-grid > div').count()!==4)throw new Error('Fusion policy controls missing');
if(!(await desktop.locator('#fusionCapabilities').textContent())?.includes('/'))throw new Error('Available capability summary missing');
await assertRoyalFrame(desktop,'.fusion-provider-card','Fusion provider card');
await assertRoyalFrame(desktop,'.fusion-capability-card','Fusion capability card');
await assertRoyalFrame(desktop,'.fusion-policy','Fusion policy panel');
await assertNoOverflow(desktop,'Fusion desktop');
await desktop.screenshot({ path: `${out}/nexvary-panel-0.6-fusion-desktop.png`, fullPage: true });

await openView(desktop,'files');
if(await desktop.locator('#fileBrowser').count()!==1||await desktop.locator('#fileContent').count()!==1||await desktop.locator('#fileSave').count()!==1||await desktop.locator('#fileNewFile').count()!==1)throw new Error('Safe File Manager controls missing');
await assertRoyalFrame(desktop,'#fileBrowser','File Manager browser');
await assertRoyalFrame(desktop,'#fileSave','File Manager save button');
await assertRoyalFrame(desktop,'#fileNewFile','File Manager new-file button');
await desktop.screenshot({ path: `${out}/nexvary-panel-0.6-files-desktop.png`, fullPage: true });

await openView(desktop,'deploy');
if(await desktop.locator('form[action="/git/deploy"]').count()!==1)throw new Error('Git Deploy form missing');
await assertRoyalFrame(desktop,'form[action="/git/deploy"] input','Git Deploy input');
await desktop.screenshot({ path: `${out}/nexvary-panel-0.6-deploy-desktop.png`, fullPage: true });

await openView(desktop,'wordpress');
if(await desktop.locator('form[action="/wordpress/prepare"]').count()!==1)throw new Error('WordPress Manager provisioning form missing');
await desktop.screenshot({ path: `${out}/nexvary-panel-0.6-wordpress-desktop.png`, fullPage: true });

await openView(desktop,'security');
if(await desktop.locator('.security-posture-grid .posture-card').count()!==4)throw new Error('Security posture cards missing');
if(await desktop.locator('form[action="/2fa/start"]').count()!==1)throw new Error('2FA enrollment control missing');
await assertRoyalFrame(desktop,'.security-posture-grid .posture-card','Security posture card');
await desktop.screenshot({ path: `${out}/nexvary-panel-0.6-security-desktop.png`, fullPage: true });

await openView(desktop,'services');
if(await desktop.locator('.doctor-command-center').count()!==1)throw new Error('Doctor command center missing');
await desktop.screenshot({ path: `${out}/nexvary-panel-0.6-services-desktop.png`, fullPage: true });

await openView(desktop,'notifications');
if(await desktop.locator('.notification-list').count()!==1)throw new Error('Notification Center missing');
if(await desktop.locator('.notification-filter').count()!==3)throw new Error('Notification filters missing');
await assertRoyalFrame(desktop,'.notification-filter','Notification filter button');
await desktop.locator('.notification-filter[data-notification-filter="critical"]').click();
if(await desktop.locator('.notification-filter.active[data-notification-filter="critical"]').count()!==1)throw new Error('Critical notification filter does not activate');
await desktop.locator('.notification-filter[data-notification-filter="all"]').click();
await desktop.screenshot({ path: `${out}/nexvary-panel-0.6-notifications-desktop.png`, fullPage: true });

const mobile = await browser.newPage({ viewport: { width: 390, height: 844 } });
mobile.on('pageerror', e => failures.push(`mobile: ${e.message}`));
await enterPanel(mobile);
if (await mobile.locator('#sidebar.open').count() !== 0) throw new Error('Mobile drawer must start closed');
await assertRoyalFrame(mobile,'#workspaceStage > section.active-view','Mobile workspace page');
await assertNoOverflow(mobile,'Mobile dashboard');
await mobile.screenshot({ path: `${out}/nexvary-panel-0.6-mobile.png`, fullPage: true });
await mobile.locator('#mobileMenu').click();
await mobile.locator('#sidebar.open').waitFor({ state: 'visible' });
await mobile.waitForTimeout(300);
await assertRoyalFrame(mobile,'#nav a.active','Mobile active navigation item');
await mobile.screenshot({ path: `${out}/nexvary-panel-0.6-mobile-drawer.png`, fullPage: false });
await mobile.keyboard.press('Escape');
await mobile.waitForTimeout(250);
if(await mobile.locator('#sidebar.open').count())throw new Error('Escape did not close mobile drawer');
await browser.close();
if (failures.length) throw new Error(failures.join('\n'));
console.log('Nexvary Panel 0.6 Fusion Capability/Site Health/Royal UI Release Gate: PASS');
