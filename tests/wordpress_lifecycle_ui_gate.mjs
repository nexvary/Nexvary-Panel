import { chromium } from 'playwright';
import fs from 'node:fs';

const base=process.env.NVP_BASE_URL||'http://127.0.0.1:8000';
const password=process.env.NVP_TEST_PASSWORD;
if(!password)throw new Error('NVP_TEST_PASSWORD is required');
const out=process.env.NVP_SCREENSHOT_DIR||'tests/artifacts';
fs.mkdirSync(out,{recursive:true});

const browser=await chromium.launch({headless:true});
const page=await browser.newPage({viewport:{width:1600,height:1050}});
await page.goto(`${base}/login`,{waitUntil:'networkidle'});
await page.locator('input[name="username"]').fill('admin');
await page.locator('input[name="password"]').fill(password);
await page.locator('button').filter({hasText:'دخول آمن'}).click();
await page.waitForURL(url=>url.pathname==='/'||url.pathname==='',{timeout:15000});

const nav=page.locator('#nav a[href="#wordpress"]');
if(await nav.count()!==1)throw new Error('WordPress navigation entry missing');
await nav.click();
await page.locator('#wordpress.active-view').waitFor({state:'visible'});

for(const sel of ['#wordpressLifecyclePanel','#wpLifecycleDomain','#wpInventoryBtn','#wpIntegrityBtn','#wpMaintenanceOnBtn','#wpMaintenanceOffBtn','#wpProviderBadge','#wpCoreVersion','#wpPluginCount','#wpThemeCount','#wpMaintenanceState','#wpLifecycleResult','#wpLifecycleComponents']){
  if(await page.locator(sel).count()!==1)throw new Error(`WordPress lifecycle control missing: ${sel}`);
}
if(await page.locator('script[src="/static/wordpress-lifecycle.js"]').count()!==1)throw new Error('WordPress lifecycle script missing');
const text=await page.locator('#wordpress').innerText();
for(const marker of ['WordPress Manager','Lifecycle & Integrity','Verify Core Integrity','Maintenance ON','Maintenance OFF','FILE EDITOR','DISABLED']){
  if(!text.includes(marker))throw new Error(`WordPress lifecycle marker missing: ${marker}`);
}
if(await page.evaluate(()=>document.documentElement.scrollWidth>document.documentElement.clientWidth+2))throw new Error('WordPress lifecycle desktop horizontal overflow');
await page.screenshot({path:`${out}/nexvary-panel-0.7-wordpress-lifecycle-desktop.png`,fullPage:true});

await page.setViewportSize({width:390,height:844});
await page.waitForTimeout(300);
if(await page.evaluate(()=>document.documentElement.scrollWidth>document.documentElement.clientWidth+2))throw new Error('WordPress lifecycle mobile horizontal overflow');
await page.screenshot({path:`${out}/nexvary-panel-0.7-wordpress-lifecycle-mobile.png`,fullPage:true});

await browser.close();
console.log('Nexvary Panel WordPress Lifecycle Chromium Gate: PASS');
