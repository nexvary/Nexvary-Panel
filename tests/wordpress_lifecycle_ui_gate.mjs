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

for(const sel of ['#wordpressLifecyclePanel','#wpLifecycleDomain','#wpInventoryBtn','#wpIntegrityBtn','#wpRepairBtn','#wpRollbackBtn','#wpMaintenanceOnBtn','#wpMaintenanceOffBtn','#wpProviderBadge','#wpCoreVersion','#wpPluginCount','#wpThemeCount','#wpMaintenanceState','#wpLifecycleResult','#wpLifecycleComponents']){
  if(await page.locator(sel).count()!==1)throw new Error(`WordPress lifecycle control missing: ${sel}`);
}
if(await page.locator('script[src="/static/wordpress-lifecycle.js"]').count()!==1)throw new Error('WordPress lifecycle script missing');
const text=await page.locator('#wordpress').innerText();
for(const marker of ['WordPress Manager','Lifecycle & Integrity','Verify Core Integrity','Repair Core','Rollback Last Repair','Maintenance ON','Maintenance OFF','FILE EDITOR','DISABLED']){
  if(!text.includes(marker))throw new Error(`WordPress lifecycle marker missing: ${marker}`);
}

const jsSource=await page.evaluate(async()=>await (await fetch('/static/wordpress-lifecycle.js')).text());
for(const contract of ['/api/wordpress/repair-core','/api/wordpress/repair-rollback','/api/wordpress/components/check','/api/wordpress/components/update','/api/wordpress/components/rollback']){
  if(!jsSource.includes(contract))throw new Error(`WordPress lifecycle handler contract missing: ${contract}`);
}

await page.route('**/api/wordpress/lifecycle?*',async route=>route.fulfill({status:200,contentType:'application/json',body:JSON.stringify({ok:true,domain:'wp.example.test',version:'6.8.2',maintenance:false,config_present:true,plugin_count:1,theme_count:1,plugins:[{slug:'hello-tool',version:'1.0.0'}],themes:[{slug:'royal-theme',version:'3.0.0'}]})}));
await page.route('**/api/wordpress/components/check?*',async route=>route.fulfill({status:200,contentType:'application/json',body:JSON.stringify({ok:true,domain:'wp.example.test',kind:'plugin',slug:'hello-tool',installed_version:'1.0.0',latest_version:'2.0.0',update_available:true,source:'downloads.wordpress.org'})}));
await page.locator('#wpLifecycleDomain').evaluate(select=>{const option=document.createElement('option');option.value='wp.example.test';option.textContent='wp.example.test';select.append(option)});
await page.locator('#wpLifecycleDomain').selectOption('wp.example.test');
await page.locator('#wpLifecycleComponents .wp-card').first().waitFor({state:'visible'});
if(await page.locator('#wpLifecycleComponents .wp-card').count()!==2)throw new Error('WordPress component inventory cards were not rendered');
for(const label of ['Check Update','Update','Rollback']){
  if(await page.locator('#wpLifecycleComponents button').filter({hasText:label}).count()<2)throw new Error(`WordPress component action missing: ${label}`);
}
await page.locator('#wpLifecycleComponents .wp-card').first().locator('button').filter({hasText:'Check Update'}).click();
await page.waitForFunction(()=>document.querySelector('#wpLifecycleResult')?.textContent?.includes('Official latest: 2.0.0'));
if(!(await page.locator('#wpLifecycleComponents .wp-card').first().innerText()).includes('UPDATE 1.0.0 → 2.0.0'))throw new Error('WordPress Check Update action did not update component state');

if(await page.evaluate(()=>document.documentElement.scrollWidth>document.documentElement.clientWidth+2))throw new Error('WordPress lifecycle desktop horizontal overflow');
await page.screenshot({path:`${out}/nexvary-panel-0.7-wordpress-lifecycle-desktop.png`,fullPage:true});

await page.setViewportSize({width:390,height:844});
await page.waitForTimeout(300);
if(await page.evaluate(()=>document.documentElement.scrollWidth>document.documentElement.clientWidth+2))throw new Error('WordPress lifecycle mobile horizontal overflow');
await page.screenshot({path:`${out}/nexvary-panel-0.7-wordpress-lifecycle-mobile.png`,fullPage:true});

await browser.close();
console.log('Nexvary Panel WordPress Lifecycle Chromium Gate: PASS');
