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

for(const sel of ['#wordpressLifecyclePanel','#wpLifecycleDomain','#wpInventoryBtn','#wpIntegrityBtn','#wpRepairBtn','#wpRollbackBtn','#wpMaintenanceOnBtn','#wpMaintenanceOffBtn','#wpProviderBadge','#wpCoreVersion','#wpPluginCount','#wpThemeCount','#wpMaintenanceState','#wpLifecycleResult','#wpLifecycleComponents','#wpStagingPanel','#wpStageSource','#wpStageTarget','#wpStageDatabase','#wpStageQuota','#wpStageRefreshBtn','#wpStageCloneBtn','#wpStagePreviewBtn','#wpStagePublishBtn','#wpStageRollbackBtn','#wpStageState','#wpStageRollbackState','#wpStagingResult']){
  if(await page.locator(sel).count()!==1)throw new Error(`WordPress lifecycle/staging control missing: ${sel}`);
}
for(const script of ['/static/wordpress-lifecycle.js','/static/wordpress-staging.js']){
  if(await page.locator(`script[src="${script}"]`).count()!==1)throw new Error(`WordPress script missing: ${script}`);
}
const text=await page.locator('#wordpress').innerText();
for(const marker of ['WordPress Manager','Lifecycle & Integrity','Verify Core Integrity','Repair Core','Rollback Last Repair','Maintenance ON','Maintenance OFF','Staging & Safe Publish','Clone / Refresh Staging','Publish Preview','Safe Publish','Rollback Last Publish','HOME/SITEURL','FILE EDITOR','DISABLED']){
  if(!text.includes(marker))throw new Error(`WordPress lifecycle marker missing: ${marker}`);
}

const lifecycleSource=await page.evaluate(async()=>await (await fetch('/static/wordpress-lifecycle.js')).text());
for(const contract of ['/api/wordpress/repair-core','/api/wordpress/repair-rollback','/api/wordpress/components/check','/api/wordpress/components/update','/api/wordpress/components/rollback']){
  if(!lifecycleSource.includes(contract))throw new Error(`WordPress lifecycle handler contract missing: ${contract}`);
}
const stagingSource=await page.evaluate(async()=>await (await fetch('/static/wordpress-staging.js')).text());
for(const contract of ['/api/wordpress/staging?','/api/wordpress/staging/clone','/api/wordpress/staging/publish-preview','/api/wordpress/staging/publish','/api/wordpress/staging/publish-rollback']){
  if(!stagingSource.includes(contract))throw new Error(`WordPress staging handler contract missing: ${contract}`);
}

await page.route('**/api/wordpress/lifecycle?*',async route=>route.fulfill({status:200,contentType:'application/json',body:JSON.stringify({ok:true,domain:'wp.example.test',version:'6.8.2',maintenance:false,config_present:true,plugin_count:1,theme_count:1,plugins:[{slug:'hello-tool',version:'1.0.0'}],themes:[{slug:'royal-theme',version:'3.0.0'}]})}));
await page.route('**/api/wordpress/components/check?*',async route=>route.fulfill({status:200,contentType:'application/json',body:JSON.stringify({ok:true,domain:'wp.example.test',kind:'plugin',slug:'hello-tool',installed_version:'1.0.0',latest_version:'2.0.0',update_available:true,source:'downloads.wordpress.org'})}));
await page.route('**/api/wordpress/staging?*',async route=>route.fulfill({status:200,contentType:'application/json',body:JSON.stringify({ok:true,source_domain:'wp.example.test',mapping:{source_domain:'wp.example.test',target_domain:'stage.example.test',target_db:'wpstage',status:'ready',last_publish_snapshot:''},targets:[{domain:'stage.example.test',kind:'php',enabled:1}],database_quota:{used:2,limit:10,remaining:8}})}));
await page.route('**/api/wordpress/staging/publish-preview',async route=>route.fulfill({status:200,contentType:'application/json',body:JSON.stringify({ok:true,source_domain:'wp.example.test',target_domain:'stage.example.test',source_version:'6.8.2',target_version:'6.8.2',source_files:4200,target_files:4210,safety:'snapshot-before-publish'})}));

await page.locator('#wpLifecycleDomain').evaluate(select=>{const option=document.createElement('option');option.value='wp.example.test';option.textContent='wp.example.test';select.append(option)});
await page.locator('#wpLifecycleDomain').selectOption('wp.example.test');
await page.locator('#wpLifecycleComponents .wp-card').first().waitFor({state:'visible'});
await page.waitForFunction(()=>document.querySelector('#wpStageTarget')?.value==='stage.example.test');
if(await page.locator('#wpLifecycleComponents .wp-card').count()!==2)throw new Error('WordPress component inventory cards were not rendered');
for(const label of ['Check Update','Update','Rollback']){
  if(await page.locator('#wpLifecycleComponents button').filter({hasText:label}).count()<2)throw new Error(`WordPress component action missing: ${label}`);
}
await page.locator('#wpLifecycleComponents .wp-card').first().locator('button').filter({hasText:'Check Update'}).click();
await page.waitForFunction(()=>document.querySelector('#wpLifecycleResult')?.textContent?.includes('Official latest: 2.0.0'));
if(!(await page.locator('#wpLifecycleComponents .wp-card').first().innerText()).includes('UPDATE 1.0.0 → 2.0.0'))throw new Error('WordPress Check Update action did not update component state');
if((await page.locator('#wpStageQuota').inputValue())!=='2/10 · 8 LEFT')throw new Error('WordPress staging database quota was not rendered');
if((await page.locator('#wpStageDatabase').inputValue())!=='wpstage')throw new Error('WordPress staging mapping database was not loaded');
if(!(await page.locator('#wpStageCloneBtn').isDisabled()))throw new Error('Staging Clone must require Step-Up in this UI session');
if(!(await page.locator('#wpStagePublishBtn').isDisabled()))throw new Error('Safe Publish must require Step-Up in this UI session');
if(!(await page.locator('#wpStageRollbackBtn').isDisabled()))throw new Error('Publish rollback must remain disabled without Step-Up/snapshot');
await page.locator('#wpStagePreviewBtn').click();
await page.waitForFunction(()=>document.querySelector('#wpStagingResult')?.textContent?.includes('PUBLISH PREVIEW'));
if(!(await page.locator('#wpStagingResult').innerText()).includes('snapshot-before-publish'))throw new Error('Staging publish preview safety state missing');

if(await page.evaluate(()=>document.documentElement.scrollWidth>document.documentElement.clientWidth+2))throw new Error('WordPress lifecycle desktop horizontal overflow');
await page.screenshot({path:`${out}/nexvary-panel-0.7-wordpress-lifecycle-desktop.png`,fullPage:true});

await page.setViewportSize({width:390,height:844});
await page.waitForTimeout(300);
if(await page.evaluate(()=>document.documentElement.scrollWidth>document.documentElement.clientWidth+2))throw new Error('WordPress lifecycle mobile horizontal overflow');
await page.screenshot({path:`${out}/nexvary-panel-0.7-wordpress-lifecycle-mobile.png`,fullPage:true});

await browser.close();
console.log('Nexvary Panel WordPress Lifecycle + Staging Chromium Gate: PASS');
