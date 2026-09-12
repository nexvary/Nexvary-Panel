import { chromium } from 'playwright';
import fs from 'node:fs';

const base=process.env.NVP_BASE_URL||'http://127.0.0.1:8000';
const password=process.env.NVP_TEST_PASSWORD;
if(!password) throw new Error('NVP_TEST_PASSWORD is required');
const out=process.env.NVP_SCREENSHOT_DIR||'tests/artifacts';
fs.mkdirSync(out,{recursive:true});

async function login(page){
  await page.goto(`${base}/login`,{waitUntil:'networkidle'});
  await page.locator('input[name="username"]').fill('admin');
  await page.locator('input[name="password"]').fill(password);
  await page.locator('button').filter({hasText:'دخول آمن'}).click();
  await page.waitForURL(url=>url.pathname==='/'||url.pathname==='',{timeout:15000});
  await page.locator('#dashboard.active-view').waitFor({state:'visible'});
}
async function noOverflow(page,label){
  const overflow=await page.evaluate(()=>document.documentElement.scrollWidth>document.documentElement.clientWidth+2);
  if(overflow) throw new Error(`${label}: horizontal overflow`);
}
async function openHosting(page){
  const nav=page.locator('#nav a[href="#hosting"]');
  if(await nav.count()!==1) throw new Error('Hosting Suite navigation entry missing');
  await nav.evaluate(el=>el.click());
  await page.locator('#hosting.active-view').waitFor({state:'visible'});
}

const browser=await chromium.launch({headless:true});
const page=await browser.newPage({viewport:{width:1600,height:1050}});
await login(page);
if(await page.locator('link[href="/static/hosting-suite.css"]').count()!==1) throw new Error('Hosting Suite stylesheet missing');
if(await page.locator('script[src="/static/hosting-suite.js"]').count()!==1) throw new Error('Hosting Suite script missing');
await openHosting(page);
await page.waitForFunction(()=>Number(document.querySelector('#hostingFeatureCount')?.textContent||0)>=90,{timeout:15000});

const featureCount=Number(await page.locator('#hostingFeatureCount').textContent());
const nativeCount=Number(await page.locator('#hostingNativeCount').textContent());
const foundationCount=Number(await page.locator('#hostingFoundationCount').textContent());
const plannedCount=Number(await page.locator('#hostingPlannedCount').textContent());
if(featureCount<90||nativeCount<10||foundationCount<20||plannedCount<20) throw new Error(`Hosting feature matrix unexpectedly small: ${featureCount}/${nativeCount}/${foundationCount}/${plannedCount}`);

const cards=page.locator('#hosting .hosting-feature-card');
if(await cards.count()<90) throw new Error('Hosting Suite did not render the full capability matrix');
const text=(await page.locator('#hostingFeatureGrid').innerText()).toLowerCase();
for(const required of ['email accounts','ftp accounts','cron jobs','ssl/tls','hosting packages','feature manager','reseller management']){
  if(!text.includes(required)) throw new Error(`Hosting capability missing from UI: ${required}`);
}
if(await page.locator('#hostingPolicyPackage option').count()<3) throw new Error('Default hosting packages were not loaded into Feature Manager');
if(!(await page.locator('#hostingPackageForm button[type="submit"]').isDisabled())) throw new Error('Package mutation must be disabled before Step-Up');
if(await page.locator('#hosting [data-open-view="security"]').count()<1) throw new Error('Step-Up remediation path missing from Hosting Suite');
for(const sel of ['#hostingAssignUsername','#hostingAssignPackage','#hostingImpactBtn','#hostingImpactResult']){
  if(await page.locator(sel).count()!==1) throw new Error(`Package Impact control missing: ${sel}`);
}
const assignmentText=await page.locator('.hosting-assignment-panel').innerText();
if(!assignmentText.includes('IMPACT FIRST')||!assignmentText.includes('معاينة التأثير')) throw new Error('Package Impact workflow is not visible before assignment');

const visiblePages=await page.locator('#workspaceStage>.workspace-page').evaluateAll(nodes=>nodes.filter(el=>getComputedStyle(el).display!=='none').map(el=>el.id));
if(visiblePages.length!==1||visiblePages[0]!=='hosting') throw new Error(`Workspace visibility invariant failed on Hosting Suite: ${visiblePages.join(',')}`);
await noOverflow(page,'hosting desktop');
await page.screenshot({path:`${out}/nexvary-panel-0.7-hosting-suite-desktop.png`,fullPage:false});

const mobile=await browser.newPage({viewport:{width:390,height:844}});
await login(mobile);
await openHosting(mobile);
await mobile.waitForFunction(()=>Number(document.querySelector('#hostingFeatureCount')?.textContent||0)>=90,{timeout:15000});
if(await mobile.locator('#hosting .hosting-feature-card').count()<90) throw new Error('Mobile Hosting Suite feature matrix incomplete');
if(await mobile.locator('#hostingImpactBtn').count()!==1) throw new Error('Mobile Package Impact control missing');
await noOverflow(mobile,'hosting mobile');
await mobile.screenshot({path:`${out}/nexvary-panel-0.7-hosting-suite-mobile.png`,fullPage:false});

await browser.close();
console.log('Nexvary Panel 0.7 Hosting Suite Chromium Gate: PASS');
