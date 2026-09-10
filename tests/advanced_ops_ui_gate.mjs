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

const nav=page.locator('#nav a[href="#advancedops"]');
if(await nav.count()!==1)throw new Error('Advanced Hosting Ops navigation entry missing');
await nav.click();
await page.locator('#advancedops.active-view').waitFor({state:'visible'});
if(await page.locator('link[href="/static/advanced-ops.css"]').count()!==1)throw new Error('Advanced Ops stylesheet missing');
if(await page.locator('script[src="/static/advanced-ops.js"]').count()!==1)throw new Error('Advanced Ops script missing');

const required=['#advDnsCard','#advSslCard','#advMailOpsCard','#advPhpCard','#advPostgresCard','#advMigrationCard','#advServicesCard','#advFleetCard'];
for(const sel of required)if(await page.locator(sel).count()!==1)throw new Error(`Advanced Ops card missing: ${sel}`);
if(await page.locator('#dnsDomain').count()!==1)throw new Error('Legacy DNS Center selector must remain unique');
if(await page.locator('#advDnsDomain').count()!==1)throw new Error('Advanced DNS selector missing or duplicated');
if(await page.locator('#dnsInspect').count()!==1)throw new Error('Legacy DNS Inspector control missing');

await page.waitForFunction(()=>['ONLINE','OFFLINE'].includes(document.querySelector('#advProviderState')?.textContent?.trim()),null,{timeout:10000});
const provider=(await page.locator('#advProviderState').innerText()).trim();
if(provider!=='OFFLINE')throw new Error(`CI without Advanced Ops Agent must truthfully show OFFLINE, got ${provider}`);
const notice=(await page.locator('#advNotice').innerText()).trim();
if(!notice.includes('غير متصل'))throw new Error('Advanced Ops offline posture is not explicit');

const text=await page.locator('#advancedops').innerText();
for(const marker of ['DNS Apply / Rollback','AutoSSL / Renew','Queue & Deliverability','PHP Version Manager','PostgreSQL Resources','Migration Bundles','Service Control','Fleet / Cluster Foundation']){
  if(!text.includes(marker))throw new Error(`Advanced Ops capability label missing: ${marker}`);
}
if(await page.evaluate(()=>document.documentElement.scrollWidth>document.documentElement.clientWidth+2))throw new Error('Advanced Ops desktop horizontal overflow');
await page.screenshot({path:`${out}/nexvary-panel-0.7-advanced-hosting-ops-desktop.png`,fullPage:true});

await page.setViewportSize({width:390,height:844});
await page.waitForTimeout(300);
if(await page.evaluate(()=>document.documentElement.scrollWidth>document.documentElement.clientWidth+2))throw new Error('Advanced Ops mobile horizontal overflow');
await page.screenshot({path:`${out}/nexvary-panel-0.7-advanced-hosting-ops-mobile.png`,fullPage:true});
await browser.close();
console.log('Nexvary Panel Advanced Hosting Ops Chromium Gate: PASS');
