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
await page.locator('#nav a[href="#advancedops"]').click();
await page.locator('#advancedops.active-view').waitFor({state:'visible'});

for(const sel of ['#advDomainReadinessCard','#domainReadinessDomain','#domainReadinessRefresh','#domainReadinessScore','#domainReadinessGrade','#domainReadinessMeta','#domainReadinessChecks']){
  if(await page.locator(sel).count()!==1)throw new Error(`Domain Readiness UI control missing: ${sel}`);
}
if(await page.locator('script[src="/static/domain-readiness.js"]').count()!==1)throw new Error('Domain Readiness script missing');
const text=await page.locator('#advDomainReadinessCard').innerText();
for(const marker of ['DOMAIN READINESS','Control-plane Health','UNIFIED HEALTH','READINESS','GRADE']){
  if(!text.includes(marker))throw new Error(`Domain Readiness marker missing: ${marker}`);
}
const api=await page.evaluate(async()=>{const r=await fetch('/api/domain-health',{headers:{Accept:'application/json'}});return{status:r.status,body:await r.json()}});
if(api.status!==200||api.body.ok!==true||!Array.isArray(api.body.domains))throw new Error('Domain Readiness API is not wired into the live workspace');
if(await page.evaluate(()=>document.documentElement.scrollWidth>document.documentElement.clientWidth+2))throw new Error('Domain Readiness desktop horizontal overflow');
await page.screenshot({path:`${out}/nexvary-panel-0.7-domain-readiness-desktop.png`,fullPage:true});

await page.setViewportSize({width:390,height:844});
await page.waitForTimeout(300);
if(await page.evaluate(()=>document.documentElement.scrollWidth>document.documentElement.clientWidth+2))throw new Error('Domain Readiness mobile horizontal overflow');
await page.screenshot({path:`${out}/nexvary-panel-0.7-domain-readiness-mobile.png`,fullPage:true});

await browser.close();
console.log('Nexvary Panel Domain Readiness Chromium Gate: PASS');
