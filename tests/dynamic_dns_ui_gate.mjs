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
}
async function openDns(page){
  const nav=page.locator('#nav a[href="#dns"]');
  if(await nav.count()!==1) throw new Error('DNS navigation entry missing');
  await nav.evaluate(el=>el.click());
  await page.locator('#dns.active-view').waitFor({state:'visible'});
}
async function noOverflow(page,label){
  const overflow=await page.evaluate(()=>document.documentElement.scrollWidth>document.documentElement.clientWidth+2);
  if(overflow) throw new Error(`${label}: horizontal overflow`);
}

const browser=await chromium.launch({headless:true});
const page=await browser.newPage({viewport:{width:1600,height:1000}});
await login(page);await openDns(page);
for(const sel of ['#ddnsForm','#ddnsList','#ddnsStatus','#ddnsTokenReveal','#dnsDomain','#dnsInspect']){
  if(await page.locator(sel).count()!==1) throw new Error(`Dynamic DNS UI missing ${sel}`);
}
if(await page.locator('#ddnsForm input[name="hostname"]').count()!==1) throw new Error('Dynamic DNS hostname input missing');
if(await page.locator('#ddnsForm input[name="address"]').count()!==1) throw new Error('Dynamic DNS address input missing');
if(await page.locator('#ddnsForm select[name="record_type"] option').count()!==2) throw new Error('Dynamic DNS must expose A/AAAA only');
const hero=(await page.locator('#dns .workspace-hero').innerText()).toUpperCase();
if(hero.includes('READ ONLY')) throw new Error('DNS Center still claims read-only mode');
if(!hero.includes('PROTECTED')) throw new Error('DNS Center protected-write posture missing');
const control=await page.locator('#dns .dns-summary-card').nth(3).innerText();
if(!/PROTECTED/i.test(control)) throw new Error('DNS protected control mode missing');
if(await page.locator('script[src="/static/dns.js"]').count()!==1) throw new Error('DNS JavaScript asset missing');
if(await page.locator('link[href="/static/dns.css"]').count()!==1) throw new Error('DNS stylesheet asset missing');
await noOverflow(page,'Dynamic DNS desktop');
await page.screenshot({path:`${out}/nexvary-panel-0.7-dynamic-dns-desktop.png`,fullPage:false});

const mobile=await browser.newPage({viewport:{width:390,height:844}});
await login(mobile);await openDns(mobile);
if(!(await mobile.locator('#ddnsForm').isVisible())) throw new Error('Dynamic DNS form hidden on mobile');
await noOverflow(mobile,'Dynamic DNS mobile');
await mobile.screenshot({path:`${out}/nexvary-panel-0.7-dynamic-dns-mobile.png`,fullPage:false});
await browser.close();
console.log('Nexvary Panel Dynamic DNS Chromium gate: PASS');
