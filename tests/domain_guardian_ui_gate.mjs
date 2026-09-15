import { chromium } from 'playwright';
import fs from 'node:fs';

const base=process.env.NVP_BASE_URL||'http://127.0.0.1:8000';
const password=process.env.NVP_TEST_PASSWORD;
if(!password)throw new Error('NVP_TEST_PASSWORD is required');
const out=process.env.NVP_SCREENSHOT_DIR||'tests/artifacts';
fs.mkdirSync(out,{recursive:true});

const readiness={domain:'guardian.example.test',owner:'admin',kind:'php',score:78,grade:'B',recommendations:[{id:'ssl-automation',message:'Enable AutoSSL',view:'advancedops'}],checks:[],domain_lifecycle:{aliases:1},dns:{bound:true,provider:'cloudflare',pending_previews:0,dnssec:{supported_by_bound_provider:true}},ssl:{feature_enabled:true,auto_renew:false},mail:{enabled:true,mailboxes:1,forwarders:0,deliverability_feature:true}};
const guardian={domain:'guardian.example.test',owner:'admin',score:68,state:'attention',readiness,deliverability:{score:45,grade:'D',recommendations:[{id:'spf',severity:'critical',message:'SPF missing'},{id:'dmarc',severity:'warning',message:'DMARC missing'}]},safety:{score:100,grade:'A',attention:[]},safe_prepare_count:2,live_checks:true,plan:[{id:'enable-autossl',mode:'safe-prepare',severity:'warning',message:'Prepare AutoSSL policy.'},{id:'prepare-mail-dns',mode:'safe-prepare',severity:'warning',message:'Create reviewable DNS previews.'},{id:'publish-dkim',mode:'manual',severity:'warning',message:'Publish DKIM record.'}]};

const browser=await chromium.launch({headless:true});
const page=await browser.newPage({viewport:{width:1600,height:1050}});
await page.route('**/api/domain-health*',async route=>{const url=new URL(route.request().url());if(url.searchParams.get('domain'))await route.fulfill({status:200,contentType:'application/json',body:JSON.stringify({ok:true,readiness})});else await route.fulfill({status:200,contentType:'application/json',body:JSON.stringify({ok:true,domains:[readiness],count:1})})});
await page.route('**/api/domain-guardian*',async route=>{if(route.request().method()==='POST'){await route.fulfill({status:200,contentType:'application/json',body:JSON.stringify({ok:true,prepared:[{id:'enable-autossl',external_change:false},{id:'prepare-mail-dns',external_change:false}],skipped:[],guardian,safety_note:'No external DNS record was applied and no certificate was issued.'})});return}await route.fulfill({status:200,contentType:'application/json',body:JSON.stringify({ok:true,guardian})})});

await page.goto(`${base}/login`,{waitUntil:'networkidle'});
await page.locator('input[name="username"]').fill('admin');
await page.locator('input[name="password"]').fill(password);
await page.locator('button').filter({hasText:'دخول آمن'}).click();
await page.waitForURL(url=>url.pathname==='/'||url.pathname==='',{timeout:15000});
await page.locator('#nav a[href="#advancedops"]').click();
await page.locator('#advancedops.active-view').waitFor({state:'visible'});
for(const sel of ['#domainGuardianCard','#guardianDomain','#guardianSelector','#guardianEmail','#guardianMailHost','#guardianMailIpv4','#guardianAnalyzeBtn','#guardianPrepareBtn','#guardianScore','#guardianState','#guardianSafeCount','#guardianNotice','#guardianPlan'])if(await page.locator(sel).count()!==1)throw new Error(`Domain Guardian control missing: ${sel}`);
if(await page.locator('script[src="/static/domain-guardian.js"]').count()!==1)throw new Error('Domain Guardian script missing');
await page.waitForFunction(()=>document.querySelector('#guardianDomain')?.querySelectorAll('option').length>1,{timeout:10000});
await page.locator('#guardianDomain').selectOption('guardian.example.test');
await page.locator('#guardianAnalyzeBtn').click();
await page.waitForFunction(()=>document.querySelector('#guardianScore')?.textContent?.includes('68/100'),{timeout:10000});
if((await page.locator('#guardianState').innerText()).trim()!=='ATTENTION')throw new Error('Guardian state was not rendered');
if((await page.locator('#guardianSafeCount').innerText()).trim()!=='2')throw new Error('Safe prepare count was not rendered');
const cardText=await page.locator('#domainGuardianCard').innerText();
for(const marker of ['NEXVARY DOMAIN GUARDIAN','Trust Automation','ANALYZE → SAFE PREPARE','enable-autossl','prepare-mail-dns','publish-dkim'])if(!cardText.includes(marker))throw new Error(`Guardian marker missing: ${marker}`);
if(await page.evaluate(()=>document.documentElement.scrollWidth>document.documentElement.clientWidth+2))throw new Error('Domain Guardian desktop horizontal overflow');
await page.locator('#domainGuardianCard').scrollIntoViewIfNeeded();
await page.screenshot({path:`${out}/nexvary-panel-0.7-domain-guardian-desktop.png`,fullPage:false});

await page.setViewportSize({width:390,height:844});
await page.locator('#domainGuardianCard').scrollIntoViewIfNeeded();
await page.waitForTimeout(200);
if(await page.evaluate(()=>document.documentElement.scrollWidth>document.documentElement.clientWidth+2))throw new Error('Domain Guardian mobile horizontal overflow');
await page.screenshot({path:`${out}/nexvary-panel-0.7-domain-guardian-mobile.png`,fullPage:false});

await browser.close();
console.log('NEXVARY Domain Guardian Chromium gate: PASS');
