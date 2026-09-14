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
if(await page.locator('script[src="/static/advanced-ops-tabs.js"]').count()!==1)throw new Error('Advanced Ops tab controller missing');
if(await page.locator('script[src="/static/server-lifecycle.js"]').count()!==1)throw new Error('Server Lifecycle controller missing');

const required=['#advDnsCard','#advSslCard','#advMailOpsCard','#advPhpCard','#advPostgresCard','#advMigrationCard','#advServerLifecycleCard','#advServicesCard','#advFleetCard'];
for(const sel of required)if(await page.locator(sel).count()!==1)throw new Error(`Advanced Ops card missing: ${sel}`);
for(const sel of ['#autoSslEnabled','#autoSslDays','#autoSslSaveBtn','#autoSslPolicyState','#autoSslPreflightBtn','#autoSslPreflightState','#deliverSelector','#deliverMailHost','#deliverMailIpv4','#deliverPrepareBtn','#deliverPreviewList','#serverLifecycleHost','#serverLifecycleOs','#serverLifecycleUpdates','#serverLifecycleReboot','#serverLifecycleRefresh','#serverLifecycleNtp','#serverLifecycleUpdatePreview','#serverLifecycleRebootPreview','#serverLifecycleMaintenance']){
  if(await page.locator(sel).count()!==1)throw new Error(`Advanced Ops lifecycle control missing: ${sel}`);
}

const tabs=page.locator('#advancedops [data-adv-tab]');
if(await tabs.count()!==4)throw new Error('Admin Advanced Ops must expose four capability tabs');
const expectedTabs=['Trust & Safety','DNS & TLS','Runtime & Data','Server & Fleet'];
for(let i=0;i<expectedTabs.length;i++){
  if((await tabs.nth(i).innerText()).trim()!==expectedTabs[i])throw new Error(`Advanced Ops tab label mismatch at ${i}`);
}
const assertVisible=async(sel,expected,label)=>{
  const visible=await page.locator(sel).isVisible();
  if(visible!==expected)throw new Error(`${label}: ${sel} visibility=${visible}, expected=${expected}`);
};
await assertVisible('#advDomainReadinessCard',true,'trust default');
await assertVisible('#advChangeSafetyCard',true,'trust default');
await assertVisible('#domainGuardianCard',true,'trust default');
await assertVisible('#advDnsCard',false,'trust default');
await assertVisible('#advServerLifecycleCard',false,'trust default');

await page.locator('[data-adv-tab="edge"]').click();
await assertVisible('#advDnsCard',true,'edge tab');
await assertVisible('#advSslCard',true,'edge tab');
await assertVisible('#advMailOpsCard',true,'edge tab');
await assertVisible('#advDomainReadinessCard',false,'edge tab');
if(await page.locator('[data-adv-tab="edge"]').getAttribute('aria-selected')!=='true')throw new Error('Edge tab aria-selected state missing');

const readiness=(await page.locator('#autoSslPreflightState').innerText()).trim();
if(!readiness.includes('AutoSSL readiness'))throw new Error('AutoSSL readiness posture is not explicit');
if(await page.locator('#autoSslPreflightBtn').innerText()!=='فحص الجاهزية')throw new Error('AutoSSL preflight action label missing');
if(await page.locator('#dnsDomain').count()!==1)throw new Error('Legacy DNS Center selector must remain unique');
if(await page.locator('#advDnsDomain').count()!==1)throw new Error('Advanced DNS selector missing or duplicated');
if(await page.locator('#dnsInspect').count()!==1)throw new Error('Legacy DNS Inspector control missing');

await page.waitForFunction(()=>['ONLINE','OFFLINE'].includes(document.querySelector('#advProviderState')?.textContent?.trim()),null,{timeout:10000});
const provider=(await page.locator('#advProviderState').innerText()).trim();
if(provider!=='OFFLINE')throw new Error(`CI without Advanced Ops Agent must truthfully show OFFLINE, got ${provider}`);
const notice=(await page.locator('#advNotice').innerText()).trim();
if(!notice.includes('غير متصل'))throw new Error('Advanced Ops offline posture is not explicit');

await page.locator('[data-adv-tab="runtime"]').click();
await assertVisible('#advPhpCard',true,'runtime tab');
await assertVisible('#advPostgresCard',true,'runtime tab');
await assertVisible('#advMigrationCard',true,'runtime tab');
await assertVisible('#advDnsCard',false,'runtime tab');

await page.locator('[data-adv-tab="server"]').click();
await assertVisible('#advServerLifecycleCard',true,'server tab');
await assertVisible('#advServicesCard',true,'server tab');
await assertVisible('#advFleetCard',true,'server tab');
await assertVisible('#advPhpCard',false,'server tab');
const serverMeta=(await page.locator('#serverLifecycleMeta').innerText()).trim();
if(!serverMeta.includes('SERVER PROVIDER OFFLINE'))throw new Error(`CI without Server Lifecycle Agent must truthfully show offline posture, got: ${serverMeta}`);

const text=await page.locator('#advancedops').textContent();
for(const marker of ['DNS Apply / Rollback','AutoSSL / Renew','Queue & Deliverability Repair','PHP Version Manager','PostgreSQL Resources','Migration Bundles','Server Maintenance Center','Service Control','Fleet / Cluster Foundation','PREVIEW FIRST','PREVIEW-FIRST','DIAGNOSE → PREVIEW']){
  if(!text.includes(marker))throw new Error(`Advanced Ops capability label missing: ${marker}`);
}
if(text.includes('Apply System Updates')||text.includes('Reboot Now'))throw new Error('Server Lifecycle must not expose direct update/reboot Apply in Platform 0.7');

await page.locator('[data-adv-tab="trust"]').click();
await assertVisible('#advDomainReadinessCard',true,'trust return');
if(await page.evaluate(()=>document.documentElement.scrollWidth>document.documentElement.clientWidth+2))throw new Error('Advanced Ops desktop horizontal overflow');
await page.screenshot({path:`${out}/nexvary-panel-0.7-advanced-hosting-ops-desktop.png`,fullPage:true});

await page.setViewportSize({width:390,height:844});
await page.waitForTimeout(300);
await page.locator('[data-adv-tab="server"]').click();
await assertVisible('#advServerLifecycleCard',true,'mobile server tab');
if(await page.evaluate(()=>document.documentElement.scrollWidth>document.documentElement.clientWidth+2))throw new Error('Advanced Ops mobile horizontal overflow');
await page.screenshot({path:`${out}/nexvary-panel-0.7-advanced-hosting-ops-mobile.png`,fullPage:true});
await browser.close();
console.log('Nexvary Panel Advanced Hosting Ops + Server Lifecycle Chromium Gate: PASS');
