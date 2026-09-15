import { chromium } from 'playwright';
import fs from 'node:fs';

const base=process.env.NVP_BASE_URL||'http://127.0.0.1:8000';
const password=process.env.NVP_TEST_PASSWORD;
if(!password)throw new Error('NVP_TEST_PASSWORD is required');
const out=process.env.NVP_SCREENSHOT_DIR||'tests/artifacts';
fs.mkdirSync(out,{recursive:true});

const browser=await chromium.launch({headless:true});
const page=await browser.newPage({viewport:{width:1600,height:1050}});
await page.route('**/api/doctor/remediation-preview',async route=>{
  await route.fulfill({status:200,contentType:'application/json',body:JSON.stringify({
    ok:true,
    report:{summary:{total:3,passed:1,failed:2},checks:[]},
    remediation:[
      {check:'Service: nginx',severity:'critical',detail:'inactive',safe:true,action:'restart-service',service:'nginx',reason:'Restart the allow-listed service and verify Doctor again.'},
      {check:'Disk capacity',severity:'warning',detail:'91.5% used',safe:false,action:'manual',service:'',reason:'This diagnostic needs an explicit administrator decision; no automatic fix is permitted.'}
    ]
  })});
});

await page.goto(`${base}/login`,{waitUntil:'networkidle'});
await page.locator('input[name="username"]').fill('admin');
await page.locator('input[name="password"]').fill(password);
await page.locator('button').filter({hasText:'دخول آمن'}).click();
await page.waitForURL(url=>url.pathname==='/'||url.pathname==='',{timeout:15000});
await page.locator('#nav a[href="#services"]').click();
await page.locator('#services.active-view').waitFor({state:'visible'});

for(const sel of ['#doctorBtn','#doctorRemediationBtn','#doctorRemediationState','#doctorRemediationReport']){
  if(await page.locator(sel).count()!==1)throw new Error(`Doctor remediation control missing: ${sel}`);
}
if(await page.locator('script[src="/static/doctor-remediation.js"]').count()!==1)throw new Error('Doctor remediation script missing');
if((await page.locator('#services').getAttribute('data-role'))!=='admin')throw new Error('Doctor workspace role context missing');

await page.locator('#doctorRemediationBtn').click();
await page.locator('#doctorRemediationReport').getByText('Service: nginx').waitFor({state:'visible'});
await page.locator('#doctorRemediationReport').getByText('Disk capacity').waitFor({state:'visible'});
const safeButton=page.locator('#doctorRemediationReport [data-doctor-fix="Service: nginx"]');
if(await safeButton.count()!==1)throw new Error('Safe remediation action is not rendered');
if(!(await safeButton.isDisabled()))throw new Error('Safe remediation must remain disabled until Step-Up is active');
const reportText=await page.locator('#doctorRemediationReport').innerText();
if(!reportText.includes('SAFE FIX')||!reportText.includes('MANUAL'))throw new Error('Doctor remediation classification missing');
if(await page.evaluate(()=>document.documentElement.scrollWidth>document.documentElement.clientWidth+2))throw new Error('Doctor remediation desktop horizontal overflow');
await page.screenshot({path:`${out}/nexvary-panel-0.7-doctor-remediation-desktop.png`,fullPage:true});

await page.setViewportSize({width:390,height:844});
await page.waitForTimeout(250);
if(await page.evaluate(()=>document.documentElement.scrollWidth>document.documentElement.clientWidth+2))throw new Error('Doctor remediation mobile horizontal overflow');
await page.screenshot({path:`${out}/nexvary-panel-0.7-doctor-remediation-mobile.png`,fullPage:true});

await browser.close();
console.log('NEXVARY Doctor remediation Chromium Gate: PASS');
