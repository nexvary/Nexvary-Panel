import { chromium } from 'playwright';
import fs from 'node:fs';

const base=process.env.NVP_BASE_URL||'http://127.0.0.1:8000';
const password=process.env.NVP_TEST_PASSWORD;
if(!password)throw new Error('NVP_TEST_PASSWORD is required');
const out=process.env.NVP_SCREENSHOT_DIR||'tests/artifacts';
fs.mkdirSync(out,{recursive:true});

const browser=await chromium.launch({headless:true});
const page=await browser.newPage({viewport:{width:1600,height:1050}});
await page.route('**/api/change-safety',async route=>{
  await route.fulfill({status:200,contentType:'application/json',body:JSON.stringify({
    ok:true,
    posture:{score:92,grade:'A',recent:4,external_changes:3,protected_changes:3,attention:0,pending_previews:1},
    policy:{preview_before_mutation:true,step_up_for_sensitive_writes:true,rollback_preferred:true,manual_when_unsafe:true},
    events:[
      {kind:'dns',id:1,domain:'example.test',label:'create A www.example.test',state:'preview',safety:'preview',reversible:true,external_state_touched:false,guidance:'لم يُطبّق على مزود DNS بعد؛ راجع المعاينة قبل Apply.',owner:'admin',changed_at:1900000000},
      {kind:'dns',id:2,domain:'example.test',label:'update A www.example.test',state:'applied',safety:'reversible',reversible:true,external_state_touched:true,guidance:'التغيير مطبق وله Snapshot مستخدم بواسطة DNS Rollback.',owner:'admin',changed_at:1900000100},
      {kind:'doctor',id:3,domain:'',label:'Service: nginx',state:'verified',safety:'verified',reversible:true,external_state_touched:true,guidance:'Allow-listed restart لـ nginx ثم إعادة فحص Doctor.',owner:'admin',changed_at:1900000200}
    ]
  })});
});

await page.goto(`${base}/login`,{waitUntil:'networkidle'});
await page.locator('input[name="username"]').fill('admin');
await page.locator('input[name="password"]').fill(password);
await page.locator('button').filter({hasText:'دخول آمن'}).click();
await page.waitForURL(url=>url.pathname==='/'||url.pathname==='',{timeout:15000});
await page.locator('#nav a[href="#advancedops"]').click();
await page.locator('#advancedops.active-view').waitFor({state:'visible'});

for(const sel of ['#advChangeSafetyCard','#changeSafetyScore','#changeSafetyGrade','#changeSafetyProtected','#changeSafetyAttention','#changeSafetyRefresh','#changeSafetyEvents']){
  if(await page.locator(sel).count()!==1)throw new Error(`Change Safety UI control missing: ${sel}`);
}
if(await page.locator('script[src="/static/change-safety.js"]').count()!==1)throw new Error('Change Safety script missing');
await page.locator('#changeSafetyEvents').getByText('create A www.example.test').waitFor({state:'visible'});
await page.locator('#changeSafetyEvents').getByText('Service: nginx').waitFor({state:'visible'});
if((await page.locator('#changeSafetyScore').innerText()).trim()!=='92%')throw new Error('Change Safety score not rendered');
if((await page.locator('#changeSafetyGrade').innerText()).trim()!=='A')throw new Error('Change Safety grade not rendered');
const text=await page.locator('#advChangeSafetyCard').innerText();
for(const marker of ['CHANGE SAFETY','Reversibility Control','PREVIEW','ROLLBACK READY','VERIFIED']){
  if(!text.includes(marker))throw new Error(`Change Safety marker missing: ${marker}`);
}
if(await page.evaluate(()=>document.documentElement.scrollWidth>document.documentElement.clientWidth+2))throw new Error('Change Safety desktop horizontal overflow');
await page.screenshot({path:`${out}/nexvary-panel-0.7-change-safety-desktop.png`,fullPage:true});

await page.setViewportSize({width:390,height:844});
await page.waitForTimeout(250);
if(await page.evaluate(()=>document.documentElement.scrollWidth>document.documentElement.clientWidth+2))throw new Error('Change Safety mobile horizontal overflow');
await page.screenshot({path:`${out}/nexvary-panel-0.7-change-safety-mobile.png`,fullPage:true});

await browser.close();
console.log('NEXVARY Change Safety Chromium Gate: PASS');
