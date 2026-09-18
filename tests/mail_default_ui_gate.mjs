import { chromium } from 'playwright';

const base=process.env.NVP_BASE_URL||'http://127.0.0.1:8000';
const password=process.env.NVP_TEST_PASSWORD;
if(!password)throw new Error('NVP_TEST_PASSWORD is required');

const browser=await chromium.launch({headless:true});
const page=await browser.newPage({viewport:{width:1500,height:1000}});
let savedPayload=null;

await page.route('**/api/mail',async route=>{
  const url=new URL(route.request().url());
  if(url.pathname!=='/api/mail')return route.fallback();
  return route.fulfill({status:200,contentType:'application/json',body:JSON.stringify({
    ok:true,domains:[],mailboxes:[],forwarders:[],mailbox_limit:20,forwarder_limit:100,
    available_domains:[{domain:'example.com',owner:'admin',email_accounts:true,email_forwarders:true,mailbox_used:0,mailbox_limit:20,forwarder_used:0,forwarder_limit:100}],
    provider:{online:true,engine:'postfix-dovecot'}
  })});
});
await page.route('**/api/mail/default-address**',async route=>{
  const request=route.request();
  if(request.method()==='GET'){
    return route.fulfill({status:200,contentType:'application/json',body:JSON.stringify({ok:true,feature_allowed:true,default_address:{domain:'example.com',mode:'reject',destination:'',owner:'admin',updated_at:0}})});
  }
  if(request.method()==='PUT'){
    savedPayload=request.postDataJSON();
    return route.fulfill({status:200,contentType:'application/json',body:JSON.stringify({ok:true,default_address:{...savedPayload,owner:'admin',updated_at:1}})});
  }
  return route.fallback();
});

await page.goto(`${base}/login`,{waitUntil:'networkidle'});
await page.locator('input[name="username"]').fill('admin');
await page.locator('input[name="password"]').fill(password);
await page.locator('button').filter({hasText:'دخول آمن'}).click();
await page.waitForURL(url=>url.pathname==='/'||url.pathname==='',{timeout:15000});
await page.locator('#nav a[href="#mail"]').click();
await page.locator('#mail.active-view').waitFor({state:'visible'});
await page.locator('#mailDefaultAddressShell').waitFor({state:'visible'});

for(const selector of ['#mailDefaultForm','#mailDefaultDomain','#mailDefaultMode','#mailDefaultDestination','#mailDefaultSave','#mailDefaultStatus']){
  if(await page.locator(selector).count()!==1)throw new Error(`Default Address UI missing: ${selector}`);
}
await page.waitForFunction(()=>document.querySelector('#mailDefaultFeatureState')?.textContent?.includes('ACTIVE'),null,{timeout:10000});
if(await page.locator('#mailDefaultDomain').inputValue()!=='example.com')throw new Error('Default Address did not inherit scoped domain');
if(await page.locator('#mailDefaultMode').inputValue()!=='reject')throw new Error('Default Address safe reject baseline not loaded');
if(!(await page.locator('#mailDefaultDestination').isDisabled()))throw new Error('Catch-all destination must be disabled in reject mode');

await page.locator('#mailDefaultMode').selectOption('forward');
if(await page.locator('#mailDefaultDestination').isDisabled())throw new Error('Catch-all destination did not enable in forward mode');
await page.locator('#mailDefaultDestination').fill('catch@external.example');
await page.locator('#mailDefaultSave').click();
await page.waitForFunction(()=>document.querySelector('#mailDefaultStatus')?.textContent?.includes('تم حفظ Default Address'),null,{timeout:10000});
if(!savedPayload)throw new Error('Default Address save did not call provider-backed control-plane API');
if(savedPayload.domain!=='example.com'||savedPayload.mode!=='forward'||savedPayload.destination!=='catch@external.example')throw new Error(`Default Address payload malformed: ${JSON.stringify(savedPayload)}`);

savedPayload=null;
await page.locator('#mailDefaultDestination').fill('loop@example.com');
await page.locator('#mailDefaultSave').click();
await page.waitForFunction(()=>document.querySelector('#mailDefaultStatus')?.textContent?.includes('خارج النطاق نفسه'),null,{timeout:10000});
if(savedPayload!==null)throw new Error('Same-domain catch-all loop reached API despite client guard');
if(await page.evaluate(()=>document.documentElement.scrollWidth>document.documentElement.clientWidth+2))throw new Error('Default Address UI caused desktop horizontal overflow');

await page.setViewportSize({width:390,height:844});
await page.waitForTimeout(120);
if(await page.evaluate(()=>document.documentElement.scrollWidth>document.documentElement.clientWidth+2))throw new Error('Default Address UI caused mobile horizontal overflow');
const width=await page.locator('#mailDefaultAddressShell').evaluate(el=>el.getBoundingClientRect().width);
if(width>392)throw new Error(`Default Address mobile panel overflows: ${width}`);

await browser.close();
console.log('Nexvary Panel Default Address Chromium UI gate: PASS');
