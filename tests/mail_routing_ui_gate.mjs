import { chromium } from 'playwright';

const base=process.env.NVP_BASE_URL||'http://127.0.0.1:8000';
const password=process.env.NVP_TEST_PASSWORD;
if(!password)throw new Error('NVP_TEST_PASSWORD is required');

const browser=await chromium.launch({headless:true});
const page=await browser.newPage({viewport:{width:1500,height:1000}});
let savedPayload=null;
let currentMode='local';
let localResources={mailboxes:0,forwarders:0,catchall_forward:false};

await page.route('**/api/mail',async route=>{
  const url=new URL(route.request().url());
  if(url.pathname!=='/api/mail')return route.fallback();
  return route.fulfill({status:200,contentType:'application/json',body:JSON.stringify({
    ok:true,domains:[],mailboxes:[],forwarders:[],mailbox_limit:20,forwarder_limit:100,
    available_domains:[{domain:'example.com',owner:'admin',email_accounts:true,email_forwarders:true,mailbox_used:0,mailbox_limit:20,forwarder_used:0,forwarder_limit:100}],
    provider:{online:true,engine:'postfix-dovecot'}
  })});
});
await page.route('**/api/mail/routing**',async route=>{
  const request=route.request();
  if(request.method()==='GET'){
    return route.fulfill({status:200,contentType:'application/json',body:JSON.stringify({
      ok:true,feature_allowed:true,
      routing:{domain:'example.com',mode:currentMode,owner:'admin',updated_at:0},
      local_resources:localResources
    })});
  }
  if(request.method()==='PUT'){
    savedPayload=request.postDataJSON();
    currentMode=savedPayload.mode;
    return route.fulfill({status:200,contentType:'application/json',body:JSON.stringify({
      ok:true,routing:{domain:'example.com',mode:currentMode,owner:'admin',updated_at:1}
    })});
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
await page.locator('#mailRoutingShell').waitFor({state:'visible'});

for(const selector of ['#mailRoutingForm','#mailRoutingDomain','#mailRoutingMode','#mailRoutingResourceState','#mailRoutingSave','#mailRoutingStatus']){
  if(await page.locator(selector).count()!==1)throw new Error(`Email Routing UI missing: ${selector}`);
}
await page.waitForFunction(()=>document.querySelector('#mailRoutingFeatureState')?.textContent?.includes('ACTIVE'),null,{timeout:10000});
if(await page.locator('#mailRoutingDomain').inputValue()!=='example.com')throw new Error('Email Routing did not inherit scoped domain');
if(await page.locator('#mailRoutingMode').inputValue()!=='local')throw new Error('Email Routing safe local baseline not loaded');
if(await page.locator('#mailRoutingSave').isDisabled())throw new Error('Local routing save should be available when provider and policy are active');

await page.locator('#mailRoutingMode').selectOption('remote');
if(await page.locator('#mailRoutingSave').isDisabled())throw new Error('Remote routing should be available with zero local resources');
await page.locator('#mailRoutingSave').click();
await page.waitForFunction(()=>document.querySelector('#mailRoutingStatus')?.textContent?.includes('Remote Mail Exchanger'),null,{timeout:10000});
if(!savedPayload)throw new Error('Email Routing save did not call provider-backed control-plane API');
if(savedPayload.domain!=='example.com'||savedPayload.mode!=='remote')throw new Error(`Email Routing payload malformed: ${JSON.stringify(savedPayload)}`);

currentMode='local';
localResources={mailboxes:1,forwarders:0,catchall_forward:false};
await page.locator('#mailRoutingDomain').dispatchEvent('change');
await page.waitForFunction(()=>document.querySelector('#mailRoutingResourceState')?.textContent?.includes('Mailboxes 1'),null,{timeout:10000});
await page.locator('#mailRoutingMode').selectOption('remote');
if(!(await page.locator('#mailRoutingSave').isDisabled()))throw new Error('Remote routing must be blocked while local mailboxes exist');
if(await page.evaluate(()=>document.documentElement.scrollWidth>document.documentElement.clientWidth+2))throw new Error('Email Routing UI caused desktop horizontal overflow');

await page.setViewportSize({width:390,height:844});
await page.waitForTimeout(120);
if(await page.evaluate(()=>document.documentElement.scrollWidth>document.documentElement.clientWidth+2))throw new Error('Email Routing UI caused mobile horizontal overflow');
const width=await page.locator('#mailRoutingShell').evaluate(el=>el.getBoundingClientRect().width);
if(width>392)throw new Error(`Email Routing mobile panel overflows: ${width}`);

await browser.close();
console.log('Nexvary Panel Email Routing Chromium UI gate: PASS');
