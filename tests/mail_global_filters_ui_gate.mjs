import { chromium } from 'playwright';

const base=process.env.NVP_BASE_URL||'http://127.0.0.1:8000';
const password=process.env.NVP_TEST_PASSWORD;
if(!password)throw new Error('NVP_TEST_PASSWORD is required');

const browser=await chromium.launch({headless:true});
const page=await browser.newPage({viewport:{width:1500,height:1000}});
const pageErrors=[];
page.on('pageerror',error=>pageErrors.push(String(error?.stack||error?.message||error)));
let rows=[];
let nextId=1;
let lastWrite=null;

await page.route('**/api/mail',async route=>{
  const url=new URL(route.request().url());
  if(url.pathname!=='/api/mail')return route.fallback();
  return route.fulfill({status:200,contentType:'application/json',body:JSON.stringify({
    ok:true,domains:[],mailboxes:[],forwarders:[],mailbox_limit:20,forwarder_limit:100,
    available_domains:[
      {domain:'example.com',owner:'client01',email_accounts:true,email_forwarders:true,mailbox_used:2,mailbox_limit:20,forwarder_used:0,forwarder_limit:100},
      {domain:'second.example',owner:'client01',email_accounts:true,email_forwarders:true,mailbox_used:2,mailbox_limit:20,forwarder_used:0,forwarder_limit:100}
    ],
    provider:{online:true,engine:'postfix-dovecot'}
  })});
});

await page.route('**/api/mail/global-filters',async route=>{
  const request=route.request();
  const url=new URL(request.url());
  if(url.pathname!=='/api/mail/global-filters')return route.fallback();
  if(request.method()==='GET'){
    return route.fulfill({status:200,contentType:'application/json',body:JSON.stringify({
      ok:true,owner:'client01',scope:'account',selected_domain:url.searchParams.get('domain')||'example.com',
      owner_domains:['example.com','second.example'],feature_allowed:true,filters:rows,mailbox_count:2,max_filters:30
    })});
  }
  if(request.method()==='POST'){
    const payload=request.postDataJSON();lastWrite={method:'POST',payload};
    const item={id:nextId++,owner:'client01',...payload,created_at:1,updated_at:1,enabled:payload.enabled?1:0};
    rows=[...rows,item];
    return route.fulfill({status:201,contentType:'application/json',body:JSON.stringify({ok:true,filter_id:item.id,owner:'client01',filters:rows,mailbox_count:2})});
  }
  return route.fallback();
});

await page.route('**/api/mail/global-filters/*',async route=>{
  const request=route.request();
  const url=new URL(request.url());
  const prefix='/api/mail/global-filters/';
  if(!url.pathname.startsWith(prefix))return route.fallback();
  const rawId=url.pathname.slice(prefix.length);
  const id=Number(rawId);
  if(!/^\d+$/.test(rawId)||!Number.isInteger(id)||id<1)return route.fallback();
  if(request.method()==='PUT'){
    const payload=request.postDataJSON();lastWrite={method:'PUT',id,payload};
    rows=rows.map(item=>item.id===id?{...item,...payload,enabled:payload.enabled?1:0,updated_at:2}:item);
    return route.fulfill({status:200,contentType:'application/json',body:JSON.stringify({ok:true,filter_id:id,owner:'client01',filters:rows,mailbox_count:2})});
  }
  if(request.method()==='DELETE'){
    lastWrite={method:'DELETE',id};rows=rows.filter(item=>item.id!==id);
    return route.fulfill({status:200,contentType:'application/json',body:JSON.stringify({ok:true,id,owner:'client01',filters:rows,mailbox_count:2})});
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
await page.locator('#mailGlobalFilterShell').waitFor({state:'visible'});

for(const selector of ['#mailGlobalFilterForm','#mailGlobalFilterDomain','#mailGlobalFilterField','#mailGlobalFilterPattern','#mailGlobalFilterAction','#mailGlobalFilterDestination','#mailGlobalFilterSave','#mailGlobalFilterList','#mailGlobalFilterStatus']){
  if(await page.locator(selector).count()!==1)throw new Error(`Global Email Filters UI missing: ${selector}`);
}
await page.waitForFunction(()=>document.querySelector('#mailGlobalFilterState')?.textContent?.includes('ACTIVE'),null,{timeout:10000});
if(await page.locator('#mailGlobalFilterDomain').inputValue()!=='example.com')throw new Error('Global filter workspace did not inherit scoped domain');
if(!(await page.locator('#mailGlobalFilterScope').textContent()).includes('client01'))throw new Error('Global filter account scope not exposed');

await page.locator('#mailGlobalFilterField').selectOption('header');
await page.locator('#mailGlobalFilterHeader').fill('X-Campaign-ID');
await page.locator('#mailGlobalFilterPattern').fill('vip');
await page.locator('#mailGlobalFilterAction').selectOption('fileinto');
await page.locator('#mailGlobalFilterDestination').fill('Global');
await page.locator('#mailGlobalFilterSave').click();
await page.waitForFunction(()=>document.querySelector('#mailGlobalFilterStatus')?.textContent?.includes('تم إنشاء Global Filter'),null,{timeout:10000});
if(!lastWrite||lastWrite.method!=='POST')throw new Error('Global filter create did not call API');
if(lastWrite.payload.field!=='header'||lastWrite.payload.header_name!=='X-Campaign-ID'||lastWrite.payload.destination!=='Global')throw new Error(`Global filter create payload malformed: ${JSON.stringify(lastWrite)}`);
await page.getByText('X-Campaign-ID contains “vip”',{exact:true}).waitFor({state:'visible'});

await page.locator('[data-global-filter-edit="1"]').click();
if(!(await page.locator('#mailGlobalFilterDomain').isDisabled()))throw new Error('Account selector must be immutable during global filter edit');
await page.locator('#mailGlobalFilterField').selectOption('subject');
await page.locator('#mailGlobalFilterPattern').fill('billing');
await page.locator('#mailGlobalFilterAction').selectOption('redirect');
await page.locator('#mailGlobalFilterDestination').fill('archive@external.example');
const updateResponse=page.waitForResponse(response=>new URL(response.url()).pathname==='/api/mail/global-filters/1'&&response.request().method()==='PUT',{timeout:10000});
await page.locator('#mailGlobalFilterSave').click();
await updateResponse;
if(!lastWrite||lastWrite.method!=='PUT'||lastWrite.id!==1)throw new Error(`Global filter update did not call item API: ${JSON.stringify(lastWrite)}`);
if(lastWrite.payload.field!=='subject'||lastWrite.payload.pattern!=='billing'||lastWrite.payload.destination!=='archive@external.example')throw new Error(`Global filter update payload malformed: ${JSON.stringify(lastWrite)}`);
await page.waitForFunction(()=>{
  const edit=document.querySelector('[data-global-filter-edit="1"]');
  const text=edit?.closest('.mail-row')?.textContent||'';
  return text.includes('subject')&&text.includes('billing')&&text.includes('archive@external.example');
},null,{timeout:10000});
const updatedStatus=await page.locator('#mailGlobalFilterStatus').textContent();
if(!updatedStatus?.includes('تم تحديث Global Filter'))throw new Error(`Global filter update status missing after rendered update: ${updatedStatus}`);

lastWrite=null;
await page.locator('[data-global-filter-edit="1"]').click();
await page.locator('#mailGlobalFilterAction').selectOption('redirect');
await page.locator('#mailGlobalFilterDestination').fill('loop@second.example');
await page.locator('#mailGlobalFilterSave').click();
await page.waitForFunction(()=>document.querySelector('#mailGlobalFilterStatus')?.textContent?.includes('داخل حساب الاستضافة نفسه'),null,{timeout:10000});
if(lastWrite!==null)throw new Error('Same-account redirect loop reached API despite client guard');
await page.locator('#mailGlobalFilterCancel').click();

await page.locator('[data-global-filter-delete="1"]').click();
await page.waitForFunction(()=>document.querySelector('#mailGlobalFilterStatus')?.textContent?.includes('تم حذف Global Filter'),null,{timeout:10000});
if(!lastWrite||lastWrite.method!=='DELETE'||lastWrite.id!==1)throw new Error('Global filter delete did not call item API');
if(await page.locator('[data-global-filter-edit="1"]').count())throw new Error('Deleted Global Filter remained in inventory');
if(pageErrors.length)throw new Error(`Global Email Filters emitted page errors: ${JSON.stringify(pageErrors)}`);

if(await page.evaluate(()=>document.documentElement.scrollWidth>document.documentElement.clientWidth+2))throw new Error('Global Email Filters UI caused desktop horizontal overflow');
await page.setViewportSize({width:390,height:844});
await page.waitForTimeout(150);
if(await page.evaluate(()=>document.documentElement.scrollWidth>document.documentElement.clientWidth+2))throw new Error('Global Email Filters UI caused mobile horizontal overflow');
const width=await page.locator('#mailGlobalFilterShell').evaluate(el=>el.getBoundingClientRect().width);
if(width>392)throw new Error(`Global Email Filters mobile panel overflows: ${width}`);

await browser.close();
console.log('Nexvary Panel Global Email Filters Chromium UI gate: PASS');
