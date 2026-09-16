import { chromium } from 'playwright';

const base=process.env.NVP_BASE_URL||'http://127.0.0.1:8000';
const password=process.env.NVP_TEST_PASSWORD;
if(!password)throw new Error('NVP_TEST_PASSWORD is required');

const browser=await chromium.launch({headless:true});
const page=await browser.newPage({viewport:{width:1500,height:1000}});
let accounts=[];
let lastWrite=null;

await page.route('**/api/mail/dav',async route=>{
  const request=route.request();
  if(request.method()!=='GET')return route.fallback();
  return route.fulfill({status:200,contentType:'application/json',body:JSON.stringify({
    ok:true,endpoint:'/dav/',discovery:{caldav:'/.well-known/caldav',carddav:'/.well-known/carddav'},
    provider:{online:true,engine:'radicale-caldav-carddav'},
    mailboxes:[{id:7,address:'calendar@example.com',owner:'client01',feature_allowed:true}],
    accounts
  })});
});

await page.route('**/api/mail/dav/accounts',async route=>{
  const request=route.request();
  if(request.method()!=='POST')return route.fallback();
  const payload=request.postDataJSON();lastWrite={method:'POST',payload};
  const account={id:1,mailbox_id:payload.mailbox_id,username:'calendar@example.com',owner:'client01',enabled:1,created_at:1,updated_at:1};
  accounts=[account];
  return route.fulfill({status:201,contentType:'application/json',body:JSON.stringify({ok:true,account,endpoint:'/dav/'})});
});

await page.route(/\/api\/mail\/dav\/accounts\/\d+(?:\?.*)?$/,async route=>{
  const request=route.request();const url=new URL(request.url());const id=Number(url.pathname.split('/').pop());
  if(request.method()==='PUT'){
    const payload=request.postDataJSON();lastWrite={method:'PUT',id,payload};
    accounts=accounts.map(item=>item.id===id?{...item,updated_at:2}:item);
    return route.fulfill({status:200,contentType:'application/json',body:JSON.stringify({ok:true,account:accounts[0],endpoint:'/dav/'})});
  }
  if(request.method()==='DELETE'){
    lastWrite={method:'DELETE',id};accounts=[];
    return route.fulfill({status:200,contentType:'application/json',body:JSON.stringify({ok:true,id})});
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
await page.locator('#mailDavShell').waitFor({state:'visible'});

for(const selector of ['#mailDavForm','#mailDavMailbox','#mailDavPassword','#mailDavSave','#mailDavList','#mailDavEndpoint','#mailDavState']){
  if(await page.locator(selector).count()!==1)throw new Error(`Calendars & Contacts UI missing: ${selector}`);
}
await page.waitForFunction(()=>document.querySelector('#mailDavState')?.textContent?.includes('ACTIVE'),null,{timeout:10000});
if(!(await page.locator('#mailDavEndpoint').textContent()).includes('/dav/'))throw new Error('DAV endpoint not exposed');
if(await page.locator('#mailDavMailbox').inputValue()!=='7')throw new Error('DAV mailbox selector not initialized');

const secret='UiDavCredential!2026';
await page.locator('#mailDavPassword').fill(secret);
await page.locator('#mailDavForm').scrollIntoViewIfNeeded();
await page.locator('#mailDavPassword').press('Enter');
await page.waitForFunction(()=>document.querySelector('#mailDavStatus')?.textContent?.includes('تم تفعيل'),null,{timeout:10000});
if(!lastWrite||lastWrite.method!=='POST'||lastWrite.payload.mailbox_id!==7||lastWrite.payload.password!==secret)throw new Error(`DAV create payload malformed: ${JSON.stringify(lastWrite)}`);
await page.getByText('calendar@example.com',{exact:true}).waitFor({state:'visible'});
if((await page.locator('#mailDavShell').textContent()).includes(secret))throw new Error('DAV secret leaked into rendered UI');
await page.screenshot({path:'tests/artifacts/nexvary-panel-0.9-calendars-contacts-desktop.png',fullPage:true});

await page.locator('[data-dav-rotate="1"]').scrollIntoViewIfNeeded();
await page.locator('[data-dav-rotate="1"]').click();
if(!(await page.locator('#mailDavMailbox').isDisabled()))throw new Error('DAV mailbox selector must lock during credential rotation');
const rotated='UiDavRotated!2026';
await page.locator('#mailDavPassword').fill(rotated);
await page.locator('#mailDavForm').scrollIntoViewIfNeeded();
await page.locator('#mailDavPassword').press('Enter');
await page.waitForFunction(()=>document.querySelector('#mailDavStatus')?.textContent?.includes('تم تدوير'),null,{timeout:10000});
if(!lastWrite||lastWrite.method!=='PUT'||lastWrite.id!==1||lastWrite.payload.password!==rotated)throw new Error(`DAV rotate payload malformed: ${JSON.stringify(lastWrite)}`);
if((await page.locator('#mailDavShell').textContent()).includes(rotated))throw new Error('Rotated DAV secret leaked into rendered UI');

await page.locator('[data-dav-delete="1"]').scrollIntoViewIfNeeded();
await page.locator('[data-dav-delete="1"]').click();
await page.waitForFunction(()=>document.querySelector('#mailDavStatus')?.textContent?.includes('تم إلغاء'),null,{timeout:10000});
if(!lastWrite||lastWrite.method!=='DELETE'||lastWrite.id!==1)throw new Error('DAV revoke did not call item API');
if(await page.locator('[data-dav-delete="1"]').count())throw new Error('Revoked DAV account remained in inventory');

if(await page.evaluate(()=>document.documentElement.scrollWidth>document.documentElement.clientWidth+2))throw new Error('Calendars & Contacts caused desktop horizontal overflow');
await page.setViewportSize({width:390,height:844});
await page.waitForTimeout(150);
if(await page.evaluate(()=>document.documentElement.scrollWidth>document.documentElement.clientWidth+2))throw new Error('Calendars & Contacts caused mobile horizontal overflow');
const width=await page.locator('#mailDavShell').evaluate(el=>el.getBoundingClientRect().width);
if(width>392)throw new Error(`Calendars & Contacts mobile panel overflows: ${width}`);
await page.screenshot({path:'tests/artifacts/nexvary-panel-0.9-calendars-contacts-mobile.png',fullPage:true});

await browser.close();
console.log('Nexvary Panel Calendars & Contacts Chromium UI gate: PASS');
