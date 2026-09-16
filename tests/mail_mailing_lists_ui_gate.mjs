import { chromium } from 'playwright';

const base=process.env.NVP_BASE_URL||'http://127.0.0.1:8000';
const password=process.env.NVP_TEST_PASSWORD;
if(!password)throw new Error('NVP_TEST_PASSWORD is required');

const browser=await chromium.launch({headless:true});
const page=await browser.newPage({viewport:{width:1500,height:1000}});
let rows=[];
let nextId=1;
let lastWrite=null;

await page.route('**/api/mail',async route=>{
  const url=new URL(route.request().url());
  if(url.pathname!=='/api/mail')return route.fallback();
  return route.fulfill({status:200,contentType:'application/json',body:JSON.stringify({
    ok:true,domains:[],mailboxes:[],forwarders:[],mailbox_limit:20,forwarder_limit:100,
    available_domains:[{domain:'example.com',owner:'admin',email_accounts:true,email_forwarders:true,mailbox_used:0,mailbox_limit:20,forwarder_used:0,forwarder_limit:100}],
    provider:{online:true,engine:'postfix-dovecot'}
  })});
});

await page.route('**/api/mail/mailing-lists**',async route=>{
  const request=route.request();
  const url=new URL(request.url());
  if(url.pathname==='/api/mail/mailing-lists'&&request.method()==='GET'){
    return route.fulfill({status:200,contentType:'application/json',body:JSON.stringify({ok:true,mailing_lists:rows,max_members:100})});
  }
  if(url.pathname==='/api/mail/mailing-lists'&&request.method()==='POST'){
    const payload=request.postDataJSON();lastWrite={method:'POST',payload};
    const item={id:nextId++,domain:payload.domain,localpart:payload.localpart,address:`${payload.localpart}@${payload.domain}`,owner:'admin',enabled:true,members:payload.members,created_at:1,updated_at:1};
    rows=[...rows,item];
    return route.fulfill({status:201,contentType:'application/json',body:JSON.stringify({ok:true,mailing_list:item})});
  }
  const match=url.pathname.match(/^\/api\/mail\/mailing-lists\/(\d+)$/);
  if(match&&request.method()==='PUT'){
    const id=Number(match[1]);const payload=request.postDataJSON();lastWrite={method:'PUT',payload,id};
    rows=rows.map(item=>item.id===id?{...item,members:payload.members,updated_at:2}:item);
    return route.fulfill({status:200,contentType:'application/json',body:JSON.stringify({ok:true,mailing_list:rows.find(item=>item.id===id)})});
  }
  if(match&&request.method()==='DELETE'){
    const id=Number(match[1]);lastWrite={method:'DELETE',id};rows=rows.filter(item=>item.id!==id);
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
await page.locator('#mailingListShell').waitFor({state:'visible'});

for(const selector of ['#mailingListForm','#mailingListDomain','#mailingListLocalpart','#mailingListMembers','#mailingListSave','#mailingListInventory','#mailingListStatus']){
  if(await page.locator(selector).count()!==1)throw new Error(`Mailing List UI missing: ${selector}`);
}
await page.waitForFunction(()=>document.querySelector('#mailingListState')?.textContent?.includes('ACTIVE'),null,{timeout:10000});
if(await page.locator('#mailingListDomain').inputValue()!=='example.com')throw new Error('Mailing List did not inherit scoped domain');

await page.locator('#mailingListLocalpart').fill('team');
await page.locator('#mailingListMembers').fill('Alice@external.example\nbob@external.example');
await page.locator('#mailingListSave').click();
await page.waitForFunction(()=>document.querySelector('#mailingListStatus')?.textContent?.includes('تم إنشاء Mailing List'),null,{timeout:10000});
if(!lastWrite||lastWrite.method!=='POST')throw new Error('Mailing List create did not call API');
if(lastWrite.payload.domain!=='example.com'||lastWrite.payload.localpart!=='team')throw new Error(`Mailing List create payload malformed: ${JSON.stringify(lastWrite)}`);
if(JSON.stringify(lastWrite.payload.members)!==JSON.stringify(['alice@external.example','bob@external.example']))throw new Error(`Mailing List members were not normalized: ${JSON.stringify(lastWrite.payload.members)}`);
await page.getByText('team@example.com',{exact:true}).waitFor({state:'visible'});

await page.locator('[data-list-edit="1"]').click();
if(!(await page.locator('#mailingListDomain').isDisabled()))throw new Error('Domain must remain immutable during Mailing List member edit');
await page.locator('#mailingListMembers').fill('alice@external.example\ncarol@external.example');
await page.locator('#mailingListSave').click();
await page.waitForFunction(()=>document.querySelector('#mailingListStatus')?.textContent?.includes('تم تحديث Mailing List'),null,{timeout:10000});
if(!lastWrite||lastWrite.method!=='PUT'||lastWrite.id!==1)throw new Error('Mailing List update did not call item API');
if(JSON.stringify(lastWrite.payload.members)!==JSON.stringify(['alice@external.example','carol@external.example']))throw new Error('Mailing List update members malformed');

await page.locator('[data-list-delete="1"]').click();
await page.waitForFunction(()=>document.querySelector('#mailingListStatus')?.textContent?.includes('تم حذف Mailing List'),null,{timeout:10000});
if(!lastWrite||lastWrite.method!=='DELETE'||lastWrite.id!==1)throw new Error('Mailing List delete did not call item API');
if(await page.getByText('team@example.com',{exact:true}).count())throw new Error('Deleted Mailing List remained in inventory');

if(await page.evaluate(()=>document.documentElement.scrollWidth>document.documentElement.clientWidth+2))throw new Error('Mailing List UI caused desktop horizontal overflow');
await page.setViewportSize({width:390,height:844});
await page.waitForTimeout(150);
if(await page.evaluate(()=>document.documentElement.scrollWidth>document.documentElement.clientWidth+2))throw new Error('Mailing List UI caused mobile horizontal overflow');
const width=await page.locator('#mailingListShell').evaluate(el=>el.getBoundingClientRect().width);
if(width>392)throw new Error(`Mailing List mobile panel overflows: ${width}`);

await browser.close();
console.log('Nexvary Panel Mailing Lists Chromium UI gate: PASS');
