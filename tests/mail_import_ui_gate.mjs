import { chromium } from 'playwright';

const base=process.env.NVP_BASE_URL||'http://127.0.0.1:8000';
const password=process.env.NVP_TEST_PASSWORD;
if(!password)throw new Error('NVP_TEST_PASSWORD is required');

const browser=await chromium.launch({headless:true});
const page=await browser.newPage({viewport:{width:1500,height:1000}});
let importPayload=null;

await page.route('**/api/mail',async route=>{
  const url=new URL(route.request().url());
  if(url.pathname!=='/api/mail')return route.continue();
  return route.fulfill({
    status:200,
    contentType:'application/json',
    body:JSON.stringify({
      ok:true,
      domains:[],mailboxes:[],forwarders:[],mailbox_limit:20,forwarder_limit:100,
      available_domains:[{domain:'example.com',owner:'admin',email_accounts:true,email_forwarders:true,mailbox_used:0,mailbox_limit:20,forwarder_used:0,forwarder_limit:100}],
      provider:{online:true,engine:'postfix-dovecot'}
    })
  });
});
await page.route('**/api/mail/import',async route=>{
  importPayload=route.request().postDataJSON();
  return route.fulfill({status:201,contentType:'application/json',body:JSON.stringify({ok:true,domain:'example.com',owner:'admin',imported:2,mailboxes:1,forwarders:1})});
});

await page.goto(`${base}/login`,{waitUntil:'networkidle'});
await page.locator('input[name="username"]').fill('admin');
await page.locator('input[name="password"]').fill(password);
await page.locator('button').filter({hasText:'دخول آمن'}).click();
await page.waitForURL(url=>url.pathname==='/'||url.pathname==='',{timeout:15000});
await page.locator('#nav a[href="#mail"]').click();
await page.locator('#mail.active-view').waitFor({state:'visible'});

for(const selector of ['.mail-import-shell','#mailImportForm','#mailImportDomain','#mailImportRows','#mailImportSubmit','#mailImportStatus']){
  if(await page.locator(selector).count()!==1)throw new Error(`Address Importer UI missing: ${selector}`);
}
await page.waitForFunction(()=>document.querySelector('#mailProviderState')?.textContent?.trim()==='ONLINE',null,{timeout:10000});
if(await page.locator('#mailImportDomain').inputValue()!=='example.com')throw new Error('Address Importer did not inherit a scoped mail domain');

await page.locator('#mailImportRows').fill('mailbox,alice,Nexvary-Test-Password-2026!,1024\nforwarder,sales,sales@external.example');
await page.locator('#mailImportSubmit').click();
await page.waitForFunction(()=>document.querySelector('#mailImportStatus')?.textContent?.includes('تم استيراد 2 عنوان'),null,{timeout:10000});
if(!importPayload)throw new Error('Address Importer submit did not call /api/mail/import');
if(importPayload.domain!=='example.com'||!Array.isArray(importPayload.entries)||importPayload.entries.length!==2)throw new Error(`Address Importer payload malformed: ${JSON.stringify(importPayload)}`);
if(importPayload.entries[0].kind!=='mailbox'||importPayload.entries[0].quota_mb!==1024)throw new Error('Mailbox import row was not normalized correctly');
if(importPayload.entries[1].kind!=='forwarder'||importPayload.entries[1].destination!=='sales@external.example')throw new Error('Forwarder import row was not normalized correctly');
if((await page.locator('#mailImportRows').inputValue())!=='')throw new Error('Importer secrets were not cleared after success');
if(await page.evaluate(()=>document.documentElement.scrollWidth>document.documentElement.clientWidth+2))throw new Error('Address Importer caused desktop horizontal overflow');

await page.setViewportSize({width:390,height:844});
await page.waitForTimeout(120);
if(await page.evaluate(()=>document.documentElement.scrollWidth>document.documentElement.clientWidth+2))throw new Error('Address Importer caused mobile horizontal overflow');
const width=await page.locator('.mail-import-shell').evaluate(el=>el.getBoundingClientRect().width);
if(width>392)throw new Error(`Address Importer mobile panel overflows: ${width}`);

await browser.close();
console.log('Nexvary Panel Address Importer Chromium wiring gate: PASS');
