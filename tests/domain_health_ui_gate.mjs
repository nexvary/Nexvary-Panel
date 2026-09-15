import { chromium } from 'playwright';
import fs from 'node:fs';

const base=process.env.NVP_BASE_URL||'http://127.0.0.1:8000';
const password=process.env.NVP_TEST_PASSWORD;
if(!password)throw new Error('NVP_TEST_PASSWORD is required');
const out=process.env.NVP_SCREENSHOT_DIR||'tests/artifacts';
fs.mkdirSync(out,{recursive:true});

const domains=[
  {domain:'healthy.example.test',owner:'admin',kind:'php',score:96,grade:'A',recommendations:[],checks:[{id:'site-enabled',label:'Managed site is enabled',ok:true,weight:20,detail:'ok',view:'sites'}],domain_lifecycle:{aliases:0},dns:{bound:true,provider:'cloudflare',pending_previews:0,dnssec:{supported_by_bound_provider:true}},ssl:{auto_renew:true},mail:{enabled:false}},
  {domain:'review.example.test',owner:'client02',kind:'php',score:72,grade:'C',recommendations:[{id:'ssl-automation',message:'فعّل AutoSSL',view:'advancedops'}],checks:[{id:'ssl-automation',label:'Certificate lifecycle managed',ok:false,weight:20,detail:'فعّل AutoSSL',view:'advancedops'}],domain_lifecycle:{aliases:1},dns:{bound:true,provider:'powerdns',pending_previews:1,dnssec:{supported_by_bound_provider:true}},ssl:{auto_renew:false},mail:{enabled:true}},
  {domain:'critical.example.test',owner:'client01',kind:'php',score:43,grade:'D',recommendations:[{id:'dns-provider',message:'لا يوجد DNS provider',view:'advancedops'},{id:'ssl-automation',message:'فعّل AutoSSL',view:'advancedops'}],checks:[{id:'dns-provider',label:'DNS provider binding',ok:false,weight:20,detail:'لا يوجد DNS provider',view:'advancedops'},{id:'ssl-automation',label:'Certificate lifecycle managed',ok:false,weight:20,detail:'فعّل AutoSSL',view:'advancedops'}],domain_lifecycle:{aliases:0},dns:{bound:false,provider:'',pending_previews:0,dnssec:{supported_by_bound_provider:false}},ssl:{auto_renew:false},mail:{enabled:false}}
];

const browser=await chromium.launch({headless:true});
const page=await browser.newPage({viewport:{width:1600,height:1050}});
await page.route('**/api/domain-health*',async route=>{
  const url=new URL(route.request().url());
  const requested=url.searchParams.get('domain');
  if(requested){
    const readiness=domains.find(row=>row.domain===requested);
    await route.fulfill({status:readiness?200:404,contentType:'application/json',body:JSON.stringify(readiness?{ok:true,readiness}:{ok:false,error:'not found'})});
    return;
  }
  await route.fulfill({status:200,contentType:'application/json',body:JSON.stringify({ok:true,domains,count:domains.length})});
});

await page.goto(`${base}/login`,{waitUntil:'networkidle'});
await page.locator('input[name="username"]').fill('admin');
await page.locator('input[name="password"]').fill(password);
await page.locator('button').filter({hasText:'دخول آمن'}).click();
await page.waitForURL(url=>url.pathname==='/'||url.pathname==='',{timeout:15000});
await page.locator('#nav a[href="#advancedops"]').click();
await page.locator('#advancedops.active-view').waitFor({state:'visible'});

for(const sel of ['#advDomainReadinessCard','#domainReadinessDomain','#domainReadinessRefresh','#domainReadinessScore','#domainReadinessGrade','#domainReadinessMeta','#domainReadinessChecks','#domainReadinessFleet','#domainFleetTotal','#domainFleetA','#domainFleetAttention','#domainFleetWorst','#domainFleetProblems']){
  if(await page.locator(sel).count()!==1)throw new Error(`Domain Readiness UI control missing: ${sel}`);
}
if(await page.locator('script[src="/static/domain-readiness.js"]').count()!==1)throw new Error('Domain Readiness script missing');
await page.waitForFunction(()=>document.querySelector('#domainFleetTotal')?.textContent==='3',{timeout:10000});
if((await page.locator('#domainFleetA').innerText()).trim()!=='1')throw new Error('Fleet A-grade count is wrong');
if((await page.locator('#domainFleetAttention').innerText()).trim()!=='2')throw new Error('Fleet attention count is wrong');
if((await page.locator('#domainFleetWorst').innerText()).trim()!=='43%')throw new Error('Fleet worst score is wrong');
if((await page.locator('#domainReadinessDomain').inputValue())!=='critical.example.test')throw new Error('Fleet did not select the worst domain first');
if((await page.locator('#domainReadinessScore').innerText()).trim()!=='43%')throw new Error('Worst domain readiness was not rendered');
const firstProblem=(await page.locator('#domainFleetProblems .adv-row').first().innerText());
if(!firstProblem.includes('critical.example.test')||!firstProblem.includes('43%'))throw new Error('Problem-first Fleet ordering is wrong');
const text=await page.locator('#advDomainReadinessCard').innerText();
for(const marker of ['DOMAIN READINESS','Control-plane Health','UNIFIED HEALTH','READINESS','GRADE','DOMAINS','A GRADE','ATTENTION','WORST']){
  if(!text.includes(marker))throw new Error(`Domain Readiness marker missing: ${marker}`);
}
if(await page.evaluate(()=>document.documentElement.scrollWidth>document.documentElement.clientWidth+2))throw new Error('Domain Readiness desktop horizontal overflow');
await page.screenshot({path:`${out}/nexvary-panel-0.7-domain-readiness-desktop.png`,fullPage:true});

await page.setViewportSize({width:390,height:844});
await page.waitForTimeout(300);
if((await page.locator('#domainFleetWorst').innerText()).trim()!=='43%')throw new Error('Fleet summary disappeared on mobile');
if(await page.evaluate(()=>document.documentElement.scrollWidth>document.documentElement.clientWidth+2))throw new Error('Domain Readiness mobile horizontal overflow');
await page.screenshot({path:`${out}/nexvary-panel-0.7-domain-readiness-mobile.png`,fullPage:true});

await browser.close();
console.log('Nexvary Panel problem-first Fleet Domain Readiness Chromium Gate: PASS');
