import { chromium } from 'playwright';
import fs from 'node:fs';

const base=process.env.NVP_BASE_URL||'http://127.0.0.1:8000';
const password=process.env.NVP_TEST_PASSWORD;
if(!password) throw new Error('NVP_TEST_PASSWORD is required');
const out=process.env.NVP_SCREENSHOT_DIR||'tests/artifacts';
fs.mkdirSync(out,{recursive:true});

async function login(page){
  await page.goto(`${base}/login`,{waitUntil:'networkidle'});
  await page.locator('input[name="username"]').fill('admin');
  await page.locator('input[name="password"]').fill(password);
  await page.locator('button').filter({hasText:'دخول آمن'}).click();
  await page.waitForURL(url=>url.pathname==='/'||url.pathname==='',{timeout:15000});
  await page.locator('#dashboard.active-view').waitFor({state:'visible'});
}
async function noOverflow(page,label){
  if(await page.evaluate(()=>document.documentElement.scrollWidth>document.documentElement.clientWidth+2)) throw new Error(`${label}: horizontal overflow`);
}
async function open(page){
  await page.locator('#nav a[href="#schedules"]').evaluate(el=>el.click());
  await page.locator('#schedules.active-view').waitFor({state:'visible'});
}

const browser=await chromium.launch({headless:true});
const page=await browser.newPage({viewport:{width:1600,height:1050}});
await login(page);
if(await page.locator('link[href="/static/scheduled-tasks.css"]').count()!==1) throw new Error('Scheduled Tasks stylesheet missing');
if(await page.locator('script[src="/static/scheduled-tasks.js"]').count()!==1) throw new Error('Scheduled Tasks client missing');
await open(page);
if(await page.locator('#schedules .workspace-hero').count()!==1) throw new Error('Scheduled Tasks royal hero missing');
if(await page.locator('#scheduleForm').count()!==1) throw new Error('Scheduled Tasks creation form missing');
if(await page.locator('#scheduleTaskType option').count()<2) throw new Error('Allowlisted scheduled task presets missing');
if(await page.locator('#scheduleCadence option').count()!==3) throw new Error('Hourly/daily/weekly cadence presets missing');
const api=await page.evaluate(async()=>{const r=await fetch('/api/schedules');return{status:r.status,body:await r.json()};});
if(api.status!==200||!api.body.ok) throw new Error(`Scheduled Tasks API unavailable: ${api.status}`);
if(Object.keys(api.body.task_types||{}).sort().join(',')!=='backup_site,git_deploy') throw new Error('Scheduled Tasks API exposed unexpected task types');
if(!Number.isInteger(api.body.max_cron_jobs)||api.body.max_cron_jobs<1) throw new Error('Scheduled Tasks quota missing');
await noOverflow(page,'Scheduled Tasks desktop');
await page.screenshot({path:`${out}/nexvary-panel-0.7-scheduled-tasks-desktop.png`,fullPage:false});

const mobile=await browser.newPage({viewport:{width:390,height:844}});
await login(mobile);await open(mobile);await noOverflow(mobile,'Scheduled Tasks mobile');
await mobile.screenshot({path:`${out}/nexvary-panel-0.7-scheduled-tasks-mobile.png`,fullPage:false});
await browser.close();
console.log('Nexvary Panel Scheduled Tasks Chromium Gate: PASS');
