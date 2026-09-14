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
}
async function noOverflow(page,label){
  const bad=await page.evaluate(()=>document.documentElement.scrollWidth>document.documentElement.clientWidth+2);
  if(bad) throw new Error(`${label}: horizontal overflow`);
}

const browser=await chromium.launch({headless:true});
const page=await browser.newPage({viewport:{width:1600,height:1050}});
await login(page);
await page.locator('#nav a[href="#databases"]').evaluate(el=>el.click());
await page.locator('#databases.active-view').waitFor({state:'visible'});
const manager=page.locator('#databaseLifecycleManager');
if(await manager.count()!==1||!(await manager.isVisible())) throw new Error('Managed Database Lifecycle workspace missing');
for(const id of ['databaseSnapshotCount','databaseSnapshotQuota','databaseSnapshotForm','databaseSnapshotEngine','databaseSnapshotDb','databaseSnapshotList']){
  if(await manager.locator(`#${id}`).count()!==1) throw new Error(`Database Lifecycle control missing: ${id}`);
}
if(await manager.locator('input[type="file"]').count()) throw new Error('Database Lifecycle must not expose arbitrary upload input');
const text=(await manager.innerText()).toLowerCase();
if(!text.includes('rollback')||!text.includes('path input')) throw new Error('Database Lifecycle safety contract not visible');
const api=await page.evaluate(async()=>{const r=await fetch('/api/database-lifecycle',{headers:{Accept:'application/json'}});return {status:r.status,body:await r.json()};});
if(api.status!==200||api.body?.ok!==true) throw new Error(`Database Lifecycle API unavailable: ${api.status}`);
if(api.body?.policy?.arbitrary_paths!==false||api.body?.policy?.restore_safety_snapshot!==true) throw new Error('Database Lifecycle API safety policy mismatch');
await noOverflow(page,'database lifecycle desktop');
await page.screenshot({path:`${out}/nexvary-panel-0.7-database-lifecycle-desktop.png`,fullPage:false});

const mobile=await browser.newPage({viewport:{width:390,height:844}});
await login(mobile);
await mobile.locator('#nav a[href="#databases"]').evaluate(el=>el.click());
await mobile.locator('#databases.active-view').waitFor({state:'visible'});
if(!(await mobile.locator('#databaseLifecycleManager').isVisible())) throw new Error('Database Lifecycle mobile workspace missing');
await noOverflow(mobile,'database lifecycle mobile');
await mobile.screenshot({path:`${out}/nexvary-panel-0.7-database-lifecycle-mobile.png`,fullPage:false});
await browser.close();
console.log('Nexvary Panel Database Lifecycle Chromium gate: PASS');
