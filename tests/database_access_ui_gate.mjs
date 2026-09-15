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
  const overflow=await page.evaluate(()=>document.documentElement.scrollWidth>document.documentElement.clientWidth+2);
  if(overflow) throw new Error(`${label}: horizontal overflow`);
}

const browser=await chromium.launch({headless:true});
const page=await browser.newPage({viewport:{width:1600,height:1050}});
await login(page);
await page.locator('#nav a[href="#databases"]').evaluate(el=>el.click());
await page.locator('#databases.active-view').waitFor({state:'visible'});

for(const sel of ['#databaseAccessManager','#databaseProviderState','#databaseUserCount','#databaseGrantCount','#databaseUserQuota','#databaseAccessUsers','#databaseAccessGrants']){
  if(await page.locator(sel).count()!==1) throw new Error(`Database Access Manager missing ${sel}`);
}
for(const sel of ['#postgresAccessManager','#postgresProviderState','#postgresRoleCount','#postgresGrantCount','#postgresRoleQuota','#postgresAccessRoles','#postgresAccessGrants','#postgresRoleCreateForm','#postgresGrantForm','#postgresPasswordForm']){
  if(await page.locator(sel).count()!==1) throw new Error(`PostgreSQL Access Manager missing ${sel}`);
}
if(await page.locator('link[href="/static/database-access.css"]').count()!==1) throw new Error('database-access.css missing');
if(await page.locator('script[src="/static/database-access.js"]').count()!==1) throw new Error('database-access.js missing');
if(await page.locator('script[src="/static/postgres-access.js"]').count()!==1) throw new Error('postgres-access.js missing');

const maria=await page.evaluate(async()=>{const r=await fetch('/api/database-access',{headers:{Accept:'application/json'}});return {status:r.status,body:await r.json()};});
if(maria.status!==200||maria.body.ok!==true) throw new Error(`Database Access API failed: ${maria.status}`);
if(!Array.isArray(maria.body.privilege_catalog)||!maria.body.privilege_catalog.includes('SELECT')||maria.body.privilege_catalog.includes('SUPER')) throw new Error('Database privilege catalog is unsafe/incomplete');
if(!maria.body.provider||maria.body.provider.engine!=='mariadb') throw new Error('MariaDB provider posture missing');

const postgres=await page.evaluate(async()=>{const r=await fetch('/api/database-access/postgresql',{headers:{Accept:'application/json'}});return {status:r.status,body:await r.json()};});
if(postgres.status!==200||postgres.body.ok!==true) throw new Error(`PostgreSQL Access API failed: ${postgres.status}`);
const profiles=new Set(postgres.body.profiles||[]);
for(const profile of ['readonly','readwrite','developer']) if(!profiles.has(profile)) throw new Error(`PostgreSQL profile missing: ${profile}`);
for(const forbidden of ['superuser','createdb','createrole','bypassrls']) if(profiles.has(forbidden)) throw new Error(`Unsafe PostgreSQL profile exposed: ${forbidden}`);
if(!postgres.body.provider||postgres.body.provider.engine!=='postgresql') throw new Error('PostgreSQL provider posture missing');

await noOverflow(page,'database access desktop');
await page.screenshot({path:`${out}/nexvary-panel-0.7-database-access-desktop.png`,fullPage:false});
await page.locator('#postgresAccessManager').scrollIntoViewIfNeeded();
await page.waitForTimeout(120);
await page.screenshot({path:`${out}/nexvary-panel-0.7-postgresql-access-desktop.png`,fullPage:false});

const mobile=await browser.newPage({viewport:{width:390,height:844}});
await login(mobile);
await mobile.locator('#nav a[href="#databases"]').evaluate(el=>el.click());
await mobile.locator('#databases.active-view').waitFor({state:'visible'});
await noOverflow(mobile,'database access mobile');
if(!(await mobile.locator('#databaseAccessManager').isVisible())) throw new Error('Database Access Manager hidden on mobile');
if(!(await mobile.locator('#postgresAccessManager').isVisible())) throw new Error('PostgreSQL Access Manager hidden on mobile');
await mobile.locator('#postgresAccessManager').scrollIntoViewIfNeeded();
await mobile.waitForTimeout(120);
await noOverflow(mobile,'PostgreSQL access mobile');
await mobile.screenshot({path:`${out}/nexvary-panel-0.7-postgresql-access-mobile.png`,fullPage:false});

await browser.close();
console.log('Nexvary Panel MariaDB + PostgreSQL Access Manager Chromium gate: PASS');
