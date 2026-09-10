import { chromium } from 'playwright';
import fs from 'node:fs';

const base=process.env.NVP_BASE_URL||'http://127.0.0.1:8000';
const password=process.env.NVP_TEST_PASSWORD;
if(!password)throw new Error('NVP_TEST_PASSWORD is required');
const out=process.env.NVP_SCREENSHOT_DIR||'tests/artifacts';
fs.mkdirSync(out,{recursive:true});

const browser=await chromium.launch({headless:true});
const page=await browser.newPage({viewport:{width:1600,height:1000}});
await page.goto(`${base}/login`,{waitUntil:'networkidle'});
await page.locator('input[name="username"]').fill('admin');
await page.locator('input[name="password"]').fill(password);
await page.locator('button').filter({hasText:'دخول آمن'}).click();
await page.waitForURL(url=>url.pathname==='/'||url.pathname==='',{timeout:15000});

const dashboard=page.locator('#dashboard');
if(await dashboard.count()!==1)throw new Error('Reference dashboard missing');
if(!(await dashboard.isVisible()))throw new Error('Reference dashboard is not the active workspace');
if(await page.locator('.reference-dashboard').count()!==1)throw new Error('Reference dashboard class missing');
if(await page.locator('.ref-metric-card').count()!==6)throw new Error('Reference dashboard must expose six KPI cards');
if(await page.locator('.ref-quick-grid .quick-action').count()!==6)throw new Error('Reference dashboard must expose six quick actions');
if(await page.locator('.ref-trust-list .trust-check').count()!==7)throw new Error('Trust Center must expose seven checks');
if(await page.locator('.basmala-seal strong').innerText()!=='بِسْمِ اللهِ الرَّحْمٰنِ الرَّحِيمِ')throw new Error('Approved Basmala text changed');
if(await page.locator('.brand-image img').count()!==1)throw new Error('Nexvary brand image missing');

const metricTexts=await page.locator('.ref-metric-card').allInnerTexts();
for(const required of ['المواقع','قواعد البيانات','CPU','الذاكرة','التخزين','الثقة']){
  if(!metricTexts.some(x=>x.includes(required)))throw new Error(`Missing KPI: ${required}`);
}

const quickTargets=await page.locator('.ref-quick-grid .quick-action').evaluateAll(nodes=>nodes.map(n=>n.getAttribute('data-open-view')));
for(const target of quickTargets){
  if(!target||await page.locator(`#${target}`).count()!==1)throw new Error(`Dead quick action target: ${target}`);
}
const trustFixes=page.locator('.ref-trust-list .trust-check[data-open-view]');
if(await trustFixes.count()!==7)throw new Error('Trust Center must expose seven guided paths');
for(const target of await trustFixes.evaluateAll(nodes=>nodes.map(n=>n.getAttribute('data-open-view')))){
  if(!target||await page.locator(`#${target}`).count()!==1)throw new Error(`Dead trust path: ${target}`);
}

const nav=page.locator('#nav a[href="#sites"]');
const navStyle=await nav.evaluate(el=>{const s=getComputedStyle(el);return{color:s.color,family:s.fontFamily,shadow:s.textShadow};});
if(!navStyle.family.includes('Noto Kufi Arabic'))throw new Error(`Kufi font stack missing: ${navStyle.family}`);
if(navStyle.color!=='rgb(55, 255, 154)')throw new Error(`Sidebar text is not electric green: ${navStyle.color}`);
if(!navStyle.shadow||navStyle.shadow==='none')throw new Error('Sidebar electric glow missing');

const expectedOrder=['dashboard','hosting','accounts','mail','transfers','advancedops','sites','webtools','schedules','databases','files','security','backups'];
const firstLinks=await page.locator('#nav a').evaluateAll((nodes,count)=>nodes.slice(0,count).map(n=>n.getAttribute('href')?.replace('#','')),expectedOrder.length);
if(JSON.stringify(firstLinks)!==JSON.stringify(expectedOrder))throw new Error(`Sidebar primary order mismatch: ${firstLinks.join(',')}`);
const iconColors=await page.evaluate(()=>Array.from(document.querySelectorAll('#nav a .ui-icon')).map(el=>getComputedStyle(el).color));
if(new Set(iconColors).size<8)throw new Error(`Sidebar icon palette too limited: ${new Set(iconColors).size}`);

if(await page.evaluate(()=>document.documentElement.scrollWidth>document.documentElement.clientWidth+2))throw new Error('Reference dashboard has horizontal overflow');
await page.screenshot({path:`${out}/nexvary-panel-0.7-approved-dashboard-desktop.png`,fullPage:true});

await page.locator('#nav a[href="#services"]').click();
await page.locator('#services.active-view').waitFor({state:'visible'});
if(await page.locator('#services .security-intelligence').count()!==1)throw new Error('Security Intelligence panel missing');
if(await page.locator('#services .defense-provider').count()!==2)throw new Error('CrowdSec/Fail2Ban cards missing');
await page.screenshot({path:`${out}/nexvary-panel-0.7-security-intelligence-desktop.png`,fullPage:true});

await page.setViewportSize({width:390,height:844});
await page.locator('#nav a[href="#dashboard"]').click();
await page.locator('#dashboard.active-view').waitFor({state:'visible'});
if(await page.evaluate(()=>document.documentElement.scrollWidth>document.documentElement.clientWidth+2))throw new Error('Reference dashboard mobile horizontal overflow');
await page.screenshot({path:`${out}/nexvary-panel-0.7-approved-dashboard-mobile.png`,fullPage:true});

await browser.close();
console.log('Nexvary Panel approved Royal-Tech theme Chromium Gate: PASS');
