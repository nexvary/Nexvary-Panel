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
const navStyle=await nav.evaluate(el=>{const s=getComputedStyle(el);return{color:s.color,family:s.fontFamily,shadow:s.textShadow,border:s.borderColor,bgImage:s.backgroundImage,bgColor:s.backgroundColor};});
if(!navStyle.family.includes('Noto Kufi Arabic'))throw new Error(`Kufi font stack missing: ${navStyle.family}`);
if(navStyle.color!=='rgb(203, 211, 221)')throw new Error(`Sidebar text is not the approved platinum tone: ${navStyle.color}`);
if(navStyle.shadow!=='none')throw new Error(`Sidebar typography should be restrained, not neon-glowing: ${navStyle.shadow}`);
const surfaceMissing=(navStyle.bgImage==='none')&&(navStyle.bgColor==='rgba(0, 0, 0, 0)'||navStyle.bgColor==='transparent');
if(surfaceMissing)throw new Error(`Sidebar enterprise surface missing: image=${navStyle.bgImage}, color=${navStyle.bgColor}`);

const activeNav=page.locator('#nav a.active');
const activeStyle=await activeNav.evaluate(el=>{const s=getComputedStyle(el);return{color:s.color,border:s.borderColor,shadow:s.boxShadow};});
if(activeStyle.color!=='rgb(244, 224, 179)')throw new Error(`Active sidebar text is not warm platinum/gold: ${activeStyle.color}`);
if(!activeStyle.border.includes('208')&&!activeStyle.border.includes('172'))throw new Error(`Active sidebar royal-gold border missing: ${activeStyle.border}`);
if(!activeStyle.shadow||activeStyle.shadow==='none')throw new Error('Active navigation depth cue missing');

const expectedOrder=['dashboard','hosting','accounts','mail','transfers','advancedops','sites','webtools','sitecontrols','schedules','databases','files','security','backups'];
const firstLinks=await page.locator('#nav a').evaluateAll((nodes,count)=>nodes.slice(0,count).map(n=>n.getAttribute('href')?.replace('#','')),expectedOrder.length);
if(JSON.stringify(firstLinks)!==JSON.stringify(expectedOrder))throw new Error(`Sidebar primary order mismatch: ${firstLinks.join(',')}`);
const iconColors=await page.evaluate(()=>Array.from(document.querySelectorAll('#nav a .ui-icon')).map(el=>getComputedStyle(el).color));
if(new Set(iconColors).size<8)throw new Error(`Sidebar icon palette too limited: ${new Set(iconColors).size}`);

const rootVars=await page.evaluate(()=>{const s=getComputedStyle(document.documentElement);return{navy:s.getPropertyValue('--nvp-navy').trim(),gunmetal:s.getPropertyValue('--nvp-gunmetal').trim(),gold:s.getPropertyValue('--nvp-gold').trim(),platinum:s.getPropertyValue('--nvp-platinum').trim(),blue:s.getPropertyValue('--nvp-electric-blue').trim()};});
if(rootVars.navy!=='#0c1319')throw new Error(`Deep Navy token changed: ${rootVars.navy}`);
if(rootVars.gunmetal!=='#2e3945')throw new Error(`Gunmetal token changed: ${rootVars.gunmetal}`);
if(rootVars.gold!=='#d0ac55')throw new Error(`Royal Gold token changed: ${rootVars.gold}`);
if(rootVars.platinum!=='#d9d7d4')throw new Error(`Platinum token changed: ${rootVars.platinum}`);
if(rootVars.blue!=='#6a88a0')throw new Error(`Electric Blue token changed: ${rootVars.blue}`);

if(await page.evaluate(()=>document.documentElement.scrollWidth>document.documentElement.clientWidth+2))throw new Error('Reference dashboard has horizontal overflow');
await page.screenshot({path:`${out}/nexvary-panel-0.9-approved-dashboard-desktop.png`,fullPage:true});

await page.locator('#nav a[href="#services"]').click();
await page.locator('#services.active-view').waitFor({state:'visible'});
if(await page.locator('#services .security-intelligence').count()!==1)throw new Error('Security Intelligence panel missing');
if(await page.locator('#services .defense-provider').count()!==2)throw new Error('CrowdSec/Fail2Ban cards missing');
await page.screenshot({path:`${out}/nexvary-panel-0.9-security-intelligence-desktop.png`,fullPage:true});

await page.setViewportSize({width:390,height:844});
await page.locator('#nav a[href="#dashboard"]').click();
await page.locator('#dashboard.active-view').waitFor({state:'visible'});
if(await page.evaluate(()=>document.documentElement.scrollWidth>document.documentElement.clientWidth+2))throw new Error('Reference dashboard mobile horizontal overflow');
await page.screenshot({path:`${out}/nexvary-panel-0.9-approved-dashboard-mobile.png`,fullPage:true});

await browser.close();
console.log('Nexvary Panel 0.9 Royal Enterprise theme Chromium Gate: PASS');
