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
  const overflow=await page.evaluate(()=>document.documentElement.scrollWidth>document.documentElement.clientWidth+2);
  if(overflow) throw new Error(`${label}: horizontal overflow`);
}
async function open(page,id){
  const nav=page.locator(`#nav a[href="#${id}"]`);
  if(await nav.count()!==1) throw new Error(`Missing navigation entry #${id}`);
  // This gate validates workspace rendering, not drawer hit-testing. The primary ui_gate
  // separately opens and clicks the real mobile drawer. DOM click keeps this test stable
  // when the off-canvas navigation is intentionally outside the mobile viewport.
  await nav.evaluate(el=>el.click());
  await page.locator(`#${id}.active-view`).waitFor({state:'visible'});
}

const browser=await chromium.launch({headless:true});
const page=await browser.newPage({viewport:{width:1600,height:1050}});
await login(page);

for(const css of ['/static/royal-workspaces.css','/static/royal-workspace-entities.css']){
  if(await page.locator(`link[href="${css}"]`).count()!==1) throw new Error(`Royal workspace stylesheet missing: ${css}`);
}

const pages=['sites','databases','files','security','backups','users','fusion','integrations','wordpress','deploy','docker','services','dns','notifications','audit','vault'];
const iconColors=[];
const accentValues=[];
for(const id of pages){
  await open(page,id);
  const root=page.locator(`#${id}.active-view`);
  const hero=root.locator(':scope > .workspace-hero');
  if(await hero.count()!==1) throw new Error(`${id}: royal workspace hero missing`);
  const rootAccent=await root.evaluate(el=>getComputedStyle(el).getPropertyValue('--rw-accent').trim());
  if(!rootAccent) throw new Error(`${id}: workspace accent variable missing`);
  accentValues.push(rootAccent);
  const heroStyle=await hero.evaluate(el=>{const s=getComputedStyle(el);return{border:parseFloat(s.borderTopWidth),shadow:s.boxShadow,bg:s.backgroundImage,radius:parseFloat(s.borderTopLeftRadius)}});
  if(heroStyle.border<1||heroStyle.shadow==='none'||heroStyle.bg==='none'||heroStyle.radius<8) throw new Error(`${id}: royal hero styling incomplete`);
  const heroIcon=hero.locator('.hero-icon').first();
  if(await heroIcon.count()!==1) throw new Error(`${id}: expressive hero icon missing`);
  const iconStyle=await heroIcon.evaluate(el=>{const s=getComputedStyle(el);return{color:s.color,border:parseFloat(s.borderTopWidth),shadow:s.boxShadow}});
  if(iconStyle.border<1||iconStyle.shadow==='none') throw new Error(`${id}: hero icon frame/glow missing`);
  iconColors.push(iconStyle.color);
  if(await hero.locator('.hero-stats > div').count()<2) throw new Error(`${id}: operational hero statistics missing`);
  await noOverflow(page,`${id} desktop`);
  await page.screenshot({path:`${out}/nexvary-panel-0.6-royal-${id}-desktop.png`,fullPage:false});
}

if(new Set(accentValues).size<7) throw new Error(`Internal workspace accent palette is not diverse enough: ${new Set(accentValues).size} colors`);
if(new Set(iconColors).size<7) throw new Error(`Internal workspace hero icon palette is not diverse enough: ${new Set(iconColors).size} colors`);

await open(page,'dns');
const dnsCards=page.locator('#dns .dns-summary-card');
if(await dnsCards.count()<2) throw new Error('DNS summary cards missing for frame alternation test');
const c1=await dnsCards.nth(0).evaluate(el=>getComputedStyle(el).borderColor);
const c2=await dnsCards.nth(1).evaluate(el=>getComputedStyle(el).borderColor);
if(c1===c2) throw new Error('Silver / electric-black internal frame alternation is missing');

const mobile=await browser.newPage({viewport:{width:390,height:844}});
await login(mobile);
for(const id of ['sites','files','security','backups','dns','fusion']){
  await open(mobile,id);
  const hero=mobile.locator(`#${id}.active-view > .workspace-hero`);
  if(await hero.count()!==1) throw new Error(`${id}: mobile royal hero missing`);
  await noOverflow(mobile,`${id} mobile`);
}
await mobile.screenshot({path:`${out}/nexvary-panel-0.6-royal-internal-mobile.png`,fullPage:false});

await browser.close();
console.log('Nexvary Panel Royal Internal Workspace Gate: PASS');
