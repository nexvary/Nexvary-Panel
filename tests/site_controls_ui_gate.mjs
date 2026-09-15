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
if(await page.locator('link[href="/static/site-controls.css"]').count()!==1) throw new Error('Site Control stylesheet missing');
if(await page.locator('script[src="/static/site-controls.js"]').count()!==1) throw new Error('Site Control script missing');
const nav=page.locator('#nav a[href="#sitecontrols"]');
if(await nav.count()!==1) throw new Error('Site Control navigation missing');
await nav.evaluate(el=>el.click());
await page.locator('#sitecontrols.active-view').waitFor({state:'visible'});
for(const selector of ['#siteControlDomain','#privacyControlForm','#hotlinkControlForm','#indexControlForm','#mimeControlForm','#rawAccessOutput']){
  if(await page.locator(selector).count()!==1) throw new Error(`Site Control UI missing ${selector}`);
}
if(await page.locator('#sitecontrols .workspace-hero').count()!==1) throw new Error('Site Control Royal hero missing');
const visible=await page.locator('#workspaceStage>.workspace-page').evaluateAll(nodes=>nodes.filter(el=>getComputedStyle(el).display!=='none').map(el=>el.id));
if(visible.length!==1||visible[0]!=='sitecontrols') throw new Error(`Site Control workspace visibility failed: ${visible.join(',')}`);
await noOverflow(page,'sitecontrols desktop');
await page.screenshot({path:`${out}/nexvary-panel-0.7-site-control-center-desktop.png`,fullPage:false});

const mobile=await browser.newPage({viewport:{width:390,height:844}});
await login(mobile);
await mobile.locator('#nav a[href="#sitecontrols"]').evaluate(el=>el.click());
await mobile.locator('#sitecontrols.active-view').waitFor({state:'visible'});
await noOverflow(mobile,'sitecontrols mobile');
if(await mobile.locator('#sitecontrols .sitecontrols-card').count()<5) throw new Error('Site Control mobile cards missing');
await mobile.screenshot({path:`${out}/nexvary-panel-0.7-site-control-center-mobile.png`,fullPage:false});
await browser.close();
console.log('NEXVARY Site Control Center Chromium gate: PASS');
