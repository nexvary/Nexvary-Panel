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
async function openWordPress(page){
  const nav=page.locator('#nav a[href="#wordpress"]');
  if(await nav.count()!==1) throw new Error('WordPress navigation missing');
  await nav.evaluate(el=>el.click());
  await page.locator('#wordpress.active-view').waitFor({state:'visible'});
  await page.locator('#wpSelectivePublishControls').waitFor({state:'visible'});
}
async function noOverflow(page,label){
  const overflow=await page.evaluate(()=>document.documentElement.scrollWidth>document.documentElement.clientWidth+2);
  if(overflow) throw new Error(`${label}: horizontal overflow`);
}

const browser=await chromium.launch({headless:true});
const page=await browser.newPage({viewport:{width:1600,height:1050}});
await login(page);await openWordPress(page);
if(await page.locator('#wpSelectiveScope option[value="plugins_themes"]').count()!==1) throw new Error('Selective publish scope missing');
if(await page.locator('#wpSelectivePublishBtn').count()!==1) throw new Error('Selective publish control missing');
if(await page.locator('#wpPublishHistory').count()!==1) throw new Error('Publish history container missing');
if(await page.locator('script[src="/static/wordpress-selective.js"]').count()!==1) throw new Error('Selective publish asset missing');
await noOverflow(page,'WordPress selective publish desktop');
await page.screenshot({path:`${out}/nexvary-panel-0.7-wordpress-selective-desktop.png`,fullPage:false});

const mobile=await browser.newPage({viewport:{width:390,height:844}});
await login(mobile);await openWordPress(mobile);
await noOverflow(mobile,'WordPress selective publish mobile');
await mobile.screenshot({path:`${out}/nexvary-panel-0.7-wordpress-selective-mobile.png`,fullPage:false});
await browser.close();
console.log('Nexvary Panel WordPress selective publish UI gate: PASS');
