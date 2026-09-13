import { chromium } from 'playwright';
import fs from 'node:fs';

const base=process.env.NVP_BASE_URL||'http://127.0.0.1:8000';
const password=process.env.NVP_TEST_PASSWORD;
if(!password)throw new Error('NVP_TEST_PASSWORD is required');
const out=process.env.NVP_SCREENSHOT_DIR||'tests/artifacts';
fs.mkdirSync(out,{recursive:true});

const browser=await chromium.launch({headless:true});
const page=await browser.newPage({viewport:{width:1600,height:1050}});
const pageErrors=[];
page.on('pageerror',error=>pageErrors.push(error.message));
await page.goto(`${base}/login`,{waitUntil:'networkidle'});
await page.locator('input[name="username"]').fill('admin');
await page.locator('input[name="password"]').fill(password);
await page.locator('button').filter({hasText:'دخول آمن'}).click();
await page.waitForURL(url=>url.pathname==='/'||url.pathname==='',{timeout:15000});

const nav=page.locator('#nav a[href="#fusion"]');
if(await nav.count()!==1)throw new Error('Fusion navigation entry missing');
await nav.click();
await page.locator('#fusion.active-view').waitFor({state:'visible'});
await page.locator('#extensionHubPanel').waitFor({state:'visible'});
await page.waitForFunction(()=>document.querySelectorAll('#extensionGrid .fusion-provider-card').length>=6,null,{timeout:10000});

const total=Number((await page.locator('#extensionTotal').innerText()).trim());
const enabled=Number((await page.locator('#extensionEnabled').innerText()).trim());
if(total<6||enabled!==total)throw new Error(`Extension summary invalid: enabled=${enabled}, total=${total}`);
const notice=(await page.locator('#extensionNotice').innerText()).trim();
if(!/Curated|Curated manifests/i.test(notice))throw new Error('Curated execution model is not visible');
if(await page.locator('#extensionGrid [data-extension-toggle]').count()<6)throw new Error('Extension kill-switch controls missing');

const firstToggle=page.locator('#extensionGrid [data-extension-toggle]').first();
await firstToggle.click();
await page.waitForFunction(()=>/Step-Up/.test(document.querySelector('#extensionNotice')?.textContent||''),null,{timeout:5000});
if(pageErrors.length)throw new Error(`Extension Hub page error: ${pageErrors.join(' | ')}`);
if(await page.evaluate(()=>document.documentElement.scrollWidth>document.documentElement.clientWidth+2))throw new Error('Extension Hub desktop horizontal overflow');
await page.screenshot({path:`${out}/nexvary-panel-0.7-extension-hub-desktop.png`,fullPage:true});

await page.setViewportSize({width:390,height:844});
await page.waitForTimeout(250);
if(await page.evaluate(()=>document.documentElement.scrollWidth>document.documentElement.clientWidth+2))throw new Error('Extension Hub mobile horizontal overflow');
await page.screenshot({path:`${out}/nexvary-panel-0.7-extension-hub-mobile.png`,fullPage:true});

await browser.close();
console.log('Nexvary Panel Curated Extension Hub Chromium Gate: PASS');
