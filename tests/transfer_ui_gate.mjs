import { chromium } from 'playwright';
import fs from 'node:fs';

const base=process.env.NVP_BASE_URL||'http://127.0.0.1:8000';
const password=process.env.NVP_TEST_PASSWORD;
if(!password)throw new Error('NVP_TEST_PASSWORD is required');
const out=process.env.NVP_SCREENSHOT_DIR||'tests/artifacts';
fs.mkdirSync(out,{recursive:true});

const browser=await chromium.launch({headless:true});
const page=await browser.newPage({viewport:{width:1600,height:1050}});
await page.goto(`${base}/login`,{waitUntil:'networkidle'});
await page.locator('input[name="username"]').fill('admin');
await page.locator('input[name="password"]').fill(password);
await page.locator('button').filter({hasText:'دخول آمن'}).click();
await page.waitForURL(url=>url.pathname==='/'||url.pathname==='',{timeout:15000});

const nav=page.locator('#nav a[href="#transfers"]');
if(await nav.count()!==1)throw new Error('Transfer Center navigation entry missing');
await nav.click();
await page.locator('#transfers.active-view').waitFor({state:'visible'});
if(await page.locator('link[href="/static/transfers.css"]').count()!==1)throw new Error('Transfer Center stylesheet missing');
if(await page.locator('script[src="/static/transfers.js"]').count()!==1)throw new Error('Transfer Center script missing');
if(await page.locator('#transferForm').count()!==1||await page.locator('#transferList').count()!==1)throw new Error('Transfer Center form or inventory missing');
if(await page.locator('#transferPublicKey').count()!==1)throw new Error('SSH public key input missing');
if((await page.locator('#transfers').innerText()).includes('PasswordAuthentication yes'))throw new Error('Unsafe password authentication copy detected');
await page.waitForFunction(()=>['ONLINE','OFFLINE'].includes(document.querySelector('#transferProviderState')?.textContent?.trim()),null,{timeout:10000});
const provider=(await page.locator('#transferProviderState').innerText()).trim();
if(provider!=='OFFLINE')throw new Error(`CI without Transfer Agent must truthfully show OFFLINE, got ${provider}`);
if(!await page.locator('#transfers').evaluate(el=>el.classList.contains('transfer-provider-offline')))throw new Error('Offline transfer provider guard missing');
const blocked=await page.locator('#transferForm button[type="submit"]').evaluate(el=>getComputedStyle(el).pointerEvents==='none'||el.disabled);
if(!blocked)throw new Error('Transfer mutation remains interactive while provider is offline');
if(await page.evaluate(()=>document.documentElement.scrollWidth>document.documentElement.clientWidth+2))throw new Error('Transfer Center desktop horizontal overflow');
await page.screenshot({path:`${out}/nexvary-panel-0.7-transfer-center-desktop.png`,fullPage:true});

await page.setViewportSize({width:390,height:844});
await page.waitForTimeout(250);
if(await page.evaluate(()=>document.documentElement.scrollWidth>document.documentElement.clientWidth+2))throw new Error('Transfer Center mobile horizontal overflow');
await page.screenshot({path:`${out}/nexvary-panel-0.7-transfer-center-mobile.png`,fullPage:true});
await browser.close();
console.log('Nexvary Panel SFTP Transfer Center Chromium Gate: PASS');
