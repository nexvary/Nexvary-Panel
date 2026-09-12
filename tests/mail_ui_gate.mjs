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

const nav=page.locator('#nav a[href="#mail"]');
if(await nav.count()!==1)throw new Error('Email Center navigation entry missing');
await nav.click();
await page.locator('#mail.active-view').waitFor({state:'visible'});
if(await page.locator('link[href="/static/mail.css"]').count()!==1)throw new Error('Email Center stylesheet missing');
if(await page.locator('script[src="/static/mail.js"]').count()!==1)throw new Error('Email Center script missing');
if(await page.locator('#mailboxForm').count()!==1||await page.locator('#forwarderForm').count()!==1)throw new Error('Email Center create forms missing');
if(await page.locator('#mailboxList').count()!==1||await page.locator('#forwarderList').count()!==1)throw new Error('Email Center inventory panels missing');
await page.waitForFunction(()=>['ONLINE','OFFLINE'].includes(document.querySelector('#mailProviderState')?.textContent?.trim()),null,{timeout:10000});
const provider=(await page.locator('#mailProviderState').innerText()).trim();
if(provider!=='OFFLINE')throw new Error(`CI without Mail Agent must truthfully show OFFLINE, got ${provider}`);
if(!await page.locator('#mail').evaluate(el=>el.classList.contains('mail-provider-offline')))throw new Error('Offline provider guard class missing');
const disabledByPolicy=await page.locator('#mailboxForm button[type="submit"]').evaluate(el=>getComputedStyle(el).pointerEvents==='none'||el.disabled);
if(!disabledByPolicy)throw new Error('Mailbox mutation remains interactive while provider is offline');
if(await page.evaluate(()=>document.documentElement.scrollWidth>document.documentElement.clientWidth+2))throw new Error('Email Center desktop horizontal overflow');
await page.screenshot({path:`${out}/nexvary-panel-0.7-email-center-desktop.png`,fullPage:true});

await page.setViewportSize({width:390,height:844});
await page.waitForTimeout(250);
if(await page.evaluate(()=>document.documentElement.scrollWidth>document.documentElement.clientWidth+2))throw new Error('Email Center mobile horizontal overflow');
await page.screenshot({path:`${out}/nexvary-panel-0.7-email-center-mobile.png`,fullPage:true});
await browser.close();
console.log('Nexvary Panel Email Center Chromium Gate: PASS');
