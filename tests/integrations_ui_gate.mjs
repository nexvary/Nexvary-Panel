import { chromium } from 'playwright';
import fs from 'node:fs';

const base=process.env.NVP_BASE_URL||'http://127.0.0.1:8000';
const password=process.env.NVP_TEST_PASSWORD;
if(!password)throw new Error('NVP_TEST_PASSWORD is required');
const out=process.env.NVP_SCREENSHOT_DIR||'tests/artifacts';fs.mkdirSync(out,{recursive:true});
async function login(page){await page.goto(`${base}/login`,{waitUntil:'networkidle'});await page.locator('input[name="username"]').fill('admin');await page.locator('input[name="password"]').fill(password);await page.locator('button').filter({hasText:'دخول آمن'}).click();await page.waitForURL(url=>url.pathname==='/'||url.pathname==='',{timeout:15000})}
async function noOverflow(page,label){if(await page.evaluate(()=>document.documentElement.scrollWidth>document.documentElement.clientWidth+2))throw new Error(`${label} overflow`)}
async function royal(page,selector,label){const el=page.locator(selector).first();if(await el.count()!==1)throw new Error(`${label} missing`);const s=await el.evaluate(n=>{const x=getComputedStyle(n);return {border:x.borderStyle,shadow:x.boxShadow}});if(s.border==='none'||s.shadow==='none')throw new Error(`${label} Royal frame missing`)}

const browser=await chromium.launch({headless:true});
const page=await browser.newPage({viewport:{width:1440,height:1050}});await login(page);
for(const asset of ['/static/integrations.css'])if(await page.locator(`link[href="${asset}"]`).count()!==1)throw new Error(`Missing ${asset}`);
if(await page.locator('script[src="/static/integrations.js"]').count()!==1)throw new Error('Integration script missing');
await page.locator('#nav a[href="#integrations"]').click();await page.locator('#integrations.active-view').waitFor({state:'visible'});
for(const s of ['#integrationForm','#integrationName','#integrationProvider','#integrationEndpoint','#integrationSecretId','#integrationRefresh','#integrationGrid'])if(await page.locator(s).count()!==1)throw new Error(`Missing integration control ${s}`);
if(await page.locator('#integrationProvider option').count()!==3)throw new Error('Integration provider allow-list UI mismatch');
if((await page.locator('#integrationSecretId').inputValue())!=='')throw new Error('Secret reference field must start empty');
await royal(page,'#integrations','Integration workspace');await royal(page,'.integration-create','Integration creation panel');await royal(page,'.integration-contract','Integration preflight contract');await noOverflow(page,'Integrations desktop');
await page.screenshot({path:`${out}/nexvary-panel-0.6-integrations-desktop.png`,fullPage:true});

const mobile=await browser.newPage({viewport:{width:390,height:844}});await login(mobile);await mobile.locator('#mobileMenu').click();await mobile.locator('#sidebar.open').waitFor({state:'visible'});await mobile.locator('#nav a[href="#integrations"]').click();await mobile.locator('#integrations.active-view').waitFor({state:'visible'});await noOverflow(mobile,'Integrations mobile');await mobile.screenshot({path:`${out}/nexvary-panel-0.6-integrations-mobile.png`,fullPage:true});
await browser.close();console.log('Nexvary Panel Integration Targets Chromium Gate: PASS');
