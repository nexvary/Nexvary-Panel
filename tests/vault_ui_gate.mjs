import { chromium } from 'playwright';
import fs from 'node:fs';

const base=process.env.NVP_BASE_URL||'http://127.0.0.1:8000';
const password=process.env.NVP_TEST_PASSWORD;
if(!password)throw new Error('NVP_TEST_PASSWORD is required');
const out=process.env.NVP_SCREENSHOT_DIR||'tests/artifacts';
fs.mkdirSync(out,{recursive:true});

async function login(page){
  await page.goto(`${base}/login`,{waitUntil:'networkidle'});
  await page.locator('input[name="username"]').fill('admin');
  await page.locator('input[name="password"]').fill(password);
  await page.locator('button').filter({hasText:'دخول آمن'}).click();
  await page.waitForURL(url=>url.pathname==='/'||url.pathname==='',{timeout:15000});
}
async function noOverflow(page,label){if(await page.evaluate(()=>document.documentElement.scrollWidth>document.documentElement.clientWidth+2))throw new Error(`${label} overflow`)}
async function royal(page,selector,label){const el=page.locator(selector).first();if(await el.count()!==1)throw new Error(`${label} missing`);const s=await el.evaluate(n=>{const x=getComputedStyle(n);return {border:x.borderStyle,shadow:x.boxShadow}});if(s.border==='none'||s.shadow==='none')throw new Error(`${label} Royal frame missing`)}

const browser=await chromium.launch({headless:true});
const page=await browser.newPage({viewport:{width:1440,height:1050}});
await login(page);
if(await page.locator('link[href="/static/vault.css"]').count()!==1||await page.locator('script[src="/static/vault.js"]').count()!==1)throw new Error('Vault assets missing');
await page.locator('#nav a[href="#vault"]').click();
await page.locator('#vault.active-view').waitFor({state:'visible'});
for(const selector of ['#vaultPutForm','#vaultKind','#vaultId','#vaultValue','#vaultRefresh','#vaultGrid'])if(await page.locator(selector).count()!==1)throw new Error(`Vault control missing: ${selector}`);
if((await page.locator('#vaultValue').inputValue())!=='')throw new Error('Vault secret field must never be prefilled');
if(await page.locator('#vaultKind option').count()!==5)throw new Error('Vault kind allow-list UI mismatch');
await royal(page,'#vault','Vault workspace');
await royal(page,'.vault-create','Vault create panel');
await royal(page,'.vault-boundary','Vault policy boundary');
await noOverflow(page,'Vault desktop');
await page.screenshot({path:`${out}/nexvary-panel-0.6-vault-desktop.png`,fullPage:true});

const mobile=await browser.newPage({viewport:{width:390,height:844}});
await login(mobile);
await mobile.locator('#mobileMenu').click();
await mobile.locator('#sidebar.open').waitFor({state:'visible'});
await mobile.locator('#nav a[href="#vault"]').click();
await mobile.locator('#vault.active-view').waitFor({state:'visible'});
await noOverflow(mobile,'Vault mobile');
await mobile.screenshot({path:`${out}/nexvary-panel-0.6-vault-mobile.png`,fullPage:true});
await browser.close();
console.log('Nexvary Panel Secret Vault Chromium Gate: PASS');
