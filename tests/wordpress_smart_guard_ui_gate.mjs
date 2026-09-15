import { chromium } from 'playwright';
import fs from 'node:fs';

const base=process.env.NVP_BASE_URL||'http://127.0.0.1:8000';
const password=process.env.NVP_TEST_PASSWORD;
if(!password)throw new Error('NVP_TEST_PASSWORD is required');
const out=process.env.NVP_SCREENSHOT_DIR||'tests/artifacts';
fs.mkdirSync(out,{recursive:true});

const candidate={id:41,source_domain:'live.example.test',staging_domain:'stage.example.test',kind:'plugin',slug:'hello-tool',installed_version:'1.0.0',target_version:'2.0.0',staging_snapshot:'',production_snapshot:'',status:'preview',detail:'Update candidate ready for staging verification'};

const browser=await chromium.launch({headless:true});
const page=await browser.newPage({viewport:{width:1600,height:1050}});
await page.route('**/api/wordpress/smart-guard*',async route=>{
  const url=new URL(route.request().url());
  if(route.request().method()==='POST'&&url.pathname.endsWith('/preview')){await route.fulfill({status:201,contentType:'application/json',body:JSON.stringify({ok:true,candidate,check:{ok:true,installed_version:'1.0.0',latest_version:'2.0.0',update_available:true}})});return}
  await route.fulfill({status:200,contentType:'application/json',body:JSON.stringify({ok:true,source_domain:'live.example.test',staging_domain:'stage.example.test',candidates:[candidate],policy:{staging_required:true,verify_before_guarded_publish:true,post_publish_integrity:true,automatic_rollback_on_failed_postcheck:true}})});
});

await page.goto(`${base}/login`,{waitUntil:'networkidle'});
await page.locator('input[name="username"]').fill('admin');
await page.locator('input[name="password"]').fill(password);
await page.locator('button').filter({hasText:'دخول آمن'}).click();
await page.waitForURL(url=>url.pathname==='/'||url.pathname==='',{timeout:15000});
await page.locator('#nav a[href="#wordpress"]').click();
await page.locator('#wordpress.active-view').waitFor({state:'visible'});
for(const sel of ['#wpSmartGuardPanel','#wpGuardDomain','#wpGuardKind','#wpGuardSlug','#wpGuardStage','#wpGuardPreviewBtn','#wpGuardCandidate','#wpGuardStatus','#wpGuardRollback','#wpGuardPostcheck','#wpGuardResult','#wpGuardHistory'])if(await page.locator(sel).count()!==1)throw new Error(`Smart Update Guard control missing: ${sel}`);
if(await page.locator('script[src="/static/wordpress-smart-guard.js"]').count()!==1)throw new Error('Smart Update Guard script missing');
await page.evaluate(()=>{const select=document.querySelector('#wpGuardDomain');const option=document.createElement('option');option.value='live.example.test';option.textContent='live.example.test';select.append(option)});
await page.locator('#wpGuardDomain').selectOption('live.example.test');
await page.waitForFunction(()=>document.querySelector('#wpGuardStage')?.value==='stage.example.test',{timeout:10000});
await page.locator('#wpGuardSlug').fill('hello-tool');
await page.locator('#wpGuardPreviewBtn').click();
await page.waitForFunction(()=>document.querySelector('#wpGuardCandidate')?.textContent?.includes('#41'),{timeout:10000});
const text=await page.locator('#wpSmartGuardPanel').innerText();
for(const marker of ['NEXVARY Smart Update Guard','Preview → Staging Update → Integrity Verify → Guarded Publish → Production Post-check','AUTO ROLLBACK','plugin/hello-tool','1.0.0 → 2.0.0'])if(!text.includes(marker))throw new Error(`Smart Update Guard marker missing: ${marker}`);
if(await page.evaluate(()=>document.documentElement.scrollWidth>document.documentElement.clientWidth+2))throw new Error('Smart Update Guard desktop horizontal overflow');
await page.locator('#wpSmartGuardPanel').scrollIntoViewIfNeeded();
await page.screenshot({path:`${out}/nexvary-panel-0.7-wordpress-smart-guard-desktop.png`,fullPage:false});

await page.setViewportSize({width:390,height:844});
await page.locator('#wpSmartGuardPanel').scrollIntoViewIfNeeded();
await page.waitForTimeout(200);
if(await page.evaluate(()=>document.documentElement.scrollWidth>document.documentElement.clientWidth+2))throw new Error('Smart Update Guard mobile horizontal overflow');
await page.screenshot({path:`${out}/nexvary-panel-0.7-wordpress-smart-guard-mobile.png`,fullPage:false});
await browser.close();
console.log('NEXVARY WordPress Smart Update Guard Chromium gate: PASS');
