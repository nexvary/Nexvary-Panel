import { chromium } from 'playwright';

const base=process.env.NVP_BASE_URL||'http://127.0.0.1:8000';
const password=process.env.NVP_TEST_PASSWORD;
if(!password) throw new Error('NVP_TEST_PASSWORD is required');

async function login(page){
  await page.goto(`${base}/login`,{waitUntil:'networkidle'});
  await page.locator('input[name="username"]').fill('admin');
  await page.locator('input[name="password"]').fill(password);
  await page.locator('button').filter({hasText:'دخول آمن'}).click();
  await page.waitForURL(url=>url.pathname==='/'||url.pathname==='',{timeout:15000});
}

const browser=await chromium.launch({headless:true});
for(const viewport of [{width:1600,height:1000},{width:390,height:844}]){
  const page=await browser.newPage({viewport});
  await login(page);
  const nav=page.locator('#nav a[href="#services"]').first();
  if(await nav.count()!==1) throw new Error('Maintenance Center navigation is missing');
  await nav.evaluate(el=>el.click());
  const root=page.locator('#services.active-view');
  await root.waitFor({state:'visible'});
  await root.getByText('قسم الصيانة',{exact:true}).waitFor({state:'visible'});
  await root.getByText('MAINTENANCE CENTER · SAFE OPERATIONS',{exact:true}).waitFor({state:'visible'});
  await root.getByText('SERVER-ENFORCED OPERATION REGISTRY',{exact:true}).waitFor({state:'visible'});
  const contracts=root.locator('.maintenance-contract[data-operation]');
  if(await contracts.count()<7) throw new Error('Maintenance Center operation registry is incomplete');
  for(const operation of ['restart-nginx','restart-mariadb','restart-fail2ban','restart-docker','docker-start','docker-stop','docker-restart']){
    if(await root.locator(`.maintenance-contract[data-operation="${operation}"]`).count()!==1) throw new Error(`Missing graphical maintenance contract: ${operation}`);
  }
  const state=await root.evaluate(el=>({
    direction:getComputedStyle(el).direction,
    pageOverflow:el.scrollWidth>el.clientWidth+3,
    documentOverflow:document.documentElement.scrollWidth>document.documentElement.clientWidth+3,
    freeShell:/<input[^>]+(?:name|id)=["']?(?:command|shell|terminal)/i.test(el.innerHTML),
    boundary:(el.textContent||'').includes('ALLOWLISTED')&&(el.textContent||'').includes('STEP-UP'),
    policyDetails:(el.textContent||'').includes('RBAC')&&(el.textContent||'').includes('PRE')&&(el.textContent||'').includes('POST')&&(el.textContent||'').includes('ROLLBACK'),
  }));
  if(state.direction!=='rtl') throw new Error(`Maintenance Center lost RTL at ${viewport.width}px`);
  if(state.pageOverflow||state.documentOverflow) throw new Error(`Maintenance Center horizontal overflow at ${viewport.width}px`);
  if(state.freeShell) throw new Error('Maintenance Center exposes a free-form shell/command input');
  if(!state.boundary) throw new Error('Maintenance Center privileged-boundary indicators are missing');
  if(!state.policyDetails) throw new Error('Maintenance Center does not expose enforced safety lifecycle metadata');
  await page.close();
}
await browser.close();
console.log('NEXVARY Maintenance Center desktop/mobile UI gate: PASS');
