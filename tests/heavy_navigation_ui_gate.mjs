import { chromium } from 'playwright';

const base=process.env.NVP_BASE_URL||'http://127.0.0.1:8000';
const password=process.env.NVP_TEST_PASSWORD;
if(!password) throw new Error('NVP_TEST_PASSWORD is required');

const browser=await chromium.launch({headless:true});
const page=await browser.newPage({viewport:{width:1600,height:1000}});
const failures=[];
page.on('pageerror',e=>failures.push(`pageerror:${e.message}`));
page.on('console',m=>{ if(m.type()==='error') failures.push(`console:${m.text()}`); });

await page.goto(`${base}/login`,{waitUntil:'networkidle'});
await page.locator('input[name="username"]').fill('admin');
await page.locator('input[name="password"]').fill(password);
await page.locator('button').filter({hasText:'دخول آمن'}).click();
await page.waitForURL(url=>url.pathname==='/'||url.pathname==='',{timeout:15000});

const audit=async label=>{
  const state=await page.evaluate(()=>({
    documentOverflow:document.documentElement.scrollWidth>document.documentElement.clientWidth+3,
    visibleViews:Array.from(document.querySelectorAll('#workspaceStage > .workspace-page')).filter(el=>getComputedStyle(el).display!=='none').map(el=>el.id),
  }));
  if(state.documentOverflow) failures.push(`${label}: horizontal overflow`);
  if(state.visibleViews.length!==1) failures.push(`${label}: expected one visible workspace, got ${state.visibleViews.join(',')}`);
};

const navLinks=page.locator('#nav a[href^="#"]');
const navCount=await navLinks.count();
const targets=[];
for(let i=0;i<navCount;i++){
  const link=navLinks.nth(i);
  const href=await link.getAttribute('href');
  const target=(href||'').slice(1);
  if(!target) continue;
  targets.push(target);
  if(await page.locator(`#${target}`).count()!==1){ failures.push(`dead-nav:${target}`); continue; }
  if(await link.locator('.ui-icon').count()!==1) failures.push(`nav-icon:${target}: expected exactly one .ui-icon`);
  await link.evaluate(el=>el.click());
  const view=page.locator(`#${target}.active-view`);
  try{ await view.waitFor({state:'visible',timeout:4000}); }catch{ failures.push(`dead-nav:${target}: target did not become visible`); continue; }
  await audit(`desktop:${target}`);
}

const uniqueTargets=[...new Set(targets)];
const workspaceIds=await page.locator('#workspaceStage > .workspace-page[id]').evaluateAll(nodes=>nodes.map(n=>n.id));
for(const id of workspaceIds){
  if(id!=='dashboard'&&!uniqueTargets.includes(id)) failures.push(`orphan-workspace:${id}`);
}

const openTargets=await page.locator('[data-open-view]').evaluateAll(nodes=>nodes.map(n=>n.getAttribute('data-open-view')).filter(Boolean));
for(const target of [...new Set(openTargets)]){
  if(await page.locator(`#${target}`).count()!==1) failures.push(`dead-data-open-view:${target}`);
}

const hashTargets=await page.locator('a[href^="#"]').evaluateAll(nodes=>nodes.map(n=>(n.getAttribute('href')||'').slice(1)).filter(Boolean));
for(const target of [...new Set(hashTargets)]){
  if(await page.locator(`#${target}`).count()!==1) failures.push(`dead-hash-link:${target}`);
}

const visibleButtons=page.locator('button:visible');
for(let i=0;i<await visibleButtons.count();i++){
  const b=visibleButtons.nth(i);
  const box=await b.boundingBox();
  if(!box) continue;
  if(box.width<28||box.height<28) failures.push(`small-button:${(await b.getAttribute('id'))||await b.innerText()}: ${Math.round(box.width)}x${Math.round(box.height)}`);
}

await page.setViewportSize({width:390,height:844});
for(const target of ['dashboard','hosting','mail','sites','security','services','notifications','audit']){
  const link=page.locator(`#nav a[href="#${target}"]`).first();
  if(await link.count()!==1) continue;
  await link.evaluate(el=>el.click());
  try{ await page.locator(`#${target}.active-view`).waitFor({state:'visible',timeout:4000}); }catch{ failures.push(`mobile-dead-nav:${target}`); continue; }
  await audit(`mobile:${target}`);
}

await browser.close();
if(failures.length) throw new Error(`Heavy navigation/UI gate failed (${failures.length}):\n- ${[...new Set(failures)].join('\n- ')}`);
console.log(`NEXVARY heavy navigation/UI gate: PASS (${uniqueTargets.length} navigation targets, ${workspaceIds.length} workspaces)`);
