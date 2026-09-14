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
  await page.locator('#dashboard.active-view').waitFor({state:'visible'});
}

async function workspaceTargets(page){
  return await page.locator('#nav a[href^="#"]').evaluateAll(nodes=>{
    const seen=new Set();
    const out=[];
    for(const node of nodes){
      const href=node.getAttribute('href')||'';
      const id=href.startsWith('#')?href.slice(1):'';
      const target=id?document.getElementById(id):null;
      if(id&&target?.classList.contains('workspace-page')&&!seen.has(id)){
        seen.add(id);out.push(id);
      }
    }
    return out;
  });
}

async function openWorkspace(page,id){
  const nav=page.locator(`#nav a[href="#${id}"]`).first();
  if(await nav.count()!==1) throw new Error(`Missing sidebar link for ${id}`);
  await nav.evaluate(el=>el.click());
  await page.locator(`#${id}.active-view`).waitFor({state:'visible',timeout:10000});
  await page.waitForTimeout(40);
}

async function reviewWorkspace(page,id,label){
  await openWorkspace(page,id);
  const result=await page.evaluate(activeId=>{
    const visible=Array.from(document.querySelectorAll('#workspaceStage > .workspace-page')).filter(el=>{
      const s=getComputedStyle(el);return s.display!=='none'&&s.visibility!=='hidden';
    }).map(el=>el.id);
    const root=document.getElementById(activeId);
    if(!root) return {missing:true};
    const heading=root.querySelector('h1,h2,h3');
    const headingSize=heading?parseFloat(getComputedStyle(heading).fontSize):0;
    const rect=root.getBoundingClientRect();
    const controls=Array.from(root.querySelectorAll('button,input,select,textarea,a')).filter(el=>{
      const s=getComputedStyle(el);const r=el.getBoundingClientRect();
      return s.display!=='none'&&s.visibility!=='hidden'&&r.width>0&&r.height>0;
    });
    const viewport=document.documentElement.clientWidth;
    const escaped=controls.filter(el=>{
      const r=el.getBoundingClientRect();
      return r.left < -3 || r.right > viewport + 3;
    }).slice(0,8).map(el=>({tag:el.tagName,id:el.id||'',text:(el.textContent||'').trim().slice(0,40)}));
    return {
      visible,
      missing:false,
      direction:getComputedStyle(root).direction,
      pageOverflow:root.scrollWidth>root.clientWidth+3,
      documentOverflow:document.documentElement.scrollWidth>document.documentElement.clientWidth+3,
      headingSize,
      rect:{left:rect.left,right:rect.right,width:rect.width},
      escaped,
    };
  },id);
  if(result.missing) throw new Error(`${label}/${id}: workspace missing`);
  if(result.visible.length!==1||result.visible[0]!==id) throw new Error(`${label}/${id}: exactly one workspace must be visible (${result.visible.join(',')})`);
  if(result.direction!=='rtl') throw new Error(`${label}/${id}: RTL direction lost (${result.direction})`);
  if(result.pageOverflow) throw new Error(`${label}/${id}: workspace horizontal overflow`);
  if(result.documentOverflow) throw new Error(`${label}/${id}: document horizontal overflow`);
  if(id!=='dashboard'&&result.headingSize<18) throw new Error(`${label}/${id}: primary heading is too small (${result.headingSize}px)`);
  if(result.escaped.length) throw new Error(`${label}/${id}: visible controls escape viewport: ${JSON.stringify(result.escaped)}`);
}

const browser=await chromium.launch({headless:true});
const page=await browser.newPage({viewport:{width:1600,height:1000}});
await login(page);

const bodyDirection=await page.evaluate(()=>getComputedStyle(document.body).direction);
if(bodyDirection!=='rtl') throw new Error(`Application body must remain RTL, got ${bodyDirection}`);
const targets=await workspaceTargets(page);
if(targets.length<20) throw new Error(`Expected a mature multi-workspace panel, found only ${targets.length} sidebar workspaces`);

for(const id of targets) await reviewWorkspace(page,id,'desktop');
await page.screenshot({path:`${out}/nexvary-panel-0.7-final-design-review-desktop.png`,fullPage:false});

await page.setViewportSize({width:390,height:844});
for(const id of targets) await reviewWorkspace(page,id,'mobile');
await openWorkspace(page,'dashboard');
await page.screenshot({path:`${out}/nexvary-panel-0.7-final-design-review-mobile.png`,fullPage:false});

await browser.close();
console.log(`Nexvary Panel final design review gate: PASS (${targets.length} workspaces desktop + mobile)`);
