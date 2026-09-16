import { chromium } from 'playwright';
import fs from 'node:fs';

const base=process.env.NVP_BASE_URL||'http://127.0.0.1:8000';
const password=process.env.NVP_TEST_PASSWORD;
if(!password) throw new Error('NVP_TEST_PASSWORD is required');
const out=process.env.NVP_SCREENSHOT_DIR||'tests/artifacts';
fs.mkdirSync(out,{recursive:true});

const browser=await chromium.launch({headless:true});
const page=await browser.newPage({viewport:{width:1600,height:1000}});
await page.goto(`${base}/login`,{waitUntil:'networkidle'});
await page.locator('input[name="username"]').fill('admin');
await page.locator('input[name="password"]').fill(password);
await page.locator('button').filter({hasText:'دخول آمن'}).click();
await page.waitForURL(url=>url.pathname==='/'||url.pathname==='',{timeout:15000});
await page.locator('#dashboard.active-view').waitFor({state:'visible'});

const sidebarFont=await page.locator('#nav a[href="#sites"]').evaluate(el=>parseFloat(getComputedStyle(el).fontSize));
if(sidebarFont<15) throw new Error(`Sidebar type was not enlarged enough: ${sidebarFont}px`);

const hero=page.locator('#dashboard .ref-hero');
const heroStyle=await hero.evaluate(el=>({minHeight:getComputedStyle(el).minHeight,padding:getComputedStyle(el).padding,height:el.getBoundingClientRect().height}));
if(heroStyle.minHeight!=='150px') throw new Error(`Dashboard hero compact baseline missing: ${JSON.stringify(heroStyle)}`);

const portal=page.locator('#dashboard .ref-world');
if(await portal.count()!==1) throw new Error('Dashboard technical portal missing');
const portalStyle=await portal.evaluate(el=>{
  const before=getComputedStyle(el,'::before');
  const after=getComputedStyle(el,'::after');
  return {
    beforeContent:before.content,
    beforeBackground:before.backgroundImage,
    beforeClip:before.clipPath,
    afterContent:after.content,
    afterBackground:after.backgroundImage,
    afterClip:after.clipPath,
  };
});
if(portalStyle.beforeContent==='none'||portalStyle.beforeBackground==='none') throw new Error('Andalusian Royal Gold frame is not rendered');
if(portalStyle.beforeClip==='none') throw new Error('Andalusian arch geometry clip is missing');
if(!portalStyle.beforeBackground.includes('conic-gradient')) throw new Error(`Zellige geometric pattern missing: ${portalStyle.beforeBackground}`);
if(portalStyle.afterContent==='none'||portalStyle.afterBackground==='none') throw new Error('Electric Blue arch depth is not rendered');
if(!portalStyle.afterBackground.includes('radial-gradient')) throw new Error(`Technical blue aperture missing: ${portalStyle.afterBackground}`);

const palette=await page.evaluate(()=>{const s=getComputedStyle(document.documentElement);return{gold:s.getPropertyValue('--nvp-gold').trim(),blue:s.getPropertyValue('--nvp-electric-blue').trim(),green:s.getPropertyValue('--nvp-green').trim(),crimson:s.getPropertyValue('--nvp-crimson').trim()};});
if(palette.gold!=='#d0ac55'||palette.blue!=='#6a88a0') throw new Error(`Approved Royal Gold/Electric Blue tokens changed: ${JSON.stringify(palette)}`);

const basmala=await page.locator('.basmala-seal strong').innerText();
if(basmala!=='بِسْمِ اللهِ الرَّحْمٰنِ الرَّحِيمِ') throw new Error('Basmala changed during visual refinement');
if(await page.evaluate(()=>getComputedStyle(document.body).direction)!=='rtl') throw new Error('RTL direction lost');
if(await page.evaluate(()=>document.documentElement.scrollWidth>document.documentElement.clientWidth+2)) throw new Error('Desktop horizontal overflow after Andalusian refinement');
await page.screenshot({path:`${out}/nexvary-panel-0.9-andalusian-dashboard-desktop.png`,fullPage:true});

await page.setViewportSize({width:390,height:844});
await page.waitForTimeout(120);
if(await page.evaluate(()=>document.documentElement.scrollWidth>document.documentElement.clientWidth+2)) throw new Error('Mobile horizontal overflow after Andalusian refinement');
const portalMobile=await portal.evaluate(el=>({display:getComputedStyle(el).display,width:el.getBoundingClientRect().width}));
// The established mobile baseline intentionally hides the decorative center portal below 900px.
// If a future responsive pass renders it, it must remain within the viewport.
if(portalMobile.display!=='none'&&portalMobile.width>390) throw new Error(`Andalusian portal exceeds mobile viewport: ${JSON.stringify(portalMobile)}`);
await page.screenshot({path:`${out}/nexvary-panel-0.9-andalusian-dashboard-mobile.png`,fullPage:true});

await browser.close();
console.log('Nexvary Panel 0.9 Andalusian visual Chromium gate: PASS');
