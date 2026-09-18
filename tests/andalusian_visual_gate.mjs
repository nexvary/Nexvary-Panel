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
const hero=page.locator('#dashboard .ref-hero-andalusian');
if(await hero.count()!==1) throw new Error('Approved Royal/Andalusian hero missing');
const hs=await hero.evaluate(el=>({height:el.getBoundingClientRect().height,border:getComputedStyle(el).borderColor,background:getComputedStyle(el).backgroundImage}));
if(hs.height<180) throw new Error(`Approved hero is too shallow: ${JSON.stringify(hs)}`);
if(!hs.background.includes('gradient')) throw new Error('Royal indigo hero gradient missing');

const fatiha=page.locator('#dashboard .ref-fatiha');
if(await fatiha.count()!==1) throw new Error('Fatiha field missing');
const text=(await fatiha.innerText()).replace(/\s+/g,' ');
for(const required of ['بِسْمِ','ٱلْحَمْدُ','إِيَّاكَ','ٱهْدِنَا','ٱلضَّآلِّينَ']) if(!text.includes(required)) throw new Error(`Fatiha content incomplete: ${required}`);
if(await fatiha.locator('.ayah-mark').count()!==7) throw new Error('Fatiha must render seven ayah medallions');
if(await page.locator('#dashboard .andalusian-corner').count()!==4) throw new Error('Four Andalusian corner ornaments are required');
if(await page.locator('#dashboard .ref-world').count()!==0) throw new Error('Legacy radar/technical portal returned');

const palette=await page.evaluate(()=>{const s=getComputedStyle(document.documentElement);return{gold:s.getPropertyValue('--nvp-gold').trim(),blue:s.getPropertyValue('--nvp-electric-blue').trim()};});
if(palette.gold!=='#d0ac55'||palette.blue!=='#6a88a0') throw new Error(`Approved tokens changed: ${JSON.stringify(palette)}`);
if(await page.evaluate(()=>getComputedStyle(document.body).direction)!=='rtl') throw new Error('RTL direction lost');
if(await page.evaluate(()=>document.documentElement.scrollWidth>document.documentElement.clientWidth+2)) throw new Error('Desktop horizontal overflow');
await page.screenshot({path:`${out}/nexvary-panel-0.9-andalusian-dashboard-desktop.png`,fullPage:true});
await page.setViewportSize({width:390,height:844}); await page.waitForTimeout(120);
if(await page.evaluate(()=>document.documentElement.scrollWidth>document.documentElement.clientWidth+2)) throw new Error('Mobile horizontal overflow');
const fw=await fatiha.evaluate(el=>el.getBoundingClientRect().width); if(fw>390) throw new Error(`Fatiha exceeds mobile viewport: ${fw}`);
await page.screenshot({path:`${out}/nexvary-panel-0.9-andalusian-dashboard-mobile.png`,fullPage:true});
await browser.close();
console.log('Nexvary Panel 0.9 approved Andalusian/Fatiha Chromium gate: PASS');
