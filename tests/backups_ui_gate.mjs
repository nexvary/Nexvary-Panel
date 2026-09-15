import { chromium } from 'playwright';
import fs from 'node:fs';

const base = process.env.NVP_BASE_URL || 'http://127.0.0.1:8000';
const password = process.env.NVP_TEST_PASSWORD;
if (!password) throw new Error('NVP_TEST_PASSWORD is required');
const out = process.env.NVP_SCREENSHOT_DIR || 'tests/artifacts';
fs.mkdirSync(out, { recursive: true });

const browser = await chromium.launch({ headless: true });
const page = await browser.newPage({ viewport: { width: 1440, height: 1050 } });
await page.goto(`${base}/login`, { waitUntil: 'networkidle' });
await page.locator('input[name="username"]').fill('admin');
await page.locator('input[name="password"]').fill(password);
await page.locator('button').filter({ hasText: 'دخول آمن' }).click();
await page.waitForURL(url => url.pathname === '/' || url.pathname === '', { timeout: 15000 });
await page.locator('#nav a[href="#backups"]').click();
await page.locator('#backups.active-view').waitFor({ state: 'visible' });

if (await page.locator('#backups .workspace-hero').count() !== 1) throw new Error('Recovery Vault hero missing');
if (await page.locator('#backups .backup-timeline').count() !== 1) throw new Error('Recovery timeline missing');
if (await page.locator('#backups .creation-panel').count() !== 1) throw new Error('Backup creation panel missing');
if (await page.locator('#backups form[action="/backups"]').count() !== 1) throw new Error('Backup creation form missing');
if (await page.evaluate(() => document.documentElement.scrollWidth > document.documentElement.clientWidth + 2)) throw new Error('Backups workspace has horizontal overflow');

await page.screenshot({ path: `${out}/nexvary-panel-0.6-backups-desktop.png`, fullPage: true });
await browser.close();
console.log('Nexvary Panel Recovery Vault screenshot gate: PASS');
