// Layout regression check against a RUNNING console (APP_URL), driven by a
// real headless Chromium via playwright-core. Not part of the app bundle.
//
// It exists because two earlier CSS fixes moved the number a reviewer had
// quoted without moving the user's experience: the mobile nav measured 45.75px
// tall while being 0/5 clickable, because the rail was overflowing a 1px grid
// row that .stage then painted over. So this HIT-TESTS and CLICKS rather than
// reading getBoundingClientRect(). See lab journal §10i.
//
//   APP_URL=https://tdf.lab.example/ \
//   USER_B_PASSWORD=$(grep -oP '(?<=^USER_B_PASSWORD=).*' ../.env) \
//     node e2e/browser-check.mjs
//
// Expected tail: ALL BROWSER CHECKS PASSED
import { execSync } from 'node:child_process';
// playwright-core is NOT a dependency of the app. Point PLAYWRIGHT_CORE_DIR at
// an installed playwright-core package (for example one fetched by
// `npx playwright install chromium`, or a global install), and CHROMIUM_PATH
// at a Chromium binary. Both default to "resolve it yourself" rather than a
// path on any particular machine.
const PW_DIR = process.env.PLAYWRIGHT_CORE_DIR
  || execSync("find \"${HOME}/.npm/_npx\" -maxdepth 6 -type d -name playwright-core 2>/dev/null | head -1", { encoding: 'utf8', shell: '/bin/sh' }).trim();
if (!PW_DIR) throw new Error('playwright-core not found: set PLAYWRIGHT_CORE_DIR');
const { chromium } = await import(`${PW_DIR}/index.mjs`);
const EXE = process.env.CHROMIUM_PATH || undefined; // undefined = playwright's own bundled browser
const APP = process.env.APP_URL || 'https://tdf.lab.example/';
import { writeFileSync, readFileSync, copyFileSync, existsSync, unlinkSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { resolve } from 'node:path';
const PW = process.env.USER_B_PASSWORD;
const USER_A_PW = process.env.USER_A_PASSWORD;
let fails = 0;
const ok = (c, m) => { console.log(`  ${c ? 'PASS' : 'FAIL'}  ${m}`); if (!c) fails++; };

const b = await chromium.launch({ executablePath: EXE, args: ['--no-sandbox'] });
const ctx = await b.newContext({ viewport: { width: 1440, height: 900 }, ignoreHTTPSErrors: true });
const p = await ctx.newPage();
const errs = [];
p.on('console', m => { if (m.type() === 'error') errs.push(m.text()); });

await p.goto(APP, { waitUntil: 'networkidle' });
await p.getByRole('button', { name: /sign in as user-b/i }).click();
await p.waitForURL(/keycloak\.lab\.example/, { timeout: 20000 });
await p.fill('#username', 'user-b'); await p.fill('#password', PW);
await p.click('#kc-login');
await p.waitForURL(u => u.host === new URL(APP).host, { timeout: 20000 });
await p.waitForSelector('.rail', { timeout: 15000 });
console.log('LOGIN: landed on', p.url().split('?')[0], '- redirect_uri exact-match round-trip OK\n');

// ---------- U1: hit-test every nav item across the whole mobile band --------
console.log('U1 - mobile nav must be CLICKABLE (hit-tested, not measured):');
for (const w of [360, 390, 414, 600, 768, 780]) {
  await p.setViewportSize({ width: w, height: 844 });
  await p.waitForTimeout(180);
  const r = await p.evaluate(() => {
    const rail = document.querySelector('.rail');
    const row1 = getComputedStyle(document.querySelector('.workspace')).gridTemplateRows.split(' ')[0];
    const btns = [...rail.querySelectorAll('.rail__item')];
    const clickable = btns.filter(el => {
      const b = el.getBoundingClientRect();
      const hit = document.elementFromPoint(b.left + b.width / 2, b.top + b.height / 2);
      return el.contains(hit) || el === hit;
    }).length;
    return { row1, h: rail.clientHeight, n: btns.length, clickable,
             sw: document.documentElement.scrollWidth, iw: window.innerWidth };
  });
  ok(r.clickable === r.n && r.h > 20, `w=${w}  row1=${r.row1}  railH=${r.h}  clickable=${r.clickable}/${r.n}`);
}
// a REAL mouse click, the thing that actually failed before
await p.setViewportSize({ width: 390, height: 844 });
await p.waitForTimeout(200);
await p.locator('.rail__item', { hasText: /decrypt/i }).first().click({ timeout: 8000 });
await p.waitForTimeout(400);
ok(await p.locator('text=Ask the key server to unwrap').isVisible(), 'real mouse click on DECRYPT at 390px opens the panel');
await p.screenshot({ path: '/tmp/pwv/u1-mobile.png' });

// ---------- U6: horizontal overflow sweep, both panels ----------------------
console.log('\nU6 - no horizontal overflow (scrollWidth <= innerWidth + 1):');
for (const panel of ['Policy', 'Encrypt']) {
  await p.setViewportSize({ width: 1280, height: 900 });
  await p.waitForTimeout(150);
  await p.locator('.rail__item', { hasText: new RegExp(panel, 'i') }).first().click();
  await p.waitForTimeout(500);
  const row = [];
  for (const w of [360, 390, 414, 781, 850, 950, 1000, 1240, 1280]) {
    await p.setViewportSize({ width: w, height: 900 });
    await p.waitForTimeout(160);
    const m = await p.evaluate(() => ({ sw: document.documentElement.scrollWidth, iw: window.innerWidth }));
    row.push(`${w}:${m.sw - m.iw > 1 ? `OVER+${m.sw - m.iw}` : 'ok'}`);
    if (m.sw - m.iw > 1) fails++;
  }
  console.log(`  ${(row.every(x => x.endsWith('ok')) ? 'PASS' : 'FAIL')}  ${panel.padEnd(8)} ${row.join('  ')}`);
}

// ---------- regression guard on the previously-passing items ---------------
await p.setViewportSize({ width: 1440, height: 900 });
await p.locator('.rail__item', { hasText: /encrypt/i }).first().click();
await p.waitForTimeout(400);
console.log('\nRegression guard on the four already-passing fixes:');
const d = await p.evaluate(() => {
  const lead = document.querySelector('.drop__lead'), hint = document.querySelector('.drop__hint');
  return { leadTop: lead.getBoundingClientRect().top, hintTop: hint.getBoundingClientRect().top };
});
ok(d.hintTop > d.leadTop + 8, `U7 drop lines separated (lead ${d.leadTop.toFixed(0)} / hint ${d.hintTop.toFixed(0)})`);
ok(errs.length === 0, `no console errors (${errs.length})` + (errs.length ? ': ' + errs.slice(0,2).join(' | ') : ''));
await p.screenshot({ path: '/tmp/pwv/u7-desktop.png' });

// ---------- B1: the 781-1240 band at a REAL short viewport -----------------
// The stage grid row was capped to a fraction of the viewport height; taller
// content overflowed and the opaque .aside painted over it, eating clicks. The
// bug is width AND content-height dependent, so this runs at a real 1024x768 -
// a tall window would hide it. Hit-test, do not measure (lab journal §10i).
console.log('\nB1 - 1024x768: stage reachable, aside not covering it, 6/6 rail clickable, OPEN clickable:');
await p.setViewportSize({ width: 1440, height: 900 });
await p.locator('.rail__item', { hasText: /library/i }).first().click();
await p.waitForTimeout(1200);
await p.setViewportSize({ width: 1024, height: 768 });
await p.waitForTimeout(350);
const b1 = await p.evaluate(() => {
  const rail = document.querySelector('.rail');
  const items = [...rail.querySelectorAll('.rail__item')];
  const clickable = items.filter(el => {
    const r = el.getBoundingClientRect();
    const hit = document.elementFromPoint(r.left + r.width / 2, r.top + r.height / 2);
    return el.contains(hit) || el === hit;
  }).length;
  // the primary Open button of the first library row must be hit-testable and
  // NOT be intercepted by the opaque .aside painting over the stage. Scroll it
  // into view first: the bug is the aside COVERING it, not its being below the
  // fold (the page is allowed to scroll).
  const openBtn = document.querySelector('.lib__row .btn--primary');
  let openHit = false, coveredByAside = false, hitTag = 'none';
  if (openBtn) {
    openBtn.scrollIntoView({ block: 'center' });
    const r = openBtn.getBoundingClientRect();
    const hit = document.elementFromPoint(r.left + r.width / 2, r.top + r.height / 2);
    openHit = !!hit && (openBtn.contains(hit) || openBtn === hit);
    coveredByAside = !!(hit && hit.closest && hit.closest('.aside'));
    hitTag = hit ? `${hit.tagName}.${(hit.className || '').toString().split(' ')[0]}` : 'null';
  }
  return { clickable, n: items.length, openHit, coveredByAside, hitTag, hasOpen: !!openBtn,
           sw: document.documentElement.scrollWidth, iw: window.innerWidth };
});
ok(b1.clickable === b1.n && b1.n === 6, `6/6 rail items hit-testable (${b1.clickable}/${b1.n})`);
ok(b1.hasOpen && b1.openHit && !b1.coveredByAside, `OPEN hit-testable, not covered by aside (hit=${b1.openHit} aside=${b1.coveredByAside} got=${b1.hitTag})`);
ok(b1.sw - b1.iw <= 1, `no horizontal overflow at 1024px (sw=${b1.sw} iw=${b1.iw})`);
// a REAL click on OPEN - the interaction that was eaten before the fix
if (b1.hasOpen) {
  await p.locator('.lib__row .btn--primary').first().click({ timeout: 8000 });
  await p.waitForTimeout(1500);
  ok(await p.locator('.lib__flow .fl').first().isVisible().catch(() => false),
     'a real mouse click on OPEN at 1024x768 starts the flow');
}
await p.screenshot({ path: '/tmp/pwv/b1-1024.png' });
await p.setViewportSize({ width: 1440, height: 900 });

// ---------- LIBRARY: the real product journey, in a real browser ----------
console.log('\nLIBRARY - publish, list, open:');
await p.setViewportSize({ width: 1440, height: 900 });
await p.locator('.rail__item', { hasText: /library/i }).first().click();
await p.waitForTimeout(1200);
ok(await p.locator('text=Everyone holds every file').isVisible(), 'library panel renders');

// publish a public-attributed file as user-b
const tmp = '/tmp/pw-library-note.txt';
writeFileSync(tmp, 'published from a real browser\n');
await p.locator('.panel', { hasText: 'PUBLISH A FILE' }).locator('input[type=file]').setInputFiles(tmp);
await p.waitForTimeout(300);
await p.locator('.chip', { hasText: /public/ }).first().click();
await p.getByRole('button', { name: /seal and publish/i }).click();
await p.waitForTimeout(9000);
const rows = await p.locator('.lib__row').count();
ok(rows > 0, `file appears in the listing (${rows} row(s))`);
ok(await p.locator('.lib__row .tag', { hasText: 'yours' }).first().isVisible(), 'it is marked as user-b\'s own');

// open it - user-b holds classification=public and the 6d mapping accepts public
await p.locator('.lib__row').first().getByRole('button', { name: /^open$/i }).click();
await p.waitForTimeout(9000);
const granted = await p.locator('.outcome--granted .outcome__flag').first().isVisible().catch(() => false);
ok(granted, 'OPEN yields ACCESS GRANTED for an entitled account');
ok(await p.locator('text=published from a real browser').isVisible().catch(() => false), 'the plaintext is shown inline');
await p.screenshot({ path: '/tmp/pwv/library.png', fullPage: false });

// possession is free: the sealed download affordance is present for every row
ok(await p.locator('.lib__row').first().getByRole('button', { name: /get \.tdf/i }).isVisible(), 'a sealed-download button is offered');

// clean up so repeated runs do not pile up. Delete is two-click by design:
// the first arms "Confirm delete", the second actually removes it.
{
  const mine = p.locator('.lib__row', { hasText: 'pw-library-note' }).first();
  await mine.getByRole('button', { name: /^delete$/i }).click();
  await p.waitForTimeout(250);
  await mine.getByRole('button', { name: /confirm delete/i }).click();
  await p.waitForTimeout(2500);
  ok((await p.locator('.lib__row', { hasText: 'pw-library-note' }).count()) === 0, 'two-click delete removes the file it published');
}

// ---------- LIGHT THEME ----------------------------------------------------
console.log('\nLIGHT THEME:');
const theme = await p.evaluate(() => {
  const cs = getComputedStyle(document.body);
  const rootCS = getComputedStyle(document.documentElement);
  const lum = (rgb) => { const m = rgb.match(/\d+/g).map(Number); return (0.2126*m[0] + 0.7152*m[1] + 0.0722*m[2]) / 255; };
  return {
    bodyBg: cs.backgroundColor, bodyLum: lum(cs.backgroundColor),
    textLum: lum(cs.color),
    scheme: rootCS.colorScheme,
    darkLeftovers: document.documentElement.getAttribute('data-theme'),
  };
});
ok(theme.bodyLum > 0.85, `page ground is light (luminance ${theme.bodyLum.toFixed(2)}, ${theme.bodyBg})`);
ok(theme.textLum < 0.25, `text is dark ink (luminance ${theme.textLum.toFixed(2)})`);
ok(/light/.test(theme.scheme), `color-scheme is light (${theme.scheme}) so form controls and scrollbars follow`);
ok(!theme.darkLeftovers, `no leftover data-theme attribute (${theme.darkLeftovers})`);

// ---------- PROTOCOL FLOW --------------------------------------------------
console.log('\nPROTOCOL FLOW (deny path):');
await p.setViewportSize({ width: 1440, height: 1000 });
await p.locator('.rail__item', { hasText: /library/i }).first().click();
await p.waitForTimeout(1200);
const secret = p.locator('.lib__row', { hasText: 'eagle-briefing' }).first();
await secret.getByRole('button', { name: /^open$/i }).click();
await p.waitForTimeout(10000);
const flow = await p.evaluate(() => {
  // scope to the flow inside the OPENED library row - the publish panel has
  // its own .fl further up the page
  const row = [...document.querySelectorAll('.lib__row')].find(r => r.textContent.includes('eagle-briefing'));
  const fl = row?.querySelector('.lib__flow .fl');
  if (!fl) return null;
  const rows = [...fl.querySelectorAll('.fl__row')];
  return {
    lanes: [...fl.querySelectorAll('.fl__laneName')].map(e => e.textContent),
    steps: rows.length,
    failed: rows.filter(r => r.className.includes('fl__row--failed')).map(r => r.querySelector('.fl__label')?.textContent),
    skipped: rows.filter(r => r.className.includes('fl__row--skipped')).map(r => r.querySelector('.fl__label')?.textContent),
    badges: [...new Set([...fl.querySelectorAll('.fl__obs')].map(e => e.textContent))],
    laneXs: [...fl.querySelectorAll('.fl__lane')].map(e => Math.round(e.getBoundingClientRect().x)),
    // M2: the dashed lifelines must run the full height of the diagram, not
    // collapse to the ~53px header row (the `2 / -1` -> last-explicit-line bug).
    lifeH: Math.round(Math.max(0, ...[...fl.querySelectorAll('.fl__life')].map(e => e.getBoundingClientRect().height))),
    laneH: Math.round(fl.querySelector('.fl__lane')?.getBoundingClientRect().height || 0),
  };
});
ok(!!flow, 'the flow diagram renders on open');
ok(flow.lanes.length >= 4, `actor lanes present: ${flow.lanes.join(' | ')}`);
ok(flow.laneXs.every((x, i, a) => i === 0 || x > a[i-1]), 'lanes are laid out left-to-right in order');
ok(flow.failed.length === 1 && /Compare your entitlements/i.test(flow.failed[0]), `the run STOPS at the entitlement comparison (${flow.failed[0]})`);
ok(flow.skipped.length >= 1, `downstream steps marked never-reached (${flow.skipped.length})`);
ok(flow.lifeH > flow.laneH * 3, `lifelines span the whole diagram, not just the header (lifeline ${flow.lifeH}px vs lane header ${flow.laneH}px)`);
// all three honesty CATEGORIES must appear. Server-side badges are named after
// the actor that does the work ("inside Platform", "inside Key server"), so
// match the category rather than one literal label.
const hasObserved = flow.badges.includes('observed');
const hasSdk = flow.badges.some(b => /inside the SDK/i.test(b));
const hasServer = flow.badges.some(b => /^inside (Platform|Key server|Keycloak|Library server)$|^server-side$/.test(b));
ok(hasObserved && hasSdk && hasServer, `all three honesty categories present: ${flow.badges.join(', ')}`);
const cmp = await p.locator('.lib__flow .fl__step', { hasText: 'Compare your entitlements' }).first();
await cmp.click(); await p.waitForTimeout(500);
ok(await p.locator('.fl__cmp--failed').isVisible().catch(()=>false), 'the failed comparison expands with both sides shown');
ok(await p.locator('.fl__cmp .tag--failing').first().isVisible().catch(()=>false), 'the required attribute is highlighted as the failing one');
ok(await p.locator('text=Resolved inside the platform').isVisible().catch(()=>false), 'it says plainly that YOUR side was resolved server-side and not disclosed');

// the diagram scrolls inside ITSELF on a phone; the page never scrolls sideways
console.log('\nFLOW ON MOBILE:');
for (const w of [360, 390, 780]) {
  await p.setViewportSize({ width: w, height: 900 });
  await p.waitForTimeout(250);
  const m = await p.evaluate(() => ({
    pageOver: document.documentElement.scrollWidth - window.innerWidth,
    scrollerOver: (() => { const e = document.querySelector('.fl__scroll'); return e ? e.scrollWidth - e.clientWidth : -1; })(),
  }));
  ok(m.pageOver <= 1, `w=${w}: page does not scroll sideways (${m.pageOver}px) while the diagram scrolls within itself (${m.scrollerOver}px)`);
}
await p.setViewportSize({ width: 1440, height: 1000 });


// ---------- W-G: the console's own "wrap as HTML" affordances --------------
console.log('\nW-G - the console offers the wrapper, and what it hands over is a real one:');
{
  await p.setViewportSize({ width: 1440, height: 950 });
  await p.locator('.rail__item', { hasText: /encrypt/i }).first().click();
  await p.waitForTimeout(400);
  const src = '/tmp/pw-wrap-note.txt';
  writeFileSync(src, 'wrapped from a real browser\n');
  await p.locator('.panel', { hasText: 'PAYLOAD' }).locator('input[type=file]').setInputFiles(src);
  await p.waitForTimeout(300);
  await p.locator('.chip', { hasText: /public/ }).first().click();
  await p.getByRole('button', { name: /^encrypt$/i }).click();
  await p.waitForFunction(() => /sealed/i.test(document.body.innerText), { timeout: 30000 });

  ok(await p.locator('[data-testid=wrap-html]').isVisible(), 'Encrypt offers a "Wrap as <name>.html" button');
  ok(/executable document/i.test(await p.evaluate(() => document.body.innerText)),
     'and the console warns, in place, that an HTML wrapper is executable');

  const [dl] = await Promise.all([
    p.waitForEvent('download', { timeout: 20000 }),
    p.locator('[data-testid=wrap-html]').click(),
  ]);
  ok(/\.tdf\.html$/.test(dl.suggestedFilename()), `it saves as <file>.tdf.html (${dl.suggestedFilename()})`);
  const saved = '/tmp/pw-wrapped.html';
  await dl.saveAs(saved);
  const html = readFileSync(saved, 'utf8');
  const b64 = /id="data-input" value="([A-Za-z0-9+/=]+)"/.exec(html)?.[1] ?? '';
  const inner = Buffer.from(b64, 'base64');
  ok(html.startsWith('<!doctype html>'), 'the downloaded file is a complete HTML document');
  ok((html.match(/<script[\s>]/g) ?? []).length === 1, 'with exactly one script');
  ok(inner.length > 0 && inner.subarray(0, 2).toString() === 'PK', `and it really carries a zip/.tdf (${inner.length} bytes, magic ${inner.subarray(0, 2).toString()})`);

  // and the same affordance in the library
  await p.locator('.rail__item', { hasText: /library/i }).first().click();
  await p.waitForTimeout(1500);
  ok(await p.locator('[data-testid=get-html]').first().isVisible(), 'the Library offers "Get .html" per row');
  const [dl2] = await Promise.all([
    p.waitForEvent('download', { timeout: 25000 }),
    p.locator('[data-testid=get-html]').first().click(),
  ]);
  ok(/\.html$/.test(dl2.suggestedFilename()), `Library "Get .html" downloads a wrapper (${dl2.suggestedFilename()})`);
}

// The self-decrypting wrapper has its own suite - `node e2e/wrapper-check.mjs`.
// It needs a second browser context to approve a device code and a different
// fixture lifecycle, so it does not belong inside this one.

console.log(fails === 0 ? '\nALL BROWSER CHECKS PASSED' : `\n${fails} BROWSER CHECK(S) FAILED`);
await b.close();
process.exit(fails ? 1 : 0);
