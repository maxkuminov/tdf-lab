// End-to-end check for the self-decrypting HTML wrapper.
//
// Opens a generated wrapper from a real file:// URL, runs the device
// authorization grant, approves the code in a separate browser context (as a
// real realm user), and asserts the outcome: plaintext for an entitled user,
// a clean refusal with no plaintext for an unentitled one.
//
// Credentials are read from the repo-root .env at runtime (override with
// LAB_ENV=/path/to/.env); no secret appears in this file.
//
//   node e2e/wrapper-check.mjs
//
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
import { readFileSync } from 'node:fs';

const LAB_ENV = process.env.LAB_ENV || new URL('../../.env', import.meta.url).pathname;
const env = Object.fromEntries(
  readFileSync(LAB_ENV, 'utf8')
    .split('\n')
    .filter((l) => /^[A-Z0-9_]+=/.test(l))
    .map((l) => {
      const i = l.indexOf('=');
      return [l.slice(0, i), l.slice(i + 1)];
    }),
);
const KC = `https://${env.TDF_KEYCLOAK_HOST}`;
const CONSOLE_URL = `https://${env.TDF_WEB_HOST}`;

const users = {
  'user-a': { pw: env.USER_A_PASSWORD, expect: 'granted' },
  'user-b': { pw: env.USER_B_PASSWORD, expect: 'refused' },
};

let failures = 0;
const check = (name, ok, detail = '') => {
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${name}${detail ? ' — ' + detail : ''}`);
  if (!ok) failures++;
};

// Approve a device user_code in an isolated context, as `who`.
async function approve(browser, who, userCode) {
  const ctx = await browser.newContext();
  const p = await ctx.newPage();
  await p.goto(`${KC}/realms/lab-realm/device?user_code=${encodeURIComponent(userCode)}`, {
    waitUntil: 'domcontentloaded',
  });
  // Keycloak asks for login first, then shows the consent/approve screen.
  if (await p.locator('#username').count()) {
    await p.fill('#username', who);
    await p.fill('#password', users[who].pw);
    await p.click('#kc-login, input[type=submit]');
    await p.waitForLoadState('domcontentloaded');
  }
  // Device verification / consent: accept whichever affirmative control exists.
  for (const sel of ['#kc-login', 'input[name=accept]', 'button[name=accept]', 'input[type=submit]']) {
    if (await p.locator(sel).count()) {
      await p.click(sel).catch(() => {});
      break;
    }
  }
  await p.waitForLoadState('domcontentloaded').catch(() => {});
  const body = await p.textContent('body').catch(() => '');
  await ctx.close();
  return body || '';
}

async function runFor(browser, who, wrapperPath) {
  const ctx = await browser.newContext();
  const page = await ctx.newPage();
  const errors = [];
  page.on('console', (m) => {
    if (m.type() === 'error') errors.push(m.text());
  });
  await page.goto(`file://${wrapperPath}`, { waitUntil: 'domcontentloaded' });

  check(`[${who}] wrapper renders from file://`, (await page.title()).length > 0);

  // Kick off the device flow.
  const start = page.locator('button', { hasText: /sign in|decrypt|open/i }).first();
  await start.click();

  // Wait for the user code to appear on the page.
  let userCode = null;
  for (let i = 0; i < 40; i++) {
    const txt = await page.textContent('body');
    const m = txt && txt.match(/\b([A-Z]{4}-[A-Z]{4})\b/);
    if (m) { userCode = m[1]; break; }
    await page.waitForTimeout(500);
  }
  check(`[${who}] device user_code shown on the page`, !!userCode, userCode || 'none found');
  if (!userCode) { await ctx.close(); return; }

  await approve(browser, who, userCode);

  // Wait for a terminal verdict.
  let verdict = null;
  for (let i = 0; i < 80; i++) {
    const txt = (await page.textContent('body')) || '';
    if (/ACCESS GRANTED|the eagle lands at dawn/i.test(txt)) { verdict = 'granted'; break; }
    if (/ACCESS DENIED|permission_denied|refused/i.test(txt)) { verdict = 'refused'; break; }
    await page.waitForTimeout(500);
  }
  check(`[${who}] reached a terminal verdict`, !!verdict, verdict || 'timed out');
  check(`[${who}] verdict is ${users[who].expect}`, verdict === users[who].expect, `got ${verdict}`);

  const body = (await page.textContent('body')) || '';
  if (users[who].expect === 'granted') {
    check(`[${who}] plaintext revealed in the page`, /the eagle lands at dawn/i.test(body));
  } else {
    check(`[${who}] NO plaintext anywhere on the page`, !/the eagle lands at dawn/i.test(body));
    check(`[${who}] refusal names permission_denied`, /permission_denied/i.test(body));
  }
  const unexpected = errors.filter(
    (e) => !/BaseKey|Mismatched wrapping key algorithm/.test(e),
  );
  check(`[${who}] no unexpected console errors`, unexpected.length === 0, unexpected.join(' | '));
  await ctx.close();
}

const wrapper = process.argv[2];
if (!wrapper) {
  console.error('usage: node e2e/wrapper-check.mjs /abs/path/to/sealed.tdf.html');
  process.exit(2);
}

const browser = await chromium.launch({
  executablePath: EXE,
  args: ['--no-sandbox', '--allow-file-access-from-files'],
});
for (const who of ['user-a', 'user-b']) await runFor(browser, who, wrapper);
await browser.close();

console.log(failures === 0 ? '\nALL WRAPPER CHECKS PASSED' : `\n${failures} CHECK(S) FAILED`);
process.exit(failures === 0 ? 0 : 1);
