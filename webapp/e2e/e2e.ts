// Verification harness: exercises the SAME source modules the SPA ships,
// against a running lab, from node. Not part of the app bundle.
// config-shim MUST stay the first import: it supplies src/config.ts's runtime
// configuration from TDF_* env vars before any module reads it.
import './config-shim';
import { createClients, encryptToTdf, decryptTdf } from '../src/tdf';
import { fetchPolicy, allValues } from '../src/policy';
import { openTdfFile, policyAttributes } from '../src/manifest';
import { getRpcCalls } from '../src/rpc';
import {
  attributeSetKey,
  deleteFile,
  downloadFile,
  guessAccess,
  listFiles,
  uploadFile,
  setApiBase,
  ShareApiError,
} from '../src/share';
import {
  buildSealedHtml,
  extractSealedTdf,
  looksLikeSealedHtml,
  sealedHtmlName,
  sealedRuntimeScript,
  unwrapIfHtml,
  WrapperError,
} from '../src/wrapper/html';
import { readFileSync, mkdirSync, writeFileSync } from 'node:fs';
import { createHash } from 'node:crypto';

const SECRET = 'https://lab.example/attr/classification/value/secret';
const PUBLIC = 'https://lab.example/attr/classification/value/public';

let failures = 0;
function check(label: string, actual: string, expected: string) {
  const ok = actual === expected;
  if (!ok) failures++;
  console.log(`    ${ok ? 'PASS' : 'FAIL'}  ${label}: got ${actual}${ok ? '' : `, expected ${expected}`}`);
}
function outcomeOf(o: Awaited<ReturnType<typeof decryptTdf>>): string {
  return o.outcome === 'granted' ? 'granted' : `${o.outcome}/${o.kind}`;
}
function tok(name: string) {
  const v = process.env[name];
  if (!v) throw new Error(`missing ${name}`);
  return async () => v;
}
const bytes = (p: string) => new Uint8Array(readFileSync(p));

/** HTTP status a share-API call produced, or 'ok'. */
async function status(fn: () => Promise<unknown>): Promise<string> {
  try {
    await fn();
    return 'ok';
  } catch (err) {
    if (err instanceof ShareApiError) return String(err.status);
    return `threw:${(err as Error).name}`;
  }
}

async function main() {
  // Node's fetch cannot resolve a relative URL; the browser can and does.
  if (process.env.API_BASE) setApiBase(process.env.API_BASE);
  const userAToken = tok('USER_A_TOKEN');
  const userBToken = tok('USER_B_TOKEN');
  const userA = createClients(userAToken);
  const userB = createClients(userBToken);

  console.log('--- policy read (user-a)');
  const policy = await fetchPolicy(userA);
  console.log('    values', allValues(policy).map((v) => `${v.attribute}/${v.label} [${v.rule}]`));
  check('subject mappings present (secret + public)', String(policy.subjectMappings.length), '2');

  console.log('--- parse an otdfctl-produced .tdf with the app zip reader');
  const cli = await openTdfFile(bytes('/tmp/lab-secret.txt.tdf'), 'lab-secret.txt.tdf');
  check('policy attrs decoded', String(policyAttributes(cli.policy)), SECRET);

  console.log('--- encrypt with the app SDK path (user-a)');
  const file = new File([new TextEncoder().encode('the eagle lands at dawn\n')], 'browser-secret.txt', { type: 'text/plain' });
  const sealed = await encryptToTdf(userA, file, [SECRET]);
  const parsed = await openTdfFile(sealed.bytes, sealed.filename);
  check('sealed policy carries the attribute', String(policyAttributes(parsed.policy)), SECRET);

  console.log('--- the ALLOW / DENY pair');
  check('user-a opens the secret file', outcomeOf(await decryptTdf(userA, sealed.bytes)), 'granted');
  check('user-b is refused', outcomeOf(await decryptTdf(userB, sealed.bytes)), 'refused/denied');

  console.log('--- classification/public is satisfiable (subject mapping from lab journal §6d)');
  check('user-b opens a public-attributed file', outcomeOf(await decryptTdf(userB, bytes('/tmp/lab-public.txt.tdf'))), 'granted');
  check('user-a (secret) also opens public', outcomeOf(await decryptTdf(userA, bytes('/tmp/lab-public.txt.tdf'))), 'granted');

  console.log('--- an edited policy is a binding mismatch, not a denial');
  check('tampered policy', outcomeOf(await decryptTdf(userA, bytes('/tmp/lab-tampered.tdf'))), 'refused/policy-binding');

  console.log('--- REGRESSION: a denial must not explain a LATER, different failure');
  check('  1. user-b denied (seeds the global trace)', outcomeOf(await decryptTdf(userB, sealed.bytes)), 'refused/denied');
  const d2 = await decryptTdf(userA, bytes('/tmp/lab-corrupt-payload.tdf'));
  check('  2. corrupted payload: rewrap OK, integrity fails', outcomeOf(d2), 'refused/integrity');
  if (d2.outcome === 'refused') check('  3. must NOT quote the earlier denial', String(d2.serviceCode ?? 'none'), 'none');

  console.log('--- truncated vs not-a-zip read differently');
  for (const [label, path] of [['truncated', '/tmp/lab-truncated.tdf'], ['not a zip', '/tmp/lab-notazip.tdf']] as const) {
    try {
      await openTdfFile(bytes(path), path);
      console.log(`    FAIL  ${label}: expected a throw`);
      failures++;
    } catch (e) {
      console.log(`    ${label}: ${(e as Error).message.slice(0, 66)}...`);
    }
  }

  // =========================================================================
  //  SHARED LIBRARY
  // =========================================================================
  console.log('\n=== shared library (tdf-share-api behind the nginx same-origin proxy) ===');

  console.log('--- auth is required and really verified');
  check('no token', await status(() => listFiles(async () => '')), '401');
  check('garbage token', await status(() => listFiles(async () => 'not.a.jwt')), '401');
  const unsigned =
    Buffer.from(JSON.stringify({ alg: 'none', typ: 'JWT' })).toString('base64url') +
    '.' +
    Buffer.from(
      JSON.stringify({
        sub: 'x',
        iss: 'https://keycloak.lab.example/realms/lab-realm',
        aud: 'https://platform.lab.example',
        preferred_username: 'user-a',
        azp: 'web-console',
        exp: 9999999999,
      }),
    ).toString('base64url') +
    '.';
  check('well-formed but unsigned token', await status(() => listFiles(async () => unsigned)), '401');
  if (process.env.EXPIRED_TOKEN) {
    check('expired token', await status(() => listFiles(tok('EXPIRED_TOKEN'))), '401');
  }
  check('valid user-a token', await status(() => listFiles(userAToken)), 'ok');

  console.log('--- user-a publishes a secret file; user-b can SEE and FETCH but not READ it');
  const published = await uploadFile(userAToken, sealed.bytes, 'canary.txt.tdf');
  check('attributes come from the MANIFEST, not the client', String(published.attributes), SECRET);
  check('uploader comes from the verified token', published.uploader, 'user-a');

  const asUserB = await listFiles(userBToken);
  const seen = asUserB.files.find((f) => f.id === published.id);
  check("user-b sees user-a's file in the listing", seen ? 'yes' : 'no', 'yes');
  check('and it is not marked as his', String(seen?.mine), 'false');

  const fetched = await downloadFile(userBToken, published.id);
  check(
    'bytes user-b gets are identical to what user-a uploaded',
    String(Buffer.compare(Buffer.from(fetched), Buffer.from(sealed.bytes)) === 0),
    'true',
  );
  check('POSSESSION IS NOT ACCESS: user-b decrypting it', outcomeOf(await decryptTdf(userB, fetched)), 'refused/denied');

  console.log('--- user-b publishes a public file; user-a opens it');
  const pubFile = new File([new TextEncoder().encode('notice: everyone can read this\n')], 'notice.txt', { type: 'text/plain' });
  const userBSealed = await encryptToTdf(userB, pubFile, [PUBLIC]);
  const userBPublished = await uploadFile(userBToken, userBSealed.bytes, 'notice.txt.tdf');
  check("user-b's upload carries the public attribute", String(userBPublished.attributes), PUBLIC);
  check(
    'user-a fetches and opens it',
    outcomeOf(await decryptTdf(userA, await downloadFile(userAToken, userBPublished.id))),
    'granted',
  );

  console.log('--- the access hint is a per-file, ANY_OF-safe, last-write-wins memory');
  const obs = new Map<string, { outcome: 'granted' | 'denied'; fileId: string }>();
  obs.set(attributeSetKey([PUBLIC]), { outcome: 'granted', fileId: 'fA' });
  obs.set(attributeSetKey([SECRET]), { outcome: 'denied', fileId: 'fB' });
  check('the exact file you opened -> fact', guessAccess({ id: 'fA', attributes: [PUBLIC] }, obs), 'opened');
  check('the exact file you were refused -> fact', guessAccess({ id: 'fB', attributes: [SECRET] }, obs), 'refused');
  check('another file, same set, granted -> inference', guessAccess({ id: 'fC', attributes: [PUBLIC] }, obs), 'likely-yes');
  check('another file, same set, refused -> inference', guessAccess({ id: 'fD', attributes: [SECRET] }, obs), 'likely-no');
  check('no attributes at all', guessAccess({ id: 'fE', attributes: [] }, obs), 'open-to-all');
  check('never tested', guessAccess({ id: 'fF', attributes: ['https://lab.example/attr/x/value/y'] }, obs), 'unknown');
  // ANY_OF: a grant on {PUBLIC, SECRET} must NOT make a {SECRET}-only file predictable
  const obs2 = new Map(obs);
  obs2.set(attributeSetKey([PUBLIC, SECRET]), { outcome: 'granted', fileId: 'fG' });
  check('a superset grant does NOT leak to a subset file', guessAccess({ id: 'fH', attributes: [SECRET] }, obs2), 'likely-no');
  // last write wins: a later denial replaces an earlier grant for the same set
  const obs3 = new Map<string, { outcome: 'granted' | 'denied'; fileId: string }>();
  obs3.set(attributeSetKey([PUBLIC]), { outcome: 'granted', fileId: 'x1' });
  obs3.set(attributeSetKey([PUBLIC]), { outcome: 'denied', fileId: 'x2' });
  check('a later denial supersedes an earlier grant', guessAccess({ id: 'x3', attributes: [PUBLIC] }, obs3), 'likely-no');

  console.log('--- S1: a realm ID token (has the API audience via the mapper) must be REJECTED');
  if (process.env.ID_TOKEN) {
    check('ID token rejected', await status(() => listFiles(tok('ID_TOKEN'))), '401');
  } else {
    console.log('    (skipped: no ID_TOKEN in env)');
  }

  console.log('--- S5: structurally-fake TDFs are rejected (honestly not "verified")');
  check('fake: empty wrappedKey + empty binding', await status(() => uploadFile(userAToken, bytes('/tmp/fake-nokeys.tdf'), 'f.tdf')), '400');
  check('fake: no policyBinding at all', await status(() => uploadFile(userAToken, bytes('/tmp/fake-nobinding.tdf'), 'f.tdf')), '400');

  console.log('--- S3: a manifest whose declared size lies about a 2MB body is rejected');
  check('oversize-manifest lie', await status(() => uploadFile(userAToken, bytes('/tmp/lie-manifest-size.tdf'), 'f.tdf')), '400');

  console.log('--- validation: the server will not store something that is not a TDF');
  check('junk body', await status(() => uploadFile(userAToken, new TextEncoder().encode('hello'), 'junk.tdf')), '400');
  check('truncated .tdf', await status(() => uploadFile(userAToken, bytes('/tmp/lab-truncated.tdf'), 't.tdf')), '400');
  check('a real zip that is not a TDF', await status(() => uploadFile(userAToken, bytes('/tmp/lab-plainzip.zip'), 'z.tdf')), '400');
  check('oversize (21MB, cap 20MB)', await status(() => uploadFile(userAToken, new Uint8Array(21 * 1024 * 1024), 'big.tdf')), '413');

  console.log('--- ids are server UUIDs; nothing caller-supplied reaches the filesystem');
  // '.' and '../x' are normalised away by URL parsing before the request is
  // even sent, so what the API sees is `/files/` - which must NOT fall through
  // to the listing. Strict routing makes that a 404.
  for (const bad of ['../index.json', '..%2Findex.json', 'not-a-uuid', '%2e%2e%2fetc%2fpasswd', '.']) {
    const st = await status(() => downloadFile(userAToken, bad));
    const rejected = st !== 'ok';
    if (!rejected) failures++;
    console.log(`    ${rejected ? 'PASS' : 'FAIL'}  GET id=${JSON.stringify(bad)} rejected with ${st}`);
  }
  check('a well-formed but unknown UUID', await status(() => downloadFile(userAToken, '00000000-0000-0000-0000-000000000000')), '404');

  console.log('--- deletion is uploader-only, compared by token SUBJECT');
  check("user-b deleting user-a's file", await status(() => deleteFile(userBToken, published.id)), '403');
  check('user-b deleting its own file', await status(() => deleteFile(userBToken, userBPublished.id)), 'ok');
  check('user-a deleting its own file', await status(() => deleteFile(userAToken, published.id)), 'ok');
  check('deleting it a second time', await status(() => deleteFile(userAToken, published.id)), '404');

  const finalList = await listFiles(userAToken);
  console.log(`    library now holds ${finalList.files.length} file(s); user-a usage ${finalList.usage.files} files / ${finalList.usage.bytes} bytes`);

  // =========================================================================
  //  HTML-WRAPPED TDF  (section 10l)
  // =========================================================================
  console.log('\n=== self-decrypting HTML wrapper ===');

  const OUT = 'e2e/out';
  mkdirSync(OUT, { recursive: true });

  console.log('--- W1: the wrapper is ONE self-contained file');
  const wrapped = buildSealedHtml({ tdf: sealed.bytes, filename: sealed.filename });
  writeFileSync(`${OUT}/sealed-secret.html`, wrapped, 'utf8');
  check('name is <file>.html', sealedHtmlName(sealed.filename), `${sealed.filename}.html`);
  // The bundled SDK legitimately contains the characters `<script` inside
  // string literals; only `</script` can end the element, so THAT is the
  // invariant worth asserting on the text.
  check('exactly one </script> in the document', String((wrapped.match(/<\/script/g) ?? []).length), '1');
  check('it carries its whole runtime inline (> 300 KB)', String(wrapped.length > 300 * 1024), 'true');
  check('no <link>, <img>, <iframe> or <object>', String(/<(link|img|iframe|object|embed)\b/i.test(wrapped)), 'false');
  // Nothing may be fetched at load time. `src=`/`href=` must not appear at all;
  // the one runtime the page can ever load is set from JS, only on the trusted
  // origin, and only from a hardcoded same-origin absolute path.
  check('no src= or href= anywhere in the markup', String(/\s(src|href)\s*=/i.test(wrapped)), 'false');
  check('it references no companion runtime file', String(/sealed\/runtime\.js/.test(wrapped)), 'false');
  check('the runtime carries no deployment hostname', String(sealedRuntimeScript().includes(new URL(process.env.TDF_PLATFORM_URL ?? 'https://platform.lab.example').host)), 'false');
  check('no template placeholder survived substitution', String(wrapped.includes('__TDF_B64__') || wrapped.includes('__META_B64__')), 'false');
  const metaB64 = /id="meta-input" value="([^"]*)"/.exec(wrapped)?.[1] ?? '';
  const meta = JSON.parse(Buffer.from(metaB64, 'base64').toString('utf8')) as { origin?: string; filename?: string; cfg?: { wrapperClientId?: string } };
  check('the console origin is baked in as base64 metadata', String(meta.origin), process.env.TDF_APP_ORIGIN ?? 'https://tdf.lab.example');
  check('the device grant client travels in the metadata', String(meta.cfg?.wrapperClientId), process.env.TDF_OIDC_WRAPPER_CLIENT_ID ?? 'wrapper');

  console.log('--- W2: the embedded ciphertext round-trips through the normal path');
  const back = extractSealedTdf(new TextEncoder().encode(wrapped));
  check(
    'extracted bytes are byte-identical to the .tdf',
    String(Buffer.compare(Buffer.from(back.bytes), Buffer.from(sealed.bytes)) === 0),
    'true',
  );
  check('the display name survives', String(back.filename), sealed.filename);
  const fromWrapper = await decryptTdf(userA, back.bytes);
  check('user-a decrypts the extracted payload', outcomeOf(fromWrapper), 'granted');
  if (fromWrapper.outcome === 'granted') {
    check('plaintext matches the original', fromWrapper.text ?? '', 'the eagle lands at dawn\n');
  }
  check('a .tdf passes through unwrapIfHtml untouched', String(unwrapIfHtml(sealed.bytes, 'x.tdf').bytes === sealed.bytes), 'true');
  check('looksLikeSealedHtml says no to a .tdf', String(looksLikeSealedHtml(sealed.bytes)), 'false');
  check('looksLikeSealedHtml says yes to the wrapper', String(looksLikeSealedHtml(new TextEncoder().encode(wrapped))), 'true');

  console.log('--- W3: the format is the one the SDK\'s legacy reader still accepts');
  // @opentdf/sdk 0.20.0 removed every HTML *write* path (setHtmlFormat /
  // withHtmlFormat / asHtml all throw ConfigurationError) but kept unwrapHtml()
  // on the tdf3 read path. This is that function's own regex, run against what
  // we emit. Imported by relative path because the package `exports` map does
  // not publish it.
  const sdkUnwrap = await import('../node_modules/@opentdf/sdk/dist/web/tdf3/src/utils/unwrap.js')
    .then((m) => m.unwrapHtml as (b: Uint8Array) => Uint8Array)
    .catch(() => null);
  if (sdkUnwrap) {
    const viaSdk = sdkUnwrap(new TextEncoder().encode(wrapped));
    check(
      "the SDK's own unwrapHtml() recovers the same bytes",
      String(Buffer.compare(Buffer.from(viaSdk), Buffer.from(sealed.bytes)) === 0),
      'true',
    );
  } else {
    console.log('    (skipped: the SDK deep path did not resolve)');
    failures++;
  }

  console.log('--- W4: a hostile manifest and a hostile filename cannot inject');
  const HOSTILE_NAME = '"><script>window.__pwned=1</script><img src=x onerror=alert(1)>.tdf';
  const hostileTdf = bytes('/tmp/lab-hostile.tdf');
  const hostileWrapped = buildSealedHtml({ tdf: hostileTdf, filename: HOSTILE_NAME });
  writeFileSync(`${OUT}/sealed-hostile.html`, hostileWrapped, 'utf8');
  check('still exactly one </script>', String((hostileWrapped.match(/<\/script/g) ?? []).length), '1');
  check('the hostile filename appears nowhere in the source', String(hostileWrapped.includes('window.__pwned')), 'false');
  check('no onerror= / onload= handler was introduced', String(/\son(error|load|click)\s*=/i.test(hostileWrapped)), 'false');
  check('no <img> was introduced', String(/<img\b/i.test(hostileWrapped)), 'false');
  check('no <svg> was introduced', String(/<svg\b/i.test(hostileWrapped)), 'false');
  // The structural guarantee, stated as an assertion: the ONLY difference
  // between the shipped page and the template is two pure-base64 substitutions.
  const template = readFileSync('src/wrapper/generated/page.html', 'utf8');
  const b64Only = /^[A-Za-z0-9+/]*={0,2}$/;
  const slots = /id="(?:data|meta)-input" value="([^"]*)"/g;
  const emitted: string[] = [];
  for (const m of hostileWrapped.matchAll(slots)) emitted.push(m[1]);
  check('both substituted slots are pure base64', String(emitted.length === 2 && emitted.every((v) => b64Only.test(v))), 'true');
  check(
    'the page is the template with only those two values substituted',
    String(
      hostileWrapped
        .replace(emitted[0] ?? '\u0000', '__TDF_B64__')
        .replace(emitted[1] ?? '\u0000', '__META_B64__') === template,
    ),
    'true',
  );
  // and the hostile attribute really is in there, so the browser check has
  // something to prove it renders as TEXT
  const hostileFacts = await openTdfFile(hostileTdf, 'hostile.tdf');
  check(
    'the fixture really carries an HTML attribute FQN',
    String(policyAttributes(hostileFacts.policy).some((a) => a.includes('<script>'))),
    'true',
  );

  console.log('--- W5: the generator refuses what it cannot make safe');
  check('empty input', await status(async () => buildSealedHtml({ tdf: new Uint8Array(0), filename: 'x' })), 'threw:WrapperError');
  check('over the size cap', await status(async () => buildSealedHtml({ tdf: new Uint8Array(9 * 1024 * 1024), filename: 'x' })), 'threw:WrapperError');
  check(
    'a non-https console origin',
    await status(async () => buildSealedHtml({ tdf: sealed.bytes, filename: 'x', consoleOrigin: 'http://evil.example' })),
    'threw:WrapperError',
  );
  check(
    'an HTML file with no payload',
    await status(async () => extractSealedTdf(new TextEncoder().encode('<!doctype html><html><body>hi</body></html>'))),
    'threw:WrapperError',
  );
  if (!(new WrapperError('x') instanceof Error)) failures++;

  console.log('--- W7: bidi / invisible characters are stripped from a display name');
  // U+202E RIGHT-TO-LEFT OVERRIDE is the classic filename spoof: it makes
  // `report<RLO>lmth.fdt.pdf` render as something ending in .pdf while the file
  // is really .tdf.html. Worth nothing against the injection boundary here (a
  // filename never reaches markup) and a great deal against a human deciding
  // whether to open an executable document, which is what this feature emits.
  const SPOOF = 'report\u202Elmth.fdt\u200B.pdf';
  const spoofed = buildSealedHtml({ tdf: sealed.bytes, filename: SPOOF });
  const spoofMetaB64 = /id="meta-input" value="([^"]*)"/.exec(spoofed)?.[1] ?? '';
  const spoofMeta = JSON.parse(Buffer.from(spoofMetaB64, 'base64').toString('utf8')) as { filename?: string };
  check('U+202E is stripped from the stored name', String(/\u202e/.test(spoofMeta.filename ?? '')), 'false');
  check('U+200B is stripped too', String(/\u200b/.test(spoofMeta.filename ?? '')), 'false');
  check('the visible characters survive', String(spoofMeta.filename), 'reportlmth.fdt.pdf');
  check('the saved-as name still ends .html', String(/\.html$/.test(sealedHtmlName(SPOOF))), 'true');
  check('and carries no override character', String(/[\u061c\u200b-\u200f\u202a-\u202e\u2066-\u2069]/.test(sealedHtmlName(SPOOF))), 'false');
  check(
    'a name that is ONLY spoofing characters falls back',
    sealedHtmlName('\u202e\u200b\u2066'),
    'sealed.tdf.html',
  );
  // and the same rule on the way back in, for a hand-crafted wrapper
  const spoofBack = extractSealedTdf(new TextEncoder().encode(spoofed));
  check('the extractor returns the cleaned name', String(spoofBack.filename), 'reportlmth.fdt.pdf');

  console.log('--- W8: a payload beyond the read ceiling is refused before it is decoded');
  const huge = `<!doctype html><html><body><input id="data-input" value="${'A'.repeat(40 * 1024 * 1024)}"></body></html>`;
  check('oversize embedded payload', await status(async () => extractSealedTdf(new TextEncoder().encode(huge))), 'threw:WrapperError');

  console.log('--- W6: the inline runtime is byte-stable, so its CSP hash is too');
  const script = sealedRuntimeScript();
  const scriptFromPage = /<script>([\s\S]*?)<\/script>/.exec(wrapped)?.[1] ?? '';
  const scriptFromHostile = /<script>([\s\S]*?)<\/script>/.exec(hostileWrapped)?.[1] ?? '';
  check('the emitted script equals the template script', String(script === scriptFromPage), 'true');
  check('and is identical across two different payloads', String(scriptFromPage === scriptFromHostile), 'true');
  const sha = createHash('sha256').update(script, 'utf8').digest('base64');
  writeFileSync(`${OUT}/runtime-sha256.txt`, sha, 'utf8');
  console.log(`    CSP hash for nginx location /sealed/:  'sha256-${sha}'`);

  console.log(`    wrote ${OUT}/sealed-secret.html and ${OUT}/sealed-hostile.html for the browser check`);

  console.log('\n--- rpc trace (last 6)');
  for (const call of getRpcCalls().slice(-6)) {
    console.log(`    ${call.ok ? 'ok ' : 'ERR'} ${call.path} ${call.durationMs.toFixed(0)}ms ${call.code ?? ''}`);
  }

  console.log(failures === 0 ? '\nALL CHECKS PASSED' : `\n${failures} CHECK(S) FAILED`);
  process.exit(failures === 0 ? 0 : 1);
}

main().catch((e) => {
  console.error('HARNESS FAILED', e);
  process.exit(1);
});
