// Stage 2 of the wrapper build: inline the bundled runtime into the page
// template and emit the file the generator actually ships.
//
//   src/wrapper/page.template.html   markup + CSS + <!--SEALED_RUNTIME-->
// + src/wrapper/generated/sealed-page.iife.js
// = src/wrapper/generated/page.html
//
// Two invariants are asserted rather than hoped for, because both fail
// silently and catastrophically:
//
//  1. The bundle must not contain the sequence `</script`. If it did, the
//     browser would end the inline script early and render the rest of the
//     runtime as text - a broken page with no error anywhere.
//  2. The two base64 slots must survive into the output, or `buildSealedHtml`
//     would have nowhere to put the payload.
import { readFileSync, writeFileSync } from 'node:fs';
import { createHash } from 'node:crypto';

const TEMPLATE = 'src/wrapper/page.template.html';
const BUNDLE = 'src/wrapper/generated/sealed-page.iife.js';
const OUT = 'src/wrapper/generated/page.html';
const MARKER = '<!--SEALED_RUNTIME-->';

const template = readFileSync(TEMPLATE, 'utf8');
const bundle = readFileSync(BUNDLE, 'utf8').trim();

if (/<\/script/i.test(bundle)) {
  throw new Error(
    'the bundled runtime contains "</script", which would terminate the inline script early',
  );
}
if (!template.includes(MARKER)) throw new Error(`${TEMPLATE} has lost its ${MARKER} marker`);

// A REPLACER FUNCTION, not a replacement string. `String.replace` interprets
// `$&`, `$'`, `` $` `` and `$1` inside a replacement STRING - and minified
// JavaScript contains `$'` all the time (a `$`-named identifier followed by a
// quote). With a plain string this spliced the tail of the template back into
// the middle of the runtime: a 445 KB page with TWO <script> openers, no error,
// and a bundle that no longer parsed. A function replacement disables that
// substitution entirely.
const page = template.replace(MARKER, () => bundle);
for (const slot of ['__TDF_B64__', '__META_B64__']) {
  if (!page.includes(slot)) throw new Error(`the generated page lost its ${slot} slot`);
}
// Count script TAGS in the markup, i.e. in the template - not in the composed
// page. The bundle legitimately contains the characters `<script` inside string
// literals (the SDK has a `createElement('script')` path it never takes here),
// and an opening tag inside script text is inert: an HTML parser only ends a
// script element at `</script`, which is invariant 1 above.
const tags = template.match(/<script[\s>]/g) ?? [];
if (tags.length !== 1) throw new Error(`expected exactly one <script> in the template, found ${tags.length}`);

writeFileSync(OUT, page, 'utf8');

const inline = /<script>([\s\S]*?)<\/script>/.exec(page)[1];
const sha = createHash('sha256').update(inline, 'utf8').digest('base64');
// The web image reads this file at build time and pins it into the /sealed/
// CSP (web/entrypoint.sh). The runtime carries no deployment hostname (they
// travel in each wrapper's metadata), so the hash is a property of the build
// alone and is the same for every deployment of that build.
writeFileSync('src/wrapper/generated/sealed-script.sha256', `sha256-${sha}\n`, 'utf8');
console.log(`wrapper template: ${OUT}  (${(page.length / 1024).toFixed(0)} KB)`);
console.log(`CSP hash for nginx location /sealed/:  'sha256-${sha}'`);
