/**
 * The complete runtime of a self-decrypting HTML-wrapped TDF.
 *
 * This file is bundled - with the real `@opentdf/sdk` inside it - into ONE
 * inline <script> in every wrapper page. There is no second request, no CDN and
 * no companion file: a wrapper works from a USB stick on a machine that has
 * never heard of this lab, and the only network traffic it makes is to the
 * realm and to the key server, after a person asks for it.
 *
 * ---------------------------------------------------------------------------
 * WHAT THIS DESIGN COSTS - written here because the page says it to the reader
 * ---------------------------------------------------------------------------
 *
 * 1. `Origin: null` had to be added to the platform's CORS allowlist. `null` is
 *    the origin of EVERY document loaded from a filesystem and of every
 *    sandboxed frame - it is not "this file", it is a whole class. So any such
 *    document may now reach this KAS. A valid bearer token is still required
 *    and every policy decision is unchanged, so this is not an authorization
 *    hole; it is a widening of who is allowed to knock.
 *
 * 2. The wrapper's own JavaScript now handles the access token and the
 *    plaintext. In the console that code is served by the lab; here it arrived
 *    in the same file as the ciphertext, from whoever sent it. Opening a
 *    wrapper is choosing to run their program. That is exactly why products
 *    doing this commercially hand you a link to a web application instead of a
 *    self-decrypting document - and saying so is the point of building it.
 *
 * Neither is hidden from the reader. Both are on the page, in a box.
 */

import { CONFIG_ERROR, OIDC_AUTHORITY, PLATFORM_URL } from '../config';
import { createClients, decryptTdf, type DecryptOutcome } from '../tdf';
import { fetchPolicy } from '../policy';
import { openTdfFile, policyAttributes, formatBytes, type TdfFile } from '../manifest';
import {
  DeviceAuthError,
  pollForTokens,
  startDeviceAuth,
  type DeviceStart,
  type DeviceTokens,
} from './device-auth';

// ------------------------------------------------------------------ tiny DOM
function el<K extends keyof HTMLElementTagNameMap>(
  tag: K,
  cls?: string | null,
  text?: string | null,
): HTMLElementTagNameMap[K] {
  const n = document.createElement(tag);
  if (cls) n.className = cls;
  // textContent, always. Every manifest-derived string on this page is
  // attacker-influenced and none of it is ever assigned as markup.
  if (text !== undefined && text !== null) n.textContent = String(text);
  return n;
}
function clear(n: Element): void {
  while (n.firstChild) n.removeChild(n.firstChild);
}
function prose(text: string): HTMLElement {
  return el('p', 'prose', text);
}
type Panel = { root: HTMLElement; body: HTMLElement };
function panel(title: string, aside?: string | null): Panel {
  const root = el('section', 'panel');
  const head = el('header', 'panel__head');
  head.appendChild(el('h2', null, title));
  if (aside) head.appendChild(el('span', 'panel__aside', aside));
  root.appendChild(head);
  const body = el('div', 'panel__body');
  root.appendChild(body);
  return { root, body };
}
function kv(rows: [string, string][]): HTMLElement {
  const g = el('div', 'kv');
  for (const [k, v] of rows) {
    g.appendChild(el('span', 'kv__k', k));
    g.appendChild(el('span', 'kv__v', v));
  }
  return g;
}
/** A bolded lead-in followed by body text, both as text nodes. */
function risk(lead: string, body: string): HTMLElement {
  const d = el('div', 'risk');
  d.appendChild(el('strong', null, lead));
  d.appendChild(document.createTextNode(' ' + body));
  return d;
}

function b64ToBytes(s: string): Uint8Array {
  const bin = atob(s);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

/**
 * Display-spoofing hygiene, repeated here on purpose: this page may have been
 * hand-built by whoever sent it, so nothing in its metadata is trusted just
 * because OUR generator would have cleaned it. U+202E alone turns a `.tdf.html`
 * into something that reads as `.pdf`.
 */
function cleanName(raw: unknown, fallback: string): string {
  if (typeof raw !== 'string' || !raw) return fallback;
  let out = raw
    .replace(/[\u0000-\u001f\u007f-\u009f]/g, '')
    .replace(/[\u061c\u200b-\u200f\u202a-\u202e\u2066-\u2069\ufeff]/g, '');
  out = out.normalize ? out.normalize('NFC') : out;
  out = out.split(/[\\/]/).pop() ?? '';
  return out.trim().slice(0, 180) || fallback;
}

function download(bytes: Uint8Array, name: string, type: string): void {
  const blob = new Blob([bytes as BlobPart], { type });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = name;
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 10_000);
}

// -------------------------------------------------------------------- steps
type StepStatus = 'pending' | 'active' | 'done' | 'failed' | 'skipped';
type Step = { label: string; obs: string; status: StepStatus; note?: string };

/**
 * The console's honesty vocabulary, kept verbatim. A step that never ran gets
 * NO badge - badging an unreached step "observed" is the exact dishonesty the
 * badges exist to prevent.
 */
function renderSteps(host: HTMLElement, steps: Step[]): void {
  const ul = el('ul', 'steps');
  steps.forEach((s, i) => {
    const li = el('li', `step step--${s.status}`);
    li.appendChild(el('span', 'step__n', String(i + 1)));
    li.appendChild(
      el('span', 'step__label', s.label + (s.status === 'skipped' ? ' — never reached' : '')),
    );
    if (s.status === 'skipped' || s.status === 'pending') {
      const none = el('span', 'step__obs step__obs--none', 'not observed');
      none.title = 'This step did not happen, so nothing observed it.';
      li.appendChild(none);
    } else {
      li.appendChild(
        el('span', `step__obs step__obs--${s.obs === 'observed' ? 'observed' : 'other'}`, s.obs),
      );
    }
    if (s.note) li.appendChild(el('p', 'step__note', s.note));
    ul.appendChild(li);
  });
  clear(host);
  host.appendChild(ul);
}

// ===========================================================================
//  boot
// ===========================================================================

/** Ceiling on what this page will decode at all. */
const MAX_PAYLOAD = 24 * 1024 * 1024;

type Meta = { filename?: unknown; origin?: unknown; createdAt?: unknown };

function boot(): void {
  const app = document.getElementById('app');
  if (!app) return;

  let meta: Meta = {};
  try {
    const raw = (document.getElementById('meta-input') as HTMLInputElement).value;
    meta = JSON.parse(new TextDecoder().decode(b64ToBytes(raw))) as Meta;
  } catch {
    meta = {};
  }
  const filename = cleanName(meta.filename, 'sealed.tdf');
  const labOrigin =
    typeof meta.origin === 'string' && /^https:\/\/[a-z0-9.-]+(:[0-9]+)?$/i.test(meta.origin)
      ? meta.origin
      : '';
  const createdAt =
    typeof meta.createdAt === 'string'
      ? `${meta.createdAt.slice(0, 19).replace('T', ' ')} UTC`
      : null;

  document.title = `${filename} — sealed`;
  const hd = document.getElementById('hd-title');
  if (hd) hd.textContent = filename;

  const localDoc = location.protocol === 'file:';
  const atLab = !!labOrigin && location.origin === labOrigin;

  const facts = panel('What this file declares', 'read locally, no network');
  app.appendChild(facts.root);

  void (async () => {
    let tdf: Uint8Array;
    let parsed: TdfFile;
    try {
      const raw = (document.getElementById('data-input') as HTMLInputElement).value || '';
      if ((raw.length * 3) / 4 > MAX_PAYLOAD) {
        throw new Error(
          `the embedded payload is larger than this page will decode (cap ${MAX_PAYLOAD} bytes)`,
        );
      }
      tdf = b64ToBytes(raw);
      parsed = await openTdfFile(tdf, filename);
    } catch (err) {
      facts.body.appendChild(
        el(
          'p',
          'notice notice--deny',
          `This page could not read its own payload: ${err instanceof Error ? err.message : String(err)}`,
        ),
      );
      return;
    }

    const attrs = policyAttributes(parsed.policy);
    const kao = parsed.manifest.encryptionInformation?.keyAccess?.[0];
    const payloadEntry = parsed.entries.find((e) => e.name.endsWith('payload'));
    const rows: [string, string][] = [
      ['file', filename],
      [
        'requires',
        attrs.length
          ? `${attrs.length} attribute value${attrs.length === 1 ? '' : 's'} — listed below`
          : 'no attributes — any authenticated account can open it',
      ],
      ['key server', kao?.url ?? '—'],
      ['key id', kao?.kid ?? '—'],
      [
        'policy uuid',
        parsed.policy?.uuid ?? (parsed.policyError ? `unreadable: ${parsed.policyError}` : '—'),
      ],
      ['schema', parsed.manifest.schemaVersion ?? '—'],
      ['algorithm', parsed.manifest.encryptionInformation?.method?.algorithm ?? '—'],
      [
        'payload',
        `${formatBytes(payloadEntry?.compressedSize ?? 0)}${
          parsed.manifest.payload?.isEncrypted
            ? ' of ciphertext'
            : ' (manifest does not claim it is encrypted)'
        }`,
      ],
      [
        'segments',
        String(parsed.manifest.encryptionInformation?.integrityInformation?.segments?.length ?? 0),
      ],
      ['wrapped key', kao?.wrappedKey ? `${kao.wrappedKey.slice(0, 44)}…` : '—'],
      [
        'policy binding',
        typeof kao?.policyBinding === 'object' ? (kao.policyBinding?.alg ?? 'present') : 'present',
      ],
    ];
    if (createdAt) rows.push(['wrapped at', createdAt]);
    facts.body.appendChild(kv(rows));

    if (attrs.length) {
      facts.body.appendChild(
        el('p', 'eyebrow eyebrow--sect', 'attribute values bound into the policy'),
      );
      const tags = el('div');
      for (const a of attrs) tags.appendChild(el('span', 'tag tag--material', a));
      facts.body.appendChild(tags);
    }
    facts.body.appendChild(
      prose(
        'All of that is plaintext inside this file and was read with no network call of any kind. ' +
          'None of it is the data. The payload above is ciphertext: holding this file gives you ' +
          'every word of the policy and not one word of the document.',
      ),
    );

    // The lab this wrapper belongs to travels in its metadata (config.ts).
    // Without a valid one there is nowhere to authenticate or rewrap, so say
    // so instead of offering a button that calls placeholder hosts.
    if (CONFIG_ERROR) {
      const p = panel('Open it here', null);
      app.appendChild(p.root);
      p.body.appendChild(
        el(
          'p',
          'notice notice--deny',
          `This wrapper does not say which lab it belongs to (${CONFIG_ERROR}), so it cannot sign you in or ask a key server for the key. Open the .tdf in the lab console instead.`,
        ),
      );
      return;
    }
    facts.body.appendChild(
      kv([
        ['platform', PLATFORM_URL],
        ['realm', OIDC_AUTHORITY],
      ]),
    );

    buildOpener(app, tdf, attrs, { filename, localDoc, atLab });
  })();
}

// --------------------------------------------------------------- the opener
function buildOpener(
  app: HTMLElement,
  tdf: Uint8Array,
  attrs: string[],
  ctx: { filename: string; localDoc: boolean; atLab: boolean },
): void {
  const p = panel('Open it here', ctx.localDoc ? 'file:// — no server involved' : location.origin);
  app.appendChild(p.root);

  p.body.appendChild(
    prose(
      'This page can do the whole thing where it sits. It signs you in against the realm using the ' +
        'device authorization grant — the one OAuth flow that needs no redirect back to this ' +
        'page, which is exactly what makes it work from a document with no origin — then asks ' +
        'the key server to rewrap the data key for you, and decrypts the payload here. Your ' +
        'password is typed into the identity provider, on its own site. This page never sees it.',
    ),
  );

  // The two costs, on the page rather than in a runbook.
  p.body.appendChild(
    risk(
      'What allowing this cost:',
      'for any of it to work, the key server had to be told to accept requests from the origin ' +
        'null. That is not "this file" — null is the origin of every document opened from a ' +
        'filesystem and of every sandboxed frame, so any of them may now knock. A valid token is ' +
        'still required and every policy decision is unchanged, so nothing became readable that ' +
        'was not readable before; the set of pages allowed to ask simply got much larger.',
    ),
  );
  p.body.appendChild(
    risk(
      'And the part worth stopping on:',
      'the code doing all this is in this file, and this file came from whoever sent it to you. It ' +
        'handles your access token and your plaintext. In the lab console that code is served by ' +
        'the lab; here you are choosing to run a stranger’s program. This is precisely why ' +
        'products that do this commercially hand you a link to a web application instead of a ' +
        'self-decrypting document — and why this wrapper says so rather than feeling seamless.',
    ),
  );

  if (!ctx.localDoc && !ctx.atLab) {
    p.body.appendChild(
      el(
        'p',
        'notice notice--deny',
        `This page is served from ${location.origin}. The key server's allowlist covers documents ` +
          'opened from a filesystem and the lab’s own origin, not arbitrary web origins, so ' +
          'the rewrap below will very likely be refused by your browser before it is even sent. ' +
          'Download the .tdf and open it in the console, or open this file from disk.',
      ),
    );
  }

  const status = el('p', 'notice');
  status.textContent = 'Nothing has left this page. No request of any kind has been made.';
  p.body.appendChild(status);

  const row = el('div', 'btn-row');
  const signBtn = el('button', 'btn btn--primary', 'Sign in and decrypt');
  signBtn.type = 'button';
  signBtn.id = 'sealed-open';
  row.appendChild(signBtn);
  const dl = el('button', 'btn', 'Download the .tdf');
  dl.type = 'button';
  dl.id = 'sealed-download';
  dl.onclick = () => download(tdf, ctx.filename, 'application/tdf');
  row.appendChild(dl);
  const cancel = el('button', 'btn btn--ghost hidden', 'Cancel');
  cancel.type = 'button';
  cancel.id = 'sealed-cancel';
  row.appendChild(cancel);
  p.body.appendChild(row);

  const codeHost = el('div');
  p.body.appendChild(codeHost);

  const stepsPanel = panel('What is happening', 'live');
  stepsPanel.root.className = 'panel hidden';
  const stepsHost = el('div');
  stepsPanel.body.appendChild(stepsHost);
  app.appendChild(stepsPanel.root);

  const out = el('div');
  app.appendChild(out);

  let cancelled = false;
  /** Kept so a denial can read the policy back with the same credential. */
  let tokens: DeviceTokens | null = null;

  cancel.onclick = () => {
    cancelled = true;
  };
  signBtn.onclick = () => void run();

  async function run(): Promise<void> {
    cancelled = false;
    signBtn.disabled = true;
    cancel.className = 'btn btn--ghost';
    clear(out);
    clear(codeHost);
    stepsPanel.root.className = 'panel';

    const steps: Step[] = [
      {
        label: 'Read the manifest',
        obs: 'observed',
        status: 'done',
        note: 'Plaintext. It names the key server and the policy and holds no key.',
      },
      {
        label: 'Ask the realm for a device code',
        obs: 'observed',
        status: 'active',
        note: 'No redirect URI is involved, which is the whole reason this works from a page with no origin.',
      },
      {
        label: 'You approve the code in the identity provider',
        obs: 'inside Keycloak',
        status: 'pending',
        note: 'Your password is typed there, on its own site. This page never sees it.',
      },
      { label: 'The realm issues an access token to this page', obs: 'observed', status: 'pending' },
      {
        label: 'Rewrap request: wrapped key + policy + your token',
        obs: 'observed',
        status: 'pending',
        note: 'Decryption starts as a request. Nothing is decrypted locally yet.',
      },
      {
        label: 'The key server checks the binding, then your entitlements',
        obs: 'inside Key server',
        status: 'pending',
        note: 'Resolved from your Keycloak account at decision time. This page is not a participant and never sees your side.',
      },
      { label: 'The key server’s answer', obs: 'observed', status: 'pending' },
      {
        label: 'Unwrap the key and decrypt the payload here',
        obs: 'inside the SDK',
        status: 'pending',
        note: 'AES-256-GCM, segment by segment, in this document.',
      },
    ];
    renderSteps(stepsHost, steps);

    let start: DeviceStart;
    try {
      status.className = 'notice';
      status.textContent = 'Asking the realm for a code…';
      start = await startDeviceAuth();
    } catch (err) {
      steps[1].status = 'failed';
      for (let i = 2; i < steps.length; i++) steps[i].status = 'skipped';
      renderSteps(stepsHost, steps);
      fail(err);
      return;
    }

    steps[1].status = 'done';
    steps[2].status = 'active';
    renderSteps(stepsHost, steps);

    clear(codeHost);
    codeHost.appendChild(
      el('p', 'eyebrow eyebrow--sect', 'enter this code in the identity provider'),
    );
    const codeEl = el('p', 'usercode', start.userCode);
    codeEl.id = 'sealed-usercode';
    codeHost.appendChild(codeEl);
    const v = el('p', 'verify');
    v.appendChild(document.createTextNode('at '));
    const link = el('a', null, start.verificationUri);
    link.href = start.verificationUriComplete ?? start.verificationUri;
    link.target = '_blank';
    link.rel = 'noreferrer noopener';
    link.id = 'sealed-verify-link';
    v.appendChild(link);
    if (start.verificationUriComplete) {
      v.appendChild(document.createTextNode(' — that link pre-fills the code.'));
    }
    codeHost.appendChild(v);
    const poll = el('p', 'poll', 'Waiting for approval…');
    codeHost.appendChild(poll);

    status.className = 'notice';
    status.textContent = 'Waiting for you to approve that code. Nothing has been decrypted.';

    try {
      tokens = await pollForTokens(
        start,
        (ev) => {
          poll.textContent =
            ev.kind === 'slow-down'
              ? `The realm asked us to slow down; polling every ${ev.interval}s.`
              : `Waiting for approval… ${ev.secondsLeft}s before this code expires.`;
        },
        () => cancelled,
      );
    } catch (err) {
      steps[2].status = 'failed';
      for (let i = 3; i < steps.length; i++) steps[i].status = 'skipped';
      renderSteps(stepsHost, steps);
      fail(err, true);
      return;
    }

    clear(codeHost);
    cancel.className = 'btn btn--ghost hidden';
    steps[2].status = 'done';
    steps[3].status = 'done';
    steps[4].status = 'active';
    renderSteps(stepsHost, steps);
    status.className = 'notice';
    status.textContent = 'Signed in. Asking the key server to rewrap…';

    const held = tokens;
    const clients = createClients(async () => {
      if (Date.now() > held.expiresAt) {
        throw new Error('That access token expired. Press Start again for a fresh code.');
      }
      return held.accessToken;
    });

    let res: DecryptOutcome;
    try {
      res = await decryptTdf(clients, tdf);
    } catch (err) {
      steps[4].status = 'failed';
      for (let i = 5; i < steps.length; i++) steps[i].status = 'skipped';
      renderSteps(stepsHost, steps);
      fail(err);
      return;
    }

    steps[4].status = 'done';
    if (res.outcome === 'granted') {
      steps[5].status = 'done';
      steps[6].status = 'done';
      steps[7].status = 'done';
    } else if (res.kind === 'denied' || res.kind === 'policy-binding') {
      // The key server genuinely answered - that step is done, not unreached.
      steps[5].status = 'failed';
      steps[6].status = 'done';
      steps[7].status = 'skipped';
    } else if (res.kind === 'integrity') {
      steps[5].status = 'done';
      steps[6].status = 'done';
      steps[7].status = 'failed';
    } else {
      steps[4].status = 'failed';
      for (let i = 5; i < steps.length; i++) steps[i].status = 'skipped';
    }
    renderSteps(stepsHost, steps);
    renderOutcome(res);
    signBtn.disabled = false;
    signBtn.textContent = 'Try again';
  }

  function fail(err: unknown, expired = false): void {
    const msg = err instanceof Error ? err.message : String(err);
    const code = err instanceof DeviceAuthError ? err.code : undefined;
    status.className = 'notice notice--deny';
    status.textContent =
      code === 'cancelled' ? 'Cancelled. Nothing was sent after that point.' : msg;
    cancel.className = 'btn btn--ghost hidden';
    signBtn.disabled = false;
    signBtn.textContent = expired || code === 'expired_token' ? 'Start again' : 'Sign in and decrypt';
  }

  function renderOutcome(res: DecryptOutcome): void {
    if (res.outcome === 'granted') {
      status.className = 'notice notice--grant';
      status.textContent = 'Decrypted in this page.';
      const g = panel('Access granted', formatBytes(res.plaintext.byteLength));
      g.body.appendChild(
        el(
          'p',
          'notice notice--grant',
          'The key server unwrapped the data key for you and the payload decrypted here, inside ' +
            'this document. The same file refuses everyone the policy does not name.',
        ),
      );
      if (res.text !== null) {
        g.body.appendChild(el('pre', 'code', res.text));
      } else {
        g.body.appendChild(prose('The payload is not UTF-8 text, so there is nothing to show inline.'));
      }
      const r = el('div', 'btn-row');
      const b = el('button', 'btn', 'Download the plaintext');
      b.type = 'button';
      b.onclick = () =>
        download(res.plaintext, ctx.filename.replace(/\.tdf$/i, '') || 'payload', res.mimeType);
      r.appendChild(b);
      g.body.appendChild(r);
      out.appendChild(g.root);
      return;
    }

    status.className = 'notice notice--deny';
    status.textContent = res.headline;

    if (res.kind === 'denied') {
      const d = panel('Access denied', res.serviceCode ?? 'permission_denied');
      d.body.appendChild(
        el(
          'p',
          'notice notice--deny',
          'You hold a valid token and this file is intact. The key server still refused to unwrap ' +
            'the key, because policy says this account is not entitled to this data. That is the ' +
            'system working — and it is the same answer the console gives, from the same request.',
        ),
      );
      d.body.appendChild(
        kv([
          ['result', res.serviceCode ?? 'permission_denied'],
          ['message', res.serviceMessage ?? res.sdkMessage],
        ]),
      );
      d.body.appendChild(
        prose(
          'The rewrap call itself returned HTTP 200. This platform carries the refusal inside the ' +
            'response, as a per-key result whose status is permission_denied: a decision was made ' +
            'and answered, not an error.',
        ),
      );
      if (attrs.length) {
        d.body.appendChild(el('p', 'eyebrow eyebrow--sect', 'what you would have needed'));
        const tr = el('div');
        for (const a of attrs) tr.appendChild(el('span', 'tag tag--deny', a));
        d.body.appendChild(tr);
      }
      const guide = el('div');
      d.body.appendChild(guide);
      guide.appendChild(
        prose(
          'That reads a Keycloak USER ATTRIBUTE, not a claim in your token — your access token ' +
            'carries no classification of any kind. Set the attribute on this account in the realm ' +
            'admin console and press Try again: the entitlement is resolved server-side on every ' +
            'request, so the very next attempt uses the new value. No new token, no sign-out.',
        ),
      );
      out.appendChild(d.root);
      void showMappings(guide);
      return;
    }

    if (res.kind === 'policy-binding') {
      const t = panel('Policy binding mismatch', res.serviceCode ?? 'invalid_argument');
      t.body.appendChild(
        el(
          'p',
          'notice notice--deny',
          'The policy in this file was altered after it was sealed. The key server recomputed the ' +
            'HMAC over the policy it was handed, compared it with the binding in the manifest, and ' +
            'they do not match — so it refused before deciding anything about entitlement.',
        ),
      );
      t.body.appendChild(kv([['message', res.serviceMessage ?? res.sdkMessage]]));
      out.appendChild(t.root);
      return;
    }

    const f = panel(res.headline, res.kind);
    f.body.appendChild(el('p', 'notice notice--deny', res.serviceMessage ?? res.sdkMessage));
    if (res.kind === 'network') {
      f.body.appendChild(
        prose(
          'The request never reached the platform. From a page like this one that usually means the ' +
            'key server did not allow this origin — which is the control doing its job, not a bug.',
        ),
      );
    }
    out.appendChild(f.root);
  }

  /**
   * Best effort: the subject mapping that would have satisfied the policy,
   * from the same read-only policy call the console makes. A failure here is
   * swallowed - the guidance above stands on its own.
   */
  async function showMappings(host: HTMLElement): Promise<void> {
    const held = tokens;
    if (!attrs.length || !held) return;
    try {
      const snap = await fetchPolicy(createClients(async () => held.accessToken));
      const ms = snap.subjectMappings.filter((m) => attrs.includes(m.valueFqn));
      if (!ms.length) {
        host.insertBefore(
          el(
            'p',
            'notice notice--deny',
            'No subject mapping grants these values, so no account in this realm can currently open ' +
              'this file — not even whoever sealed it. An attribute value with no subject ' +
              'mapping is a lock with no key cut for it.',
          ),
          host.firstChild,
        );
        return;
      }
      const head = el('p', 'eyebrow eyebrow--sect', 'what would have satisfied it');
      host.insertBefore(head, host.firstChild);
      const anchor: Node | null = head.nextSibling;
      for (const m of ms) {
        const line = el('p', 'notice');
        line.style.whiteSpace = 'pre-wrap';
        line.textContent =
          `${m.valueFqn}\nrequires ` +
          m.conditions
            .map((c) => `${c.selector} ${c.operator} [${c.values.join(', ')}]`)
            .join(` ${m.booleanOperator} `) +
          `\nfor actions: ${m.actions.join(', ') || '—'}`;
        host.insertBefore(line, anchor);
      }
    } catch {
      /* a policy read is a nicety here */
    }
  }
}

boot();
