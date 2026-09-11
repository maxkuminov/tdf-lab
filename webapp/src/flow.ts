/**
 * The protocol flow model: what actually happens, who does it, and — the part
 * that matters most here — whether this browser genuinely saw it.
 *
 * Three honesty levels, and they are not decoration. A teaching tool that
 * quietly implies it watched a server-side decision is lying, so every step
 * carries one:
 *
 *   observed  this app did it, or its RPC interceptor saw the request. The
 *             artifacts under these steps are real captured values.
 *   sdk       the OpenTDF SDK performs it inside its own client. We know it
 *             happens and roughly when; we do NOT see the request. (Verified:
 *             `fetchKasPubKey` builds its own transport, so our interceptor
 *             never fires for it.)
 *   server    happens inside the platform, after our request arrives. The
 *             browser is not a participant and never sees the intermediate
 *             values — only the final answer.
 */

import type { DecryptOutcome } from './tdf';
import type { PolicySubjectMapping } from './policy';
import type { RpcCall } from './rpc';
import type { TdfManifest } from './manifest';

export type Lane = 'browser' | 'keycloak' | 'platform' | 'kas' | 'library';

export const LANE_LABEL: Record<Lane, string> = {
  browser: 'This browser',
  keycloak: 'Keycloak',
  platform: 'Platform',
  kas: 'Key server',
  library: 'Library server',
};

export const LANE_SUB: Record<Lane, string> = {
  browser: 'your tab',
  keycloak: 'identity',
  platform: 'policy · authz · ERS',
  kas: 'KAS',
  library: 'ciphertext store',
};

export type Observability = 'observed' | 'sdk' | 'server';

export const OBS_LABEL: Record<Observability, string> = {
  observed: 'observed',
  sdk: 'inside the SDK',
  server: 'inside the platform',
};

export const OBS_TITLE: Record<Observability, string> = {
  observed: 'This app performed it, or its RPC interceptor captured the request. The values below are real.',
  sdk: 'The OpenTDF SDK does this through its own transport, so this app cannot observe the request. Shown because it happens, not because we watched it.',
  server: 'This happens server-side after our request arrives. The browser is not a participant and never sees the intermediate values — only the answer that comes back.',
};

export type StepStatus = 'pending' | 'active' | 'done' | 'failed' | 'skipped';

export type Artifact =
  | { kind: 'json'; label: string; value: unknown }
  | { kind: 'text'; label: string; value: string }
  | { kind: 'kv'; label: string; rows: [string, string][] }
  | {
      kind: 'compare';
      label: string;
      required: string[];
      /** What the browser knows about the caller's side — usually nothing. */
      yoursNote: string;
      satisfiedBy: string[];
      failed: boolean;
    };

export type FlowStep = {
  id: string;
  from: Lane;
  to: Lane;
  label: string;
  detail?: string;
  obs: Observability;
  artifacts?: Artifact[];
  /** Filled by the builders; the component only renders it. */
  status: StepStatus;
};

export type FlowVerdict = 'sealed' | 'published' | 'granted' | 'denied' | 'tamper' | 'fault' | null;

export type FlowRun = {
  title: string;
  lanes: Lane[];
  steps: FlowStep[];
  verdict: FlowVerdict;
  /** Index of the step that stopped the run, if any. */
  failedAt: number | null;
};

/** Order lanes left-to-right the way the traffic actually moves. */
const LANE_ORDER: Lane[] = ['browser', 'keycloak', 'library', 'platform', 'kas'];

function lanesFor(steps: FlowStep[]): Lane[] {
  const used = new Set<Lane>();
  for (const s of steps) {
    used.add(s.from);
    used.add(s.to);
  }
  return LANE_ORDER.filter((l) => used.has(l));
}

/**
 * Mark what the run never got to.
 *
 * Only steps still PENDING after the failure become "never reached" — a step
 * the builder explicitly marked done really did happen. This matters on a
 * denial: the key server genuinely answers (with the refusal, inside an HTTP
 * 200), so that step is not skipped; only the local decrypt below it is.
 */
function finalize(title: string, steps: FlowStep[], verdict: FlowVerdict): FlowRun {
  const failedAt = steps.findIndex((s) => s.status === 'failed');
  if (failedAt >= 0) {
    steps.forEach((s, i) => {
      if (i > failedAt && s.status === 'pending') s.status = 'skipped';
    });
  }
  return { title, lanes: lanesFor(steps), steps, verdict, failedAt: failedAt >= 0 ? failedAt : null };
}

function claimRows(claims: Record<string, unknown> | null): [string, string][] {
  if (!claims) return [['(no token decoded)', '']];
  const aud = Array.isArray(claims.aud) ? claims.aud.join(', ') : String(claims.aud ?? '—');
  const roles = (claims.realm_access as { roles?: string[] } | undefined)?.roles ?? [];
  const exp = typeof claims.exp === 'number' ? new Date(claims.exp * 1000).toLocaleTimeString() : '—';
  return [
    ['preferred_username', String(claims.preferred_username ?? '—')],
    ['sub', String(claims.sub ?? '—')],
    ['iss', String(claims.iss ?? '—')],
    ['aud', aud],
    ['azp', String(claims.azp ?? '—')],
    ['realm_access.roles', roles.join(', ') || '—'],
    ['exp', exp],
    ['classification', 'absent — entitlements are NOT carried in the token'],
  ];
}

// ---------------------------------------------------------------------------
// login (retrospective: how the token in your hand was obtained)
// ---------------------------------------------------------------------------

export function buildLoginFlow(claims: Record<string, unknown> | null): FlowRun {
  const steps: FlowStep[] = [
    {
      id: 'redirect',
      from: 'browser',
      to: 'keycloak',
      label: 'Authorization request + PKCE challenge',
      detail: 'A random verifier is generated here and only its SHA-256 hash is sent.',
      obs: 'observed',
      status: 'done',
      artifacts: [
        {
          kind: 'kv',
          label: 'what left this tab',
          rows: [
            ['response_type', 'code'],
            ['client_id', 'web-console'],
            ['code_challenge_method', 'S256'],
            ['redirect_uri', `${location.origin}/`],
            ['client secret', 'none — this is a public client'],
          ],
        },
      ],
    },
    {
      id: 'authenticate',
      from: 'keycloak',
      to: 'keycloak',
      label: 'Keycloak authenticates the person',
      detail: 'Your password is typed into Keycloak, never into this app.',
      obs: 'server',
      status: 'done',
    },
    {
      id: 'code',
      from: 'keycloak',
      to: 'browser',
      label: 'Authorization code returned to the exact redirect URI',
      obs: 'observed',
      status: 'done',
    },
    {
      id: 'exchange',
      from: 'browser',
      to: 'keycloak',
      label: 'Exchange code + verifier for tokens',
      detail: 'The verifier proves this is the same tab that started the flow.',
      obs: 'observed',
      status: 'done',
    },
    {
      id: 'token',
      from: 'keycloak',
      to: 'browser',
      label: 'Signed access token (RS256)',
      detail: 'The audience mapper puts the platform in aud, which is what the platform checks first.',
      obs: 'observed',
      status: 'done',
      artifacts: [{ kind: 'kv', label: 'decoded claims (real, from your session)', rows: claimRows(claims) }],
    },
  ];
  return finalize('How you got this token', steps, null);
}

// ---------------------------------------------------------------------------
// encrypt / publish
// ---------------------------------------------------------------------------

export function buildEncryptFlow(opts: {
  attributes: string[];
  toLibrary: boolean;
  claims: Record<string, unknown> | null;
  manifest?: TdfManifest | null;
  sizeBytes?: number;
  error?: string | null;
  /** How far the operation actually got. */
  reached: 'start' | 'sealed' | 'uploaded';
}): FlowRun {
  const { attributes, toLibrary, claims, manifest, error, reached } = opts;
  const kao = manifest?.encryptionInformation?.keyAccess?.[0];
  const done = (ok: boolean): StepStatus => (ok ? 'done' : 'pending');
  const sealed = reached === 'sealed' || reached === 'uploaded';

  const steps: FlowStep[] = [];

  if (attributes.length) {
    steps.push({
      id: 'resolve',
      from: 'browser',
      to: 'platform',
      label: 'Look up the attribute values you picked',
      detail: 'GetAttributeValuesByFqns — confirms they exist and returns any key grants.',
      obs: 'observed',
      status: done(sealed),
      artifacts: [{ kind: 'json', label: 'attribute FQNs sent', value: attributes }],
    });
  }

  steps.push({
    id: 'dek',
    from: 'browser',
    to: 'browser',
    label: 'Generate a 256-bit data encryption key',
    detail: 'Made here, in this tab. It is never sent anywhere in the clear.',
    obs: 'sdk',
    status: done(sealed),
  });

  steps.push({
    id: 'kaspub',
    from: 'browser',
    to: 'kas',
    label: "Fetch the key server's public key",
    detail: 'The SDK uses its own transport for this, so this app never sees the request.',
    obs: 'sdk',
    status: done(sealed),
    artifacts: kao
      ? [{ kind: 'kv', label: 'the key it came back with', rows: [['kas', kao.url ?? '—'], ['kid', kao.kid ?? '—']] }]
      : undefined,
  });

  steps.push({
    id: 'wrap',
    from: 'browser',
    to: 'browser',
    label: 'Wrap the DEK to that key, and HMAC the policy with the DEK',
    detail: 'The binding is what makes the policy un-editable by whoever holds the file.',
    obs: 'sdk',
    status: done(sealed),
    artifacts:
      kao && typeof kao.policyBinding === 'object'
        ? [
            {
              kind: 'kv',
              label: 'key access object produced',
              rows: [
                ['wrappedKey', `${(kao.wrappedKey ?? '').slice(0, 44)}…`],
                ['policyBinding.alg', kao.policyBinding?.alg ?? 'HS256'],
                ['policyBinding.hash', `${(kao.policyBinding?.hash ?? '').slice(0, 44)}…`],
              ],
            },
          ]
        : undefined,
  });

  steps.push({
    id: 'write',
    from: 'browser',
    to: 'browser',
    label: 'Write 0.manifest.json + 0.payload (AES-256-GCM)',
    detail: 'A .tdf is a zip. The manifest is plaintext; the payload is not.',
    obs: 'sdk',
    status: done(sealed),
    artifacts: manifest
      ? [
          {
            kind: 'json',
            label: 'policy embedded in the manifest (decoded)',
            value: { dataAttributes: attributes, dissem: [] },
          },
        ]
      : undefined,
  });

  if (toLibrary) {
    const uploaded = reached === 'uploaded';
    steps.push({
      id: 'upload',
      from: 'browser',
      to: 'library',
      label: 'POST the ciphertext with your bearer token',
      detail: 'The server stores bytes it cannot open, and reads the attributes out of the manifest.',
      obs: 'observed',
      status: error && !uploaded ? 'failed' : done(uploaded),
      artifacts: [
        {
          kind: 'kv',
          label: 'request',
          rows: [
            ['Authorization', `Bearer <${String(claims?.preferred_username ?? 'you')}'s access token>`],
            ['Content-Type', 'application/octet-stream'],
            ['bytes', opts.sizeBytes ? `${opts.sizeBytes}` : '—'],
          ],
        },
        ...(error ? [{ kind: 'text' as const, label: 'server said', value: error }] : []),
      ],
    });
  }

  if (error && !toLibrary) {
    const last = steps[steps.length - 1];
    if (last) last.status = 'failed';
    last.artifacts = [...(last.artifacts ?? []), { kind: 'text', label: 'failed with', value: error }];
  }

  const verdict: FlowVerdict = error ? 'fault' : reached === 'uploaded' ? 'published' : sealed ? 'sealed' : null;
  return finalize(toLibrary ? 'Sealing and publishing' : 'Sealing a file', steps, verdict);
}

// ---------------------------------------------------------------------------
// decrypt / open — the interesting one
// ---------------------------------------------------------------------------

export function buildDecryptFlow(opts: {
  outcome: DecryptOutcome | null;
  running: boolean;
  fromLibrary: boolean;
  attributes: string[];
  manifest: TdfManifest | null;
  claims: Record<string, unknown> | null;
  mappings: PolicySubjectMapping[];
  rewrapCall?: RpcCall;
  filename?: string;
}): FlowRun {
  const { outcome, fromLibrary, attributes, manifest, claims, mappings, rewrapCall } = opts;
  const kao = manifest?.encryptionInformation?.keyAccess?.[0];

  const granted = outcome?.outcome === 'granted';
  const denied = outcome?.outcome === 'refused' && outcome.kind === 'denied';
  const tamper = outcome?.outcome === 'refused' && outcome.kind === 'policy-binding';
  const integrity = outcome?.outcome === 'refused' && outcome.kind === 'integrity';
  const otherFault = outcome?.outcome === 'refused' && !denied && !tamper && !integrity;
  const resolved = !!outcome;

  // Everything up to the rewrap answer happened for every outcome except an
  // early transport fault.
  const reachedKas = granted || denied || tamper || integrity;
  const ok = (cond: boolean): StepStatus => (cond ? 'done' : resolved ? 'skipped' : 'pending');

  const steps: FlowStep[] = [];

  if (fromLibrary) {
    steps.push({
      id: 'fetch',
      from: 'browser',
      to: 'library',
      label: 'Download the sealed bytes',
      detail: 'Anyone signed in can do this, for any file. Possession is not access.',
      obs: 'observed',
      status: ok(true),
      artifacts: [
        { kind: 'kv', label: 'request', rows: [['GET', `/api/files/…`], ['Authorization', 'Bearer <your access token>']] },
      ],
    });
  }

  steps.push({
    id: 'parse',
    from: 'browser',
    to: 'browser',
    label: 'Read the manifest',
    detail: 'Plaintext. It names the key server and the policy, but holds no key.',
    obs: 'observed',
    status: ok(true),
    artifacts: [
      {
        kind: 'kv',
        label: 'what the manifest says',
        rows: [
          ['kas', kao?.url ?? '—'],
          ['kid', kao?.kid ?? '—'],
          ['algorithm', manifest?.encryptionInformation?.method?.algorithm ?? '—'],
          ['dataAttributes', attributes.length ? attributes.join(', ') : 'none'],
        ],
      },
    ],
  });

  steps.push({
    id: 'allowlist',
    from: 'browser',
    to: 'platform',
    label: 'Check that key server is registered',
    detail: 'ListKeyAccessServers — a file naming an unknown KAS is refused before any request goes out.',
    obs: 'observed',
    status: ok(reachedKas),
  });

  steps.push({
    id: 'rewrap',
    from: 'browser',
    to: 'kas',
    label: 'Rewrap request: wrapped key + policy + your bearer token',
    detail: 'Decryption starts as a request. Nothing is decrypted locally yet.',
    obs: 'observed',
    status: ok(reachedKas),
    artifacts: [
      {
        kind: 'kv',
        label: 'what was sent',
        rows: [
          ['endpoint', '/kas.AccessService/Rewrap'],
          ['signedRequestToken', 'a JWT signed with this tab’s ephemeral key'],
          ['policy', 'the base64 policy copied from the manifest'],
          ['Authorization', `Bearer <${String(claims?.preferred_username ?? 'you')}'s access token>`],
        ],
      },
      { kind: 'kv', label: 'your token, decoded', rows: claimRows(claims) },
    ],
  });

  steps.push({
    id: 'tokencheck',
    from: 'kas',
    to: 'kas',
    label: 'Validate the token signature and audience',
    detail: 'Fails here would be 401 — an authentication problem, not a policy decision.',
    obs: 'server',
    status: ok(reachedKas),
  });

  steps.push({
    id: 'binding',
    from: 'kas',
    to: 'kas',
    label: 'Recompute the policy binding and compare',
    detail: 'The HMAC is keyed with the DEK the server is about to unwrap, so an edited policy cannot match.',
    obs: 'server',
    status: tamper ? 'failed' : ok(granted || denied || integrity),
    artifacts: tamper
      ? [
          {
            kind: 'text',
            label: 'the key server said',
            value: rewrapCall?.rawMessage ?? (outcome?.outcome === 'refused' ? outcome.sdkMessage : ''),
          },
          {
            kind: 'text',
            label: 'what this means',
            value:
              'The policy in this file was changed after it was sealed. The comparison below never ran — the request was rejected before any entitlement was considered.',
          },
        ]
      : undefined,
  });

  steps.push({
    id: 'ers',
    from: 'platform',
    to: 'keycloak',
    label: 'Resolve your entitlements from your Keycloak account',
    detail:
      'The entity resolution service reads your user attributes live. This is why entitlements are not in your token, and why changing one takes effect on the very next request.',
    obs: 'server',
    status: tamper ? 'skipped' : ok(granted || denied),
  });

  const satisfiedBy = mappings.flatMap((m) =>
    m.conditions.map((c) => `${c.selector} ${c.operator} [${c.values.join(', ')}]`),
  );

  steps.push({
    id: 'decide',
    from: 'platform',
    to: 'platform',
    label: "Compare your entitlements against the file's attributes",
    detail: 'The whole question, decided fresh, here, every time.',
    obs: 'server',
    status: denied ? 'failed' : tamper ? 'skipped' : ok(granted),
    artifacts: [
      {
        kind: 'compare',
        label: 'the comparison',
        required: attributes,
        yoursNote:
          'Resolved inside the platform from your Keycloak account. It is never sent to this browser, so the console cannot show your side — only what the answer was.',
        satisfiedBy,
        failed: !!denied,
      },
    ],
  });

  steps.push({
    id: 'answer',
    from: 'kas',
    to: 'browser',
    label: granted
      ? 'Rewrapped key, encrypted to this tab’s ephemeral key'
      : denied
        ? 'Refusal — carried inside an HTTP 200'
        : 'The key server’s answer',
    detail: denied
      ? 'Not a 4xx. The rewrap responds 200 with a per-key result whose status is permission_denied: a decision was made and answered.'
      : granted
        ? 'Only this tab can unwrap it — the key never travels in a form anyone else could use.'
        : undefined,
    obs: 'observed',
    // The key server genuinely answers whenever the request reached it — a deny,
    // a tamper rejection and an integrity release are all real HTTP responses
    // our interceptor observed. Only a request that never got to the KAS (an
    // early transport fault) leaves this step unreached. On tamper this step
    // used to render "never reached" while still carrying an OBSERVED badge and
    // the real wire data — a dishonesty the deny path already avoided.
    status: ok(reachedKas),
    artifacts: rewrapCall
      ? [
          {
            kind: 'kv',
            label: 'observed on the wire',
            rows: [
              ['path', rewrapCall.path],
              ['took', `${rewrapCall.durationMs.toFixed(0)}ms`],
              ['transport', rewrapCall.ok ? 'HTTP 200' : 'HTTP 200 (refusal carried in the body)'],
              ['status', rewrapCall.code ?? 'ok'],
            ],
          },
          ...(rewrapCall.rawMessage
            ? [{ kind: 'text' as const, label: 'verbatim, before the SDK rewrites it', value: rewrapCall.rawMessage }]
            : []),
        ]
      : undefined,
  });

  steps.push({
    id: 'decrypt',
    from: 'browser',
    to: 'browser',
    label: 'Unwrap the key and decrypt the payload locally',
    detail: 'AES-256-GCM, segment by segment, in this tab.',
    obs: 'sdk',
    status: integrity ? 'failed' : granted ? 'done' : resolved ? 'skipped' : 'pending',
    artifacts: integrity
      ? [
          {
            kind: 'text',
            label: 'what happened',
            value:
              'The key server released the key, but the ciphertext would not authenticate with it. The DATA was altered after sealing — a different failure from an edited policy.',
          },
        ]
      : undefined,
  });

  if (otherFault && outcome?.outcome === 'refused') {
    const target = steps.find((s) => s.id === 'rewrap');
    if (target) {
      target.status = 'failed';
      target.artifacts = [
        ...(target.artifacts ?? []),
        { kind: 'text', label: outcome.headline, value: outcome.serviceMessage ?? outcome.sdkMessage },
      ];
    }
  }

  const verdict: FlowVerdict = granted
    ? 'granted'
    : denied
      ? 'denied'
      : tamper
        ? 'tamper'
        : outcome
          ? 'fault'
          : null;

  return finalize(fromLibrary ? 'Opening a shared file' : 'Opening a sealed file', steps, verdict);
}
