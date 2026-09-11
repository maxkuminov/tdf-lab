import { useEffect, useRef, useState } from 'react';
import { FileDrop, Panel } from './bits';
import { Flow } from './Flow';
import { buildDecryptFlow } from '../flow';
import { useRpcCalls } from './useRpc';
import { decryptTdf, download, type DecryptOutcome, type LabClients } from '../tdf';
import { formatBytes, openTdfFile, policyAttributes, type TdfFile } from '../manifest';
import { unwrapIfHtml } from '../wrapper/html';
import { KEYCLOAK_ADMIN_URL, MAX_UPLOAD_BYTES } from '../config';
import type { PolicySnapshot } from '../policy';

export function Decrypt({
  clients,
  loaded,
  policy,
  username,
  claims,
  onLoaded,
}: {
  clients: LabClients;
  loaded: TdfFile | null;
  policy: PolicySnapshot | null;
  username: string;
  claims: Record<string, unknown> | null;
  onLoaded: (file: TdfFile) => void;
}) {
  const [busy, setBusy] = useState(false);
  const [outcome, setOutcome] = useState<DecryptOutcome | null>(null);
  const [openError, setOpenError] = useState<string | null>(null);
  const calls = useRpcCalls();
  // Bring the diagram into view when a request starts, so the feedback is not
  // stranded below the fold on a short viewport.
  const flowRef = useRef<HTMLDivElement>(null);
  useEffect(() => {
    if (busy && flowRef.current) {
      flowRef.current.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
    }
  }, [busy]);

  const required = policyAttributes(loaded?.policy ?? null);
  const mappings = (policy?.subjectMappings ?? []).filter((m) => required.includes(m.valueFqn));
  // The real rewrap call this operation produced, for the flow's artifacts.
  const rewrap = calls.filter((c) => c.path.includes('/kas.AccessService/Rewrap')).slice(-1)[0];

  async function take(f: File) {
    setOutcome(null);
    setOpenError(null);
    // Size FIRST, before a byte is read. `File.size` is free; `arrayBuffer()`
    // on a multi-gigabyte file is not, and checking afterwards means the
    // allocation that was supposed to be prevented has already happened.
    if (f.size > MAX_UPLOAD_BYTES) {
      setOpenError(
        `That file is ${formatBytes(f.size)}. This console reads at most ${formatBytes(MAX_UPLOAD_BYTES)} into browser memory, so it will not open it.`,
      );
      return;
    }
    try {
      // An HTML wrapper is accepted here too: it is a .tdf in a costume, and
      // making the user unwrap it by hand would teach nothing.
      const raw = new Uint8Array(await f.arrayBuffer());
      const { bytes, filename } = unwrapIfHtml(raw, f.name);
      onLoaded(await openTdfFile(bytes, filename));
    } catch (err) {
      setOpenError(err instanceof Error ? err.message : String(err));
    }
  }

  async function run() {
    if (!loaded) return;
    setBusy(true);
    setOutcome(null);
    try {
      setOutcome(await decryptTdf(clients, loaded.bytes));
    } finally {
      setBusy(false);
    }
  }

  const unmapped = required.filter(
    (fqn) => !(policy?.subjectMappings ?? []).some((m) => m.valueFqn === fqn),
  );

  return (
    <div className="stage__inner">
      <header className="stage__head">
        <p className="eyebrow">Step 02 — decrypt</p>
        <h1 className="stage__title">Ask the key server to unwrap</h1>
        <p className="prose">
          Decryption is a request, not a computation. The browser sends the wrapped key and the
          policy to the key server, which asks the platform whether <strong>{username}</strong>'s
          entitlements satisfy that policy. A refusal here is the system working.
        </p>
      </header>

      <Panel title="Sealed file" aside={loaded ? formatBytes(loaded.bytes.byteLength) : '.tdf'}>
        <FileDrop
          lead={loaded ? 'Load a different .tdf' : 'Drop a .tdf, or click to pick one'}
          hint="Parsed in the browser — the manifest opens without any key. An HTML-wrapped .tdf is unwrapped automatically."
          accept=".tdf,.html,application/tdf,application/zip,text/html"
          file={null}
          onFile={take}
        />
        {loaded ? (
          <div className="kv" style={{ marginTop: 14 }}>
            <span className="kv__k">loaded</span>
            <span className="kv__v material">{loaded.name}</span>
            <span className="kv__k">requires</span>
            <span className="kv__v">
              {required.length ? (
                required.map((a) => (
                  <span className="tag tag--material" key={a}>
                    {a}
                  </span>
                ))
              ) : (
                <span className="muted">no attributes — any authenticated user can open this</span>
              )}
            </span>
          </div>
        ) : null}
        {openError ? (
          <p className="notice notice--deny" style={{ marginTop: 12 }}>
            {openError}
          </p>
        ) : null}
      </Panel>

      <div className="btn-row">
        <button className="btn btn--primary" disabled={!loaded || busy} onClick={run}>
          {busy ? 'Requesting rewrap…' : 'Decrypt'}
        </button>
      </div>

      {busy || outcome ? (
        <div ref={flowRef}>
        <Flow
          run={buildDecryptFlow({
            outcome,
            running: busy,
            fromLibrary: false,
            attributes: required,
            manifest: loaded?.manifest ?? null,
            claims,
            mappings,
            rewrapCall: rewrap,
            filename: loaded?.name,
                    })}
          running={busy}
        />
        </div>
      ) : null}

      {outcome?.outcome === 'granted' ? (
        <div className="outcome outcome--granted" style={{ marginTop: 18 }}>
          <p className="outcome__flag">Access granted</p>
          <p className="outcome__lede">
            The key server unwrapped the key for {username} and the payload decrypted —{' '}
            {formatBytes(outcome.plaintext.byteLength)}.
          </p>
          {outcome.text !== null ? (
            <pre className="code">{outcome.text}</pre>
          ) : (
            <p className="notice">
              The payload is not UTF-8 text, so there is nothing to show inline.
            </p>
          )}
          <div className="btn-row" style={{ marginTop: 14 }}>
            <button
              className="btn"
              onClick={() =>
                download(
                  outcome.plaintext,
                  (loaded?.name ?? 'payload').replace(/\.tdf$/i, '') || 'payload',
                  outcome.mimeType,
                )
              }
            >
              <span>Download</span>{' '}
              <span className="btn__filename">
                {(loaded?.name ?? 'payload').replace(/\.tdf$/i, '') || 'payload'}
              </span>
            </button>
          </div>
        </div>
      ) : null}

      {outcome?.outcome === 'refused' && outcome.kind === 'denied' ? (
        <div className="outcome outcome--denied" style={{ marginTop: 18 }}>
          <p className="outcome__flag">Access denied</p>
          <p className="outcome__lede">
            {username} holds a valid token and the file is intact. The key server still refused to
            unwrap the key, because policy says {username} is not entitled to this data.
          </p>

          <div className="verdict">
            <div className="kv">
              <span className="kv__k">from</span>
              <span className="kv__v">{loaded?.manifest.encryptionInformation?.keyAccess?.[0]?.url ?? '—'}</span>
              <span className="kv__k">result</span>
              <span className="kv__v">
                <span className="tag tag--deny">{outcome.serviceCode ?? 'permission_denied'}</span>
              </span>
              <span className="kv__k">message</span>
              <span className="kv__v">{outcome.serviceMessage ?? outcome.sdkMessage}</span>
              <span className="kv__k">sdk</span>
              <span className="kv__v muted">{outcome.sdkMessage}</span>
            </div>
            <p className="prose">
              The rewrap call itself returned <em>HTTP 200</em>. This platform carries the refusal{' '}
              <em>inside</em> the response, as a per-key-access-object result whose status is{' '}
              <span className="material">permission_denied</span> — so a decision was made and
              answered, not an error. (The SDK's own message flattens that to "403"; the text above
              is what the key server actually said.)
            </p>
          </div>

          {mappings.length ? (
            <>
              <hr className="hr" />
              <p className="eyebrow">What would have satisfied it</p>
              {mappings.map((m) => (
                <p className="notice" key={m.id} style={{ marginTop: 8 }}>
                  <span className="material">{m.valueFqn}</span>
                  <br />
                  requires {m.conditions.map((c) => `${c.selector} ${c.operator} [${c.values.join(', ')}]`).join(` ${m.booleanOperator} `)}
                  <br />
                  for actions: {m.actions.join(', ') || '—'}
                </p>
              ))}
              <p className="prose" style={{ marginTop: 14 }}>
                That selector reads a Keycloak <em>user attribute</em>, not a token claim — your
                access token carries no classification of any kind. Set the attribute on this
                account in the{' '}
                <a href={KEYCLOAK_ADMIN_URL} target="_blank" rel="noreferrer">
                  admin console
                </a>{' '}
                and press Decrypt again: the entitlement is resolved server-side on every request,
                so the very next attempt uses the new value. No new token, no sign-out.
              </p>
            </>
          ) : null}

          {unmapped.length ? (
            <>
              <hr className="hr" />
              <p className="eyebrow">Why nothing would have satisfied it</p>
              <p className="notice notice--deny" style={{ marginTop: 8 }}>
                {unmapped.map((fqn) => (
                  <span key={fqn}>
                    <span className="material">{fqn}</span>
                    <br />
                  </span>
                ))}
                No subject mapping grants this attribute value, so <strong>no account in this
                realm can currently satisfy it</strong> — not even the one that sealed the file.
                An attribute value with no subject mapping is a lock with no key cut for it.
              </p>
              <p className="prose" style={{ marginTop: 14 }}>
                Create one with{' '}
                <span className="material">otdfctl policy subject-mapping create</span>, then reload
                the Policy panel.
              </p>
            </>
          ) : null}
        </div>
      ) : null}

      {outcome?.outcome === 'refused' && outcome.kind === 'policy-binding' ? (
        <div className="outcome outcome--fault" style={{ marginTop: 18 }}>
          <p className="outcome__flag">Policy binding mismatch</p>
          <p className="outcome__lede">
            The policy in this file was altered after it was sealed. The key server recomputed the
            HMAC over the policy it was handed, compared it with the{' '}
            <span className="material">policyBinding</span> in the manifest, and they do not match —
            so it refused before making any entitlement decision at all.
          </p>
          <div className="verdict">
            <div className="kv">
              <span className="kv__k">result</span>
              <span className="kv__v">
                <span className="tag tag--deny">{outcome.serviceCode ?? 'invalid_argument'}</span>
              </span>
              <span className="kv__k">message</span>
              <span className="kv__v">{outcome.serviceMessage ?? outcome.sdkMessage}</span>
            </div>
            <p className="prose">
              This is the guarantee the envelope panel describes, demonstrated. The binding is an
              HMAC keyed with the data encryption key — which is sealed inside the very key access
              object an attacker would need to open. Whoever holds the file can read its policy and
              can change it, but cannot produce a binding that matches the change.
            </p>
          </div>
        </div>
      ) : null}

      {outcome?.outcome === 'refused' &&
      outcome.kind !== 'denied' &&
      outcome.kind !== 'policy-binding' ? (
        <div className="outcome outcome--fault" style={{ marginTop: 18 }}>
          <p className="outcome__flag">{outcome.headline}</p>
          <p className="prose">
            {outcome.kind === 'unauthenticated'
              ? 'The platform rejected the token itself. That is an authentication failure, not a policy decision — check the audience claim in the Identity panel.'
              : outcome.kind === 'unsafe-kas'
                ? 'The manifest names a key server the platform has not registered, so the SDK refused to contact it. Register it in the KAS registry or use a file sealed against this lab.'
                : outcome.kind === 'integrity'
                  ? 'The key server released the key, but the ciphertext would not authenticate with it. Every segment carries an authentication tag; one of them does not match, so the payload was altered or truncated after sealing. Note the difference from a policy binding mismatch: there the POLICY was edited, here the DATA was.'
                  : outcome.kind === 'network'
                    ? 'The request never reached the platform. Check that the console origin is in the platform CORS allowlist.'
                    : 'The file could not be read as a TDF.'}
          </p>
          <div className="verdict">
            <div className="kv">
              {outcome.serviceCode ? (
                <>
                  <span className="kv__k">result</span>
                  <span className="kv__v">{outcome.serviceCode}</span>
                </>
              ) : null}
              <span className="kv__k">detail</span>
              <span className="kv__v">{outcome.serviceMessage ?? outcome.sdkMessage}</span>
            </div>
          </div>
        </div>
      ) : null}
    </div>
  );
}
