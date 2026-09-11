import { useState } from 'react';
import type { User } from 'oidc-client-ts';
import { Panel } from './bits';
import { Flow } from './Flow';
import { buildLoginFlow } from '../flow';
import { claimAsList, decodeJwt } from '../auth';
import { useRpcCalls } from './useRpc';
import { clearRpcCalls } from '../rpc';
import { KEYCLOAK_ADMIN_URL, OIDC_AUTHORITY, OIDC_CLIENT_ID, PLATFORM_URL } from '../config';

export function Identity({ user }: { user: User }) {
  const [rawOpen, setRawOpen] = useState(false);
  const calls = useRpcCalls();
  const claims = decodeJwt(user.access_token) ?? {};

  const aud = claimAsList(claims.aud);
  const realmRoles = claimAsList((claims.realm_access as { roles?: unknown } | undefined)?.roles);
  const audienceOk = aud.includes(PLATFORM_URL);
  const expiresIn = user.expires_at ? user.expires_at - Math.floor(Date.now() / 1000) : null;

  return (
    <div className="stage__inner">
      <header className="stage__head">
        <p className="eyebrow">Reference — identity</p>
        <h1 className="stage__title">The token you are carrying</h1>
        <p className="prose">
          Signed by the lab realm, redeemed by this page with authorization code + PKCE. The
          platform never sees your password and this console never holds a client secret — there
          isn't one to hold.
        </p>
      </header>

      <Panel
        title="Session"
        aside={expiresIn !== null ? `expires in ${Math.max(0, expiresIn)}s · auto-renews` : undefined}
      >
        <div className="kv">
          <span className="kv__k">username</span>
          <span className="kv__v">{String(claims.preferred_username ?? user.profile.sub)}</span>
          <span className="kv__k">email</span>
          <span className="kv__v">{String(claims.email ?? '—')}</span>
          <span className="kv__k">subject</span>
          <span className="kv__v">{String(claims.sub ?? '—')}</span>
          <span className="kv__k">issuer</span>
          <span className="kv__v">{String(claims.iss ?? OIDC_AUTHORITY)}</span>
          <span className="kv__k">azp</span>
          <span className="kv__v">{String(claims.azp ?? OIDC_CLIENT_ID)}</span>
          <span className="kv__k">audience</span>
          <span className="kv__v">
            {aud.map((a) => (
              <span className={`tag ${a === PLATFORM_URL ? 'tag--grant' : ''}`} key={a}>
                {a}
              </span>
            ))}
          </span>
          <span className="kv__k">realm roles</span>
          <span className="kv__v">
            {realmRoles.map((r) => (
              <span className="tag" key={r}>{r}</span>
            ))}
          </span>
          <span className="kv__k">scope</span>
          <span className="kv__v muted">{String(claims.scope ?? '—')}</span>
        </div>

        <p className={`notice ${audienceOk ? '' : 'notice--deny'}`} style={{ marginTop: 16 }}>
          {audienceOk ? (
            <>
              The audience claim contains <span className="material">{PLATFORM_URL}</span>, which is
              what the platform checks before it looks at policy at all. Without it every call would
              fail with an audience error that reads like a permissions problem and is not one.
            </>
          ) : (
            <>
              This token is missing <span className="material">{PLATFORM_URL}</span> from its
              audience. The platform will reject it outright — the <code>web-console</code> client is
              missing its audience protocol mapper.
            </>
          )}
        </p>
      </Panel>

      <Flow run={buildLoginFlow(claims)} running={false} />

      <Panel title="Wire log" aside={`${calls.length} calls`}>
        <p className="prose" style={{ marginBottom: 12 }}>
          Connect-RPC requests made through <em>this app's</em> client, newest last — policy reads,
          the attribute lookup during encrypt, and the rewrap. The SDK also fetches the key server's
          public key through a client it builds internally, and those calls do not pass through
          here, so the browser's network tab will show a few more than this list does. The key
          server's refusal appears here in the platform's own words, before the SDK rewrites it.
        </p>
        {calls.length === 0 ? (
          <p className="notice">Nothing yet. Read the policy or decrypt something.</p>
        ) : (
          <div className="wire">
            {calls.map((c) => (
              <div className="wire__row" key={c.id}>
                <span className="wire__path" title={c.rawMessage ?? c.path}>
                  {c.path}
                </span>
                <span className="wire__ms">{c.durationMs.toFixed(0)}ms</span>
                <span className={c.ok ? 'wire__ok' : 'wire__bad'}>{c.ok ? 'ok' : c.code}</span>
              </div>
            ))}
          </div>
        )}
        <div className="btn-row" style={{ marginTop: 14 }}>
          <button className="btn btn--ghost btn--small" onClick={clearRpcCalls}>
            Clear
          </button>
        </div>
      </Panel>

      <Panel title="Raw claims">
        <button className="btn btn--ghost btn--small" onClick={() => setRawOpen((v) => !v)}>
          {rawOpen ? 'Hide decoded access token' : 'Show decoded access token'}
        </button>
        {rawOpen ? (
          <pre className="code" style={{ marginTop: 12 }}>{JSON.stringify(claims, null, 2)}</pre>
        ) : null}
        <p className="prose" style={{ marginTop: 14 }}>
          Notice what is <em>not</em> here: no classification, no entitlement, nothing about what
          you may open. The token only says who you are. The platform's entity resolution service
          reads your <em>classification</em> user attribute straight out of Keycloak at the moment
          of each decision.
        </p>
        <p className="prose" style={{ marginTop: 10 }}>
          So to flip an account's entitlement, change that attribute in the{' '}
          <a href={KEYCLOAK_ADMIN_URL} target="_blank" rel="noreferrer">Keycloak admin console</a>{' '}
          and press Decrypt again. <strong>No sign-out and no new token</strong> — the token you are
          already holding starts producing the new answer immediately. Measured on this lab: a
          decrypt denied at t+0 succeeded with the same token about a second after the attribute
          changed, and went back to denied a second after it was changed back.
        </p>
      </Panel>
    </div>
  );
}
