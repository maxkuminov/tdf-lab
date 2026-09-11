import { useCallback, useEffect, useMemo, useState } from 'react';
import type { User } from 'oidc-client-ts';
import { completeSignin, decodeJwt, forgetSession, isSigninCallback, signOut, userManager } from './auth';
import { createClients, type LabClients } from './tdf';
import { fetchPolicy, type PolicySnapshot } from './policy';
import type { TdfFile } from './manifest';
import { Gate } from './components/Gate';
import { Encrypt } from './components/Encrypt';
import { Decrypt } from './components/Decrypt';
import { Envelope } from './components/Envelope';
import { PolicyExplorer } from './components/PolicyExplorer';
import { Identity } from './components/Identity';
import { HowItWorks } from './components/HowItWorks';
import { Library } from './components/Library';
import { Records } from './components/Records';
import { OIDC_AUTHORITY, PLATFORM_URL } from './config';

type View = 'library' | 'records' | 'encrypt' | 'decrypt' | 'policy' | 'identity' | 'how';

// The library is a destination, not a step, so it is unnumbered and sits
// first: it is what the lab is FOR. Encrypt/Decrypt below it are the bench
// where the same two operations can be driven one at a time.
const SHARED: { id: View; label: string }[] = [
  { id: 'library', label: 'Library' },
  { id: 'records', label: 'Database' },
];

const SEQUENCE: { id: View; num: string; label: string }[] = [
  { id: 'encrypt', num: '01', label: 'Encrypt' },
  { id: 'decrypt', num: '02', label: 'Decrypt' },
];

const REFERENCE: { id: View; label: string }[] = [
  { id: 'policy', label: 'Policy' },
  { id: 'identity', label: 'Identity' },
  { id: 'how', label: 'How this works' },
];

export function App() {
  const [user, setUser] = useState<User | null>(null);
  const [booted, setBooted] = useState(false);
  const [authError, setAuthError] = useState<string | null>(null);
  const [view, setView] = useState<View>('library');
  const [tdfFile, setTdfFile] = useState<TdfFile | null>(null);
  const [policy, setPolicy] = useState<PolicySnapshot | null>(null);
  const [policyError, setPolicyError] = useState<string | null>(null);
  const [policyLoading, setPolicyLoading] = useState(false);

  // Boot: finish a redirect if we landed on one, otherwise restore a session.
  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        if (isSigninCallback()) {
          const u = await completeSignin();
          if (!cancelled) setUser(u);
        } else {
          const u = await userManager.getUser();
          if (!cancelled) setUser(u && !u.expired ? u : null);
        }
      } catch (err) {
        if (!cancelled) setAuthError(err instanceof Error ? err.message : String(err));
      } finally {
        if (!cancelled) setBooted(true);
      }
    })();
    return () => {
      cancelled = true;
    };
  }, []);

  useEffect(() => {
    const onLoaded = (u: User) => setUser(u);
    const onUnloaded = () => setUser(null);
    const onExpired = () => setUser(null);
    userManager.events.addUserLoaded(onLoaded);
    userManager.events.addUserUnloaded(onUnloaded);
    userManager.events.addAccessTokenExpired(onExpired);
    return () => {
      userManager.events.removeUserLoaded(onLoaded);
      userManager.events.removeUserUnloaded(onUnloaded);
      userManager.events.removeAccessTokenExpired(onExpired);
    };
  }, []);

  // One token source for everything: the OpenTDF SDK clients and the share
  // API. Read from the manager per request so a silent refresh is picked up
  // without rebuilding anything.
  const getToken = useCallback(async () => {
    const current = await userManager.getUser();
    if (!current || current.expired) {
      throw new Error('Your session expired. Sign in again.');
    }
    return current.access_token;
  }, []);

  const clients: LabClients | null = useMemo(
    () => (user ? createClients(getToken) : null),
    [user?.profile.sub, user?.session_state, getToken],
  );

  const loadPolicy = useCallback(async () => {
    if (!clients) return;
    setPolicyLoading(true);
    setPolicyError(null);
    try {
      setPolicy(await fetchPolicy(clients));
    } catch (err) {
      setPolicyError(err instanceof Error ? err.message : String(err));
    } finally {
      setPolicyLoading(false);
    }
  }, [clients]);

  useEffect(() => {
    if (clients) void loadPolicy();
  }, [clients, loadPolicy]);

  if (!booted) {
    return (
      <div className="gate">
        <p className="eyebrow">Restoring session…</p>
      </div>
    );
  }

  if (!user || !clients) {
    return <Gate error={authError} />;
  }

  const username = String(user.profile.preferred_username ?? user.profile.sub ?? 'you');
  // Decoded once here so every panel shows the SAME real token, not a re-parse.
  const claims = decodeJwt(user.access_token);

  return (
    <div className="shell">
      <header className="banner">
        <div className="wordmark">
          <span className="wordmark__mark" aria-hidden="true">[▚]</span>
          <span>TDF Lab Console</span>
        </div>
        <div className="banner__status">
          <span className="status-dot status-dot--live">platform {hostOf(PLATFORM_URL)}</span>
          <span className="status-dot status-dot--live">realm lab-realm</span>
          <span className="status-dot">{tdfFile ? tdfFile.name : 'no file loaded'}</span>
        </div>
        <div className="banner__who">
          <span className="whoami">
            <span className="whoami__name">{username}</span>
            <span className="whoami__realm">{hostOf(OIDC_AUTHORITY)}</span>
          </span>
          <button
            className="btn btn--ghost btn--small"
            onClick={() => void signOut().catch(() => forgetSession())}
          >
            Sign out
          </button>
        </div>
      </header>

      <div className="workspace">
        <nav className="rail" aria-label="Console sections">
          <div className="rail__group">
            <p className="eyebrow">Shared</p>
            {SHARED.map((item) => (
              <button
                key={item.id}
                className="rail__item"
                aria-current={view === item.id}
                onClick={() => setView(item.id)}
              >
                <span className="rail__num rail__num--blank" aria-hidden="true">&#9635;</span>
                <span>{item.label}</span>
              </button>
            ))}
          </div>
          <div className="rail__group">
            <p className="eyebrow">Sequence</p>
            {SEQUENCE.map((item) => (
              <button
                key={item.id}
                className="rail__item"
                aria-current={view === item.id}
                onClick={() => setView(item.id)}
              >
                <span className="rail__num">{item.num}</span>
                <span>{item.label}</span>
              </button>
            ))}
          </div>
          <div className="rail__group">
            <p className="eyebrow">Reference</p>
            {REFERENCE.map((item) => (
              <button
                key={item.id}
                className="rail__item"
                aria-current={view === item.id}
                onClick={() => setView(item.id)}
              >
                <span className="rail__num rail__num--blank" aria-hidden="true">·</span>
                <span>{item.label}</span>
              </button>
            ))}
          </div>
        </nav>

        <main className="stage">
          {view === 'library' ? (
            <Library
              clients={clients}
              policy={policy}
              username={username}
              claims={claims}
              getToken={getToken}
              onLoaded={setTdfFile}
            />
          ) : null}
          {view === 'records' ? (
            <Records clients={clients} username={username} onLoaded={setTdfFile} />
          ) : null}
          {view === 'encrypt' ? (
            <Encrypt
              clients={clients}
              policy={policy}
              claims={claims}
              onLoaded={setTdfFile}
              onGoToDecrypt={() => setView('decrypt')}
            />
          ) : null}
          {view === 'decrypt' ? (
            <Decrypt
              clients={clients}
              loaded={tdfFile}
              policy={policy}
              username={username}
              claims={claims}
              onLoaded={setTdfFile}
            />
          ) : null}
          {view === 'policy' ? (
            <PolicyExplorer
              policy={policy}
              error={policyError}
              loading={policyLoading}
              onRefresh={() => void loadPolicy()}
            />
          ) : null}
          {view === 'identity' ? <Identity user={user} /> : null}
          {view === 'how' ? <HowItWorks /> : null}
        </main>

        <aside className="aside" aria-label="Manifest inspector">
          <Envelope file={tdfFile} />
        </aside>
      </div>
    </div>
  );
}

function hostOf(url: string): string {
  try {
    return new URL(url).host;
  } catch {
    return url;
  }
}
