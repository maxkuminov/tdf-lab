import { signIn } from '../auth';
import { ATTRIBUTE_NAMESPACE, OIDC_AUTHORITY, PLATFORM_URL } from '../config';

/**
 * Signed-out screen. The thesis of the lab is the comparison, so the hero is
 * the comparison rather than a product pitch.
 */
export function Gate({ error }: { error: string | null }) {
  return (
    <div className="gate">
      <div className="gate__inner">
        <p className="eyebrow">OpenTDF learning lab · {window.location.host}</p>
        <h1 className="thesis">
          One file.
          <br />
          Two readers.
          <br />
          <span className="thesis__grant">One opens it.</span>{' '}
          <span className="thesis__deny">One cannot.</span>
        </h1>
        <p className="prose">
          The same sealed payload, the same key server, two valid sign-ins. What separates them is
          a single attribute value on a user account — and the decision is made fresh every time
          the file is opened, not once when it was written.
        </p>

        <div className="gate__split">
          <div className="reader reader--grant">
            <p className="reader__name">user-a</p>
            <p className="reader__attr">classification = secret</p>
            <p className="reader__verdict">Rewrap allowed</p>
          </div>
          <div className="reader reader--deny">
            <p className="reader__name">user-b</p>
            <p className="reader__attr">classification = public</p>
            <p className="reader__verdict">Rewrap refused</p>
          </div>
        </div>

        {error ? <p className="notice notice--deny">{error}</p> : null}

        <div className="btn-row" style={{ marginTop: 10 }}>
          <button className="btn btn--primary" onClick={() => void signIn('user-a')}>
            Sign in as user-a
          </button>
          <button className="btn" onClick={() => void signIn('user-b')}>
            Sign in as user-b
          </button>
          <button className="btn btn--ghost" onClick={() => void signIn()}>
            Another account
          </button>
        </div>

        <hr className="hr" />
        <div className="kv">
          <span className="kv__k">platform</span>
          <span className="kv__v">{PLATFORM_URL}</span>
          <span className="kv__k">realm</span>
          <span className="kv__v">{OIDC_AUTHORITY}</span>
          <span className="kv__k">attributes</span>
          <span className="kv__v">
            {ATTRIBUTE_NAMESPACE} <span className="muted">— the policy namespace, not a website</span>
          </span>
        </div>
      </div>
    </div>
  );
}
