import { Panel } from './bits';
import type { PolicySnapshot } from '../policy';

export function PolicyExplorer({
  policy,
  error,
  loading,
  onRefresh,
}: {
  policy: PolicySnapshot | null;
  error: string | null;
  loading: boolean;
  onRefresh: () => void;
}) {
  return (
    <div className="stage__inner">
      <header className="stage__head">
        <p className="eyebrow">Reference — policy</p>
        <h1 className="stage__title">What the platform will enforce</h1>
        <p className="prose">
          Read with your own token over Connect-RPC. Both lab users hold the realm role{' '}
          <em>opentdf-standard</em>, which the platform maps to a casbin role that can read policy
          and not write it — so nothing on this page can change anything.
        </p>
      </header>

      <div className="btn-row" style={{ marginBottom: 18 }}>
        <button className="btn" onClick={onRefresh} disabled={loading}>
          {loading ? 'Reading…' : 'Refresh'}
        </button>
        {policy ? (
          <span className="data muted">
            read {new Date(policy.fetchedAt).toLocaleTimeString()}
          </span>
        ) : null}
      </div>

      {error ? (
        <div className="outcome outcome--fault">
          <p className="outcome__flag">Policy read failed</p>
          <p className="prose">{error}</p>
        </div>
      ) : null}

      {policy ? (
        <>
          <Panel title="Namespaces" aside={`${policy.namespaces.length}`}>
            <div className="scroll-x">
              <table className="table">
                <thead>
                  <tr><th>Name</th><th>FQN</th><th>Active</th></tr>
                </thead>
                <tbody>
                  {policy.namespaces.map((n) => (
                    <tr key={n.id}>
                      <td>{n.name}</td>
                      <td>{n.fqn}</td>
                      <td>{String(n.active)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </Panel>

          <Panel title="Attributes and values" aside={`${policy.attributes.length}`}>
            <div className="scroll-x">
              <table className="table">
                <thead>
                  <tr><th>Attribute</th><th>Rule</th><th>Values</th></tr>
                </thead>
                <tbody>
                  {policy.attributes.map((a) => (
                    <tr key={a.id}>
                      <td>{a.fqn}</td>
                      <td>{a.rule}</td>
                      <td>
                        {a.values.map((v) => (
                          <span className="tag tag--material" key={v.id}>{v.value}</span>
                        ))}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            <p className="prose" style={{ marginTop: 14 }}>
              <em>ANY_OF</em> means holding one of the listed values is enough. The rule lives on the
              attribute, not on the file, so changing it changes the outcome for every file already
              sealed against it.
            </p>
          </Panel>

          <Panel title="Subject mappings" aside={`${policy.subjectMappings.length}`}>
            <div className="scroll-x">
              <table className="table">
                <thead>
                  <tr><th>Grants</th><th>To subjects where</th><th>Actions</th></tr>
                </thead>
                <tbody>
                  {policy.subjectMappings.map((m) => (
                    <tr key={m.id}>
                      <td>{m.valueFqn}</td>
                      <td>
                        {m.conditions
                          .map((c) => `${c.selector} ${c.operator} [${c.values.join(', ')}]`)
                          .join(` ${m.booleanOperator} `)}
                      </td>
                      <td>{m.actions.join(', ')}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            <p className="prose" style={{ marginTop: 14 }}>
              The selector runs against your Keycloak account as the entity resolution service
              returns it, which is why a user attribute — not a role — decides this.
            </p>
          </Panel>

          <Panel title="Key access servers" aside={`${policy.kasRegistry.length}`}>
            <div className="scroll-x">
              <table className="table">
                <thead>
                  <tr><th>Name</th><th>URI</th></tr>
                </thead>
                <tbody>
                  {policy.kasRegistry.map((k) => (
                    <tr key={k.id}>
                      <td>{k.name}</td>
                      <td>{k.uri}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            <p className="prose" style={{ marginTop: 14 }}>
              This registry is also the allowlist. A .tdf naming a key server that is not here is
              refused before any request goes out, so a hostile file cannot make your browser talk
              to an attacker's server.
            </p>
          </Panel>
        </>
      ) : null}
    </div>
  );
}
