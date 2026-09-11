import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { Panel } from './bits';
import { decryptTdf, type LabClients } from '../tdf';
import { formatBytes, openTdfFile, type TdfFile } from '../manifest';

/**
 * The Database panel: a small SQL workload where the sensitive columns hold
 * ciphertext, one sealed TDF per CELL, each bound to its row's classification
 * attribute. The table itself (records.json, exported by dbdemo/dbdemo.py
 * from records.sqlite) is served to ANYONE without a token — possession is
 * not access. What a signed-in reader can turn into plaintext is decided
 * per cell, per click, by the key server: every decrypt here is one real
 * rewrap, and a DENIED cell is the KAS refusing it, not this page.
 *
 * This demo was scoped for NanoTDF (~300 B per sealed cell, built for exactly
 * this workload) — but NanoTDF was removed from OpenTDF in the v0.12.0
 * releases of 2026-01-27 (platform PR #3013), server rewrap path included, so
 * no client of any age can nano-round-trip against this KAS. Standard TDF is
 * what remains, and the ~1.7 KB per cell below is its honest price.
 */

type RecordsCell = { b64: string; bytes: number };

type RecordsRow = {
  id: number;
  name: string;
  department: string;
  classification: string;
  fqn: string;
  cells: Record<string, RecordsCell>;
};

type RecordsDoc = {
  generatedAt: string;
  table: string;
  encryptedFields: string[];
  fqnBase: string;
  rows: RecordsRow[];
};

type CellState =
  | { phase: 'sealed' }
  | { phase: 'working' }
  | { phase: 'granted'; text: string }
  | { phase: 'denied'; serviceMessage?: string }
  | { phase: 'error'; message: string };

const SEALED: CellState = { phase: 'sealed' };

function b64ToBytes(b64: string): Uint8Array {
  const binary = atob(b64);
  return Uint8Array.from(binary, (c) => c.charCodeAt(0));
}

export function Records({
  clients,
  username,
  onLoaded,
}: {
  clients: LabClients;
  username: string;
  onLoaded: (file: TdfFile) => void;
}) {
  const [doc, setDoc] = useState<RecordsDoc | null>(null);
  const [docError, setDocError] = useState<string | null>(null);
  const [cells, setCells] = useState<Record<string, CellState>>({});
  const [bulkRunning, setBulkRunning] = useState(false);
  const outcomeRef = useRef<HTMLDivElement | null>(null);
  // The signed-in user can change (sign out / in) while this panel is mounted;
  // a decrypt result from the previous account must not survive into the next.
  const userRef = useRef(username);
  useEffect(() => {
    if (userRef.current !== username) {
      userRef.current = username;
      setCells({});
    }
  }, [username]);

  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        // Cache-buster: dbdemo.py re-exports in place and nginx serves the
        // file with heuristic caching; a stale table after a re-seed would
        // decrypt into confusing mismatches.
        const res = await fetch(`/records.json?t=${Date.now()}`);
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        const parsed = (await res.json()) as RecordsDoc;
        if (!cancelled) setDoc(parsed);
      } catch (err) {
        if (!cancelled)
          setDocError(
            `Could not load the sealed table (${err instanceof Error ? err.message : String(err)}). ` +
              'Run `python3 dbdemo.py seed && python3 dbdemo.py export` on the host.',
          );
      }
    })();
    return () => {
      cancelled = true;
    };
  }, []);

  const keyOf = (row: RecordsRow, field: string) => `${row.id}:${field}`;

  const decryptCell = useCallback(
    async (row: RecordsRow, field: string) => {
      const key = keyOf(row, field);
      const bytes = b64ToBytes(row.cells[field].b64);
      setCells((c) => ({ ...c, [key]: { phase: 'working' } }));
      const outcome = await decryptTdf(clients, bytes);
      setCells((c) => {
        // Ignore a straggler that raced a sign-out reset.
        if (!(key in c)) return c;
        let next: CellState;
        if (outcome.outcome === 'granted') {
          next = { phase: 'granted', text: outcome.text ?? '(binary payload)' };
        } else if (outcome.kind === 'denied') {
          next = { phase: 'denied', serviceMessage: outcome.serviceMessage };
        } else {
          next = { phase: 'error', message: outcome.headline };
        }
        return { ...c, [key]: next };
      });
    },
    [clients],
  );

  /** Re-open a resolved cell's manifest in the inspector — no new rewrap. */
  const inspectCell = useCallback(
    async (row: RecordsRow, field: string) => {
      try {
        const bytes = b64ToBytes(row.cells[field].b64);
        onLoaded(await openTdfFile(bytes, `${doc?.table ?? 'records'}.${row.id}.${field}.tdf`));
      } catch {
        // Inspector is a bonus; nothing else depends on it.
      }
    },
    [doc?.table, onLoaded],
  );

  /** Click on one cell: show its real manifest in the inspector, then rewrap. */
  const onCellClick = useCallback(
    async (row: RecordsRow, field: string) => {
      const bytes = b64ToBytes(row.cells[field].b64);
      try {
        onLoaded(await openTdfFile(bytes, `${doc?.table ?? 'records'}.${row.id}.${field}.tdf`));
      } catch {
        // The inspector is a bonus; the rewrap below still tells the truth.
      }
      await decryptCell(row, field);
    },
    [decryptCell, doc?.table, onLoaded],
  );

  const decryptAll = useCallback(async () => {
    if (!doc) return;
    setBulkRunning(true);
    try {
      const work: [RecordsRow, string][] = [];
      for (const row of doc.rows)
        for (const field of doc.encryptedFields) {
          // A settled verdict (granted or denied) is not re-asked; a failed
          // cell is retried. Reseal to deliberately re-run settled cells.
          const st = cells[keyOf(row, field)];
          if (!st || st.phase === 'sealed' || st.phase === 'error') work.push([row, field]);
        }
      // A few at a time: 15 simultaneous rewraps is a rate-limit test, not a demo.
      const pool = 4;
      let i = 0;
      await Promise.all(
        Array.from({ length: pool }, async () => {
          while (i < work.length) {
            const [row, field] = work[i++];
            await decryptCell(row, field);
          }
        }),
      );
    } finally {
      setBulkRunning(false);
    }
    // The outcome tally is the payoff and renders below the fold on short
    // viewports; bring it into view once the batch settles (MINOR: a user who
    // clicked the button never saw the verdict without scrolling).
    requestAnimationFrame(() => {
      outcomeRef.current?.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
    });
  }, [doc, cells, decryptCell]);

  const tally = useMemo(() => {
    let granted = 0;
    let denied = 0;
    let failed = 0;
    for (const s of Object.values(cells)) {
      if (s.phase === 'granted') granted += 1;
      else if (s.phase === 'denied') denied += 1;
      else if (s.phase === 'error') failed += 1;
    }
    return { granted, denied, failed, any: granted + denied + failed > 0 };
  }, [cells]);

  const totalCells = doc ? doc.rows.length * doc.encryptedFields.length : 0;
  const settled = tally.granted + tally.denied;

  const sealedTotal = useMemo(() => {
    if (!doc) return 0;
    return doc.rows.reduce(
      (sum, r) => sum + doc.encryptedFields.reduce((s, f) => s + r.cells[f].bytes, 0),
      0,
    );
  }, [doc]);

  return (
    <div className="stage__inner">
      <header className="stage__head">
        <p className="eyebrow">Shared — database</p>
        <h1 className="stage__title">A table whose secrets are sealed per cell</h1>
        <p className="prose">
          An <span className="material">employees</span> table from a SQLite database on the host.
          The plain columns are ordinary data; the sensitive columns hold{' '}
          <strong>one sealed TDF per cell</strong>, bound to the row's{' '}
          <span className="material">classification</span> attribute. This whole table — ciphertext
          included — is public at <span className="material">/records.json</span>, no token needed:
          possession is not access. Click a cell (or decrypt everything) and each answer is one
          live rewrap at the key server, decided against <em>your</em> entitlements, fresh, every
          time.
        </p>
      </header>

      {docError ? (
        <div className="outcome outcome--fault">
          <p className="outcome__flag">Sealed table unavailable</p>
          <p className="prose">{docError}</p>
        </div>
      ) : null}

      {doc ? (
        <>
          <div className="btn-row" style={{ marginBottom: 18 }}>
            <button
              className="btn btn--primary"
              onClick={() => void decryptAll()}
              disabled={bulkRunning || settled >= totalCells}
            >
              {bulkRunning
                ? 'Rewrapping…'
                : settled >= totalCells
                  ? 'All cells answered'
                  : `Decrypt all ${totalCells} cells as ${username}`}
            </button>
            <button
              className="btn btn--ghost"
              onClick={() => setCells({})}
              disabled={bulkRunning || !tally.any}
            >
              Reseal view
            </button>
            <span className="data muted">exported {doc.generatedAt}</span>
          </div>

          <Panel
            title={`${doc.table} — ${doc.rows.length} rows`}
            aside={`${doc.encryptedFields.length} sealed columns`}
          >
            <div className="scroll-x">
              <table className="table">
                <thead>
                  <tr>
                    <th>Name</th>
                    <th>Department</th>
                    <th>Classification</th>
                    {doc.encryptedFields.map((f) => (
                      <th key={f}>{f} 🔒</th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {doc.rows.map((row) => (
                    <tr key={row.id}>
                      <td>{row.name}</td>
                      <td>{row.department}</td>
                      <td>
                        <span
                          className={`tag ${row.classification === 'secret' ? 'tag--material' : ''}`}
                          title={row.fqn}
                        >
                          {row.classification}
                        </span>
                      </td>
                      {doc.encryptedFields.map((field) => (
                        <td key={field}>
                          <Cell
                            state={cells[keyOf(row, field)] ?? SEALED}
                            bytes={row.cells[field].bytes}
                            busy={bulkRunning}
                            onOpen={() => void onCellClick(row, field)}
                            onInspect={() => void inspectCell(row, field)}
                          />
                        </td>
                      ))}
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            <p className="prose" style={{ marginTop: 14 }}>
              Clicking a cell also loads that cell's manifest into the envelope inspector (beside
              the table on a wide screen, below it on a narrow one) — every cell is a complete,
              self-describing TDF with its own wrapped key and policy binding. A decrypted or
              denied cell stays clickable to re-open its manifest without asking the key server
              again.
            </p>
          </Panel>

          {tally.any ? (
            <div
              ref={outcomeRef}
              className={`outcome ${tally.denied > 0 ? 'outcome--denied' : 'outcome--granted'}`}
              style={{ marginTop: 18 }}
            >
              <p className="outcome__flag">
                {tally.granted} granted · {tally.denied} denied
                {tally.failed ? ` · ${tally.failed} failed` : ''}
                {settled < totalCells ? ` · ${totalCells - settled} still sealed` : ''}
              </p>
              <p className="prose">
                {tally.denied > 0 ? (
                  <>
                    Every <strong>DENIED</strong> is the key server refusing a rewrap because{' '}
                    <span className="material">{username}</span>'s entitlements do not satisfy that
                    row's classification — the browser asked in earnest and was turned down, over
                    an HTTP 200. The ciphertext sits in this page's memory either way; it is
                    exactly as useless as it was on the wire.
                  </>
                ) : settled >= totalCells ? (
                  <>
                    Every cell in the table rewrapped: <span className="material">{username}</span>
                    's entitlements satisfy every row's classification.
                    {username !== 'user-b' ? (
                      <> Sign in as user-b to watch the same table refuse the secret rows.</>
                    ) : null}
                  </>
                ) : (
                  <>
                    {tally.granted} of {totalCells} cells rewrapped so far — each one a fresh
                    decision at the key server, nothing cached. Decrypt the rest, or keep clicking
                    cells one at a time.
                  </>
                )}
              </p>
            </div>
          ) : null}

          <Panel title="What per-cell sealing costs" aside={formatBytes(sealedTotal)}>
            <p className="prose">
              Each sealed cell is ~{formatBytes(doc.rows[0].cells[doc.encryptedFields[0]].bytes)}{' '}
              of zip + JSON manifest protecting a value of a few dozen bytes — a 60–220× blowup,
              and {doc.rows.length * doc.encryptedFields.length} cells cost{' '}
              {formatBytes(sealedTotal)} in total. The manifest being self-describing is what makes
              each cell independently portable and enforceable; that is the price.
            </p>
            <p className="prose" style={{ marginTop: 10 }}>
              <strong>This demo was scoped for NanoTDF</strong> — a compact binary TDF (~300 B per
              cell) designed for exactly this workload. NanoTDF was removed from OpenTDF in the
              v0.12.0 releases of 2026-01-27 (platform PR #3013): key server rewrap path, SDKs and
              spec docs in one sweep, consolidating on the standard format. No client of any age
              can nano-round-trip against this platform any more.
            </p>
          </Panel>
        </>
      ) : docError ? null : (
        <p className="prose muted">Loading the sealed table…</p>
      )}
    </div>
  );
}

function Cell({
  state,
  bytes,
  busy,
  onOpen,
  onInspect,
}: {
  state: CellState;
  bytes: number;
  busy: boolean;
  onOpen: () => void;
  onInspect: () => void;
}) {
  if (state.phase === 'granted')
    return (
      <button
        type="button"
        className="cellval data"
        onClick={onInspect}
        title="Decrypted. Click to re-open this cell's manifest — no new rewrap."
      >
        {state.text}
      </button>
    );
  if (state.phase === 'denied')
    return (
      <button
        type="button"
        className="tag tag--deny"
        onClick={onInspect}
        title={`${state.serviceMessage ?? 'rewrap refused by policy'} — click to re-open this cell's manifest`}
      >
        DENIED
      </button>
    );
  if (state.phase === 'error')
    return (
      <span className="tag tag--failing" title={state.message}>
        failed
      </span>
    );
  if (state.phase === 'working') return <span className="tag">rewrapping…</span>;
  return (
    <button
      type="button"
      className="tag tag--material"
      disabled={busy}
      onClick={onOpen}
      title={`Sealed TDF, ${formatBytes(bytes)}. Click to inspect and rewrap.`}
    >
      ▒▒ sealed · {formatBytes(bytes)}
    </button>
  );
}
