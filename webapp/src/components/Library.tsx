import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { FileDrop, Panel, WrapperWarning } from './bits';
import { Flow } from './Flow';
import { buildDecryptFlow, buildEncryptFlow } from '../flow';
import {
  attributeSetKey,
  deleteFile,
  downloadFile,
  formatWhen,
  guessAccess,
  listFiles,
  uploadFile,
  uploadSealed,
  ShareApiError,
  type AccessGuess,
  type LibraryFile,
  type LibraryListing,
  type Observation,
  type TokenSource,
} from '../share';
import { allValues, type PolicySnapshot } from '../policy';
import { MAX_UPLOAD_BYTES } from '../config';
import { decryptTdf, download, encryptToTdf, type DecryptOutcome, type LabClients } from '../tdf';
import { formatBytes, openTdfFile, NotATdfError, type TdfFile, type TdfManifest } from '../manifest';
import { buildSealedHtml, sealedHtmlName, unwrapIfHtml, MAX_HTML_WRAP_BYTES } from '../wrapper/html';
import { useRpcCalls } from './useRpc';

type UploadPhase = 'idle' | 'sealing' | 'uploading' | 'done';

// Each label is an OBSERVATION about the past, never a promise about the next
// rewrap. "opened" / "refused" are facts about this exact file; "should open" /
// "should refuse" are inferences from another file with the identical
// attribute set.
const GUESS_LABEL: Record<AccessGuess, string> = {
  'open-to-all': 'no attributes',
  opened: 'you opened this',
  refused: 'you were refused',
  'likely-yes': 'should open',
  'likely-no': 'should refuse',
  unknown: 'untested',
};

const GUESS_CLASS: Record<AccessGuess, string> = {
  'open-to-all': 'tag--grant',
  opened: 'tag--grant',
  refused: 'tag--deny',
  'likely-yes': 'tag--grant',
  'likely-no': 'tag--deny',
  unknown: '',
};

const GUESS_TITLE: Record<AccessGuess, string> = {
  'open-to-all': 'No attributes, so any signed-in account can open it.',
  opened: 'A fact: you opened this exact file earlier this session.',
  refused: 'A fact: the key server refused you this exact file earlier this session.',
  'likely-yes': 'Inferred: a different file with the identical attribute set opened for you. Only Open proves it.',
  'likely-no': 'Inferred: a different file with the identical attribute set was refused. Only Open proves it.',
  unknown: 'Not tried yet. The browser cannot know in advance — press Open to find out.',
};

export function Library({
  clients,
  policy,
  username,
  claims,
  getToken,
  onLoaded,
}: {
  clients: LabClients;
  policy: PolicySnapshot | null;
  username: string;
  claims: Record<string, unknown> | null;
  getToken: TokenSource;
  onLoaded: (file: TdfFile) => void;
}) {
  const [listing, setListing] = useState<LibraryListing | null>(null);
  const [listError, setListError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  const [file, setFile] = useState<File | null>(null);
  const [selected, setSelected] = useState<string[]>([]);
  const [phase, setPhase] = useState<UploadPhase>('idle');
  const [uploadError, setUploadError] = useState<string | null>(null);
  // Set when the dropped file already looks like a sealed .tdf, so the user can
  // publish it as-is instead of double-sealing it.
  const [presealed, setPresealed] = useState<TdfFile | null>(null);
  const [publishAsIs, setPublishAsIs] = useState(false);

  const [publishManifest, setPublishManifest] = useState<TdfManifest | null>(null);
  const [openedManifest, setOpenedManifest] = useState<TdfManifest | null>(null);
  const [openingId, setOpeningId] = useState<string | null>(null);
  const [outcome, setOutcome] = useState<{ id: string; result: DecryptOutcome; file: LibraryFile } | null>(null);
  // Two-click delete guard: the id awaiting confirmation, if any.
  const [confirmDelete, setConfirmDelete] = useState<string | null>(null);

  // Observations, keyed on the file's WHOLE canonical attribute set (never on
  // individual values, which would over-generalise an ANY_OF success). Last
  // write wins, so a later outcome supersedes a stale one.
  const [observations, setObservations] = useState<ReadonlyMap<string, Observation>>(new Map());

  const calls = useRpcCalls();
  // Scroll the just-started flow into view: on a short viewport the diagram
  // begins well below the fold, so an Open with no visible feedback reads as a
  // dead click.
  const openFlowRef = useRef<HTMLDivElement>(null);
  useEffect(() => {
    if (openingId && openFlowRef.current) {
      openFlowRef.current.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
    }
  }, [openingId]);
  const values = useMemo(() => allValues(policy), [policy]);
  const tooBig = !!file && file.size > MAX_UPLOAD_BYTES;
  const busy = phase === 'sealing' || phase === 'uploading';

  const refresh = useCallback(async () => {
    setLoading(true);
    setListError(null);
    try {
      setListing(await listFiles(getToken));
    } catch (err) {
      setListError(err instanceof Error ? err.message : String(err));
    } finally {
      setLoading(false);
    }
  }, [getToken]);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  function toggle(fqn: string) {
    setSelected((s) => (s.includes(fqn) ? s.filter((v) => v !== fqn) : [...s, fqn]));
  }

  /**
   * On drop, look at the bytes: if they already parse as a sealed .tdf, offer
   * to publish them as-is rather than sealing them a second time. This is a
   * very easy mistake to make given the prominent "Get .tdf" button, and it
   * produces useless `name.tdf.tdf` double-wrapped files.
   */
  async function onFile(f: File) {
    setUploadError(null);
    setPhase('idle');
    setPublishAsIs(false);
    setPresealed(null);
    setFile(f);
    // Size before bytes: `tooBig` below already blocks the publish, but this
    // function reads the whole file to sniff for a pre-sealed .tdf, and that
    // read happens before anyone presses anything.
    if (f.size > MAX_UPLOAD_BYTES) return;
    try {
      // An HTML wrapper is a .tdf in a costume; unwrap it so "publish as-is"
      // stores the sealed bytes rather than a page containing them.
      const raw = new Uint8Array(await f.arrayBuffer());
      const { bytes, filename } = unwrapIfHtml(raw, f.name);
      const parsed = await openTdfFile(bytes, filename);
      setPresealed(parsed);
      setPublishAsIs(true); // default to the safe choice: don't double-seal
    } catch (err) {
      // Not a TDF — the normal case; seal it below. Anything other than "not a
      // TDF" is surfaced when they try to publish.
      if (!(err instanceof NotATdfError)) {
        // leave it; a genuine read error will resurface on publish
      }
    }
  }


  function resetPublish() {
    setFile(null);
    setSelected([]);
    setPresealed(null);
    setPublishAsIs(false);
  }

  async function publish() {
    if (!file) return;
    setUploadError(null);
    try {
      if (presealed && publishAsIs) {
        // Already a .tdf: upload the bytes untouched. No second seal, and the
        // recorded attributes come from the manifest it already carries.
        setPhase('uploading');
        onLoaded(presealed);
        setPublishManifest(presealed.manifest);
        await uploadSealed(getToken, presealed.bytes, presealed.name);
      } else {
        setPhase('sealing');
        const sealed = await encryptToTdf(clients, file, selected);
        const parsedNew = await openTdfFile(sealed.bytes, sealed.filename);
        setPublishManifest(parsedNew.manifest);
        onLoaded(parsedNew);
        setPhase('uploading');
        await uploadFile(getToken, sealed.bytes, sealed.filename);
      }
      setPhase('done');
      resetPublish();
      await refresh();
    } catch (err) {
      setUploadError(err instanceof Error ? err.message : String(err));
      setPhase('idle');
    }
  }

  async function open(record: LibraryFile) {
    setOpeningId(record.id);
    setOutcome(null);
    try {
      const bytes = await downloadFile(getToken, record.id);
      const parsedOpen = await openTdfFile(bytes, record.filename);
      setOpenedManifest(parsedOpen.manifest);
      onLoaded(parsedOpen);
      const result = await decryptTdf(clients, bytes);
      setOutcome({ id: record.id, result, file: record });
      // Record the outcome against the file's WHOLE attribute set, last write
      // wins. Only a decided grant/deny counts; a network or tamper fault says
      // nothing about entitlement, so it is not recorded.
      const decided =
        result.outcome === 'granted' ? 'granted' : result.kind === 'denied' ? 'denied' : null;
      if (decided) {
        const key = attributeSetKey(record.attributes);
        setObservations((prev) => {
          const next = new Map(prev);
          next.set(key, { outcome: decided, fileId: record.id });
          return next;
        });
      }
    } catch (err) {
      setListError(err instanceof Error ? err.message : String(err));
    } finally {
      setOpeningId(null);
    }
  }

  /**
   * The same sealed bytes, wrapped in a self-contained page that can read its
   * own manifest anywhere and decrypt in place when served from this origin
   * (section 10l). Downloading is still not access: the wrapper adds a reader,
   * never a key.
   */
  async function fetchSealedHtml(record: LibraryFile) {
    try {
      const bytes = await downloadFile(getToken, record.id);
      const { bytes: tdf, filename } = unwrapIfHtml(bytes, record.filename);
      onLoaded(await openTdfFile(tdf, filename));
      const html = buildSealedHtml({ tdf, filename });
      download(new TextEncoder().encode(html), sealedHtmlName(filename), 'text/html;charset=utf-8');
    } catch (err) {
      setListError(err instanceof Error ? err.message : String(err));
    }
  }

  async function fetchSealed(record: LibraryFile) {
    try {
      const bytes = await downloadFile(getToken, record.id);
      onLoaded(await openTdfFile(bytes, record.filename));
      download(bytes, record.filename, 'application/tdf');
    } catch (err) {
      setListError(err instanceof Error ? err.message : String(err));
    }
  }

  /**
   * Two-click delete. Deletion is permanent and this is the only copy of the
   * file, so a bare button is a misclick away from destroying it. First click
   * arms; second click within the window confirms; anything else disarms.
   */
  function onDeleteClick(record: LibraryFile) {
    if (confirmDelete === record.id) {
      setConfirmDelete(null);
      void remove(record);
    } else {
      setConfirmDelete(record.id);
      // Auto-disarm so the row does not sit armed forever.
      // 8s, not 4: the first window was short enough that reading the button's
      // own warning used most of it up.
      window.setTimeout(() => setConfirmDelete((c) => (c === record.id ? null : c)), 8000);
    }
  }

  async function remove(record: LibraryFile) {
    try {
      await deleteFile(getToken, record.id);
      if (outcome?.id === record.id) setOutcome(null);
      await refresh();
    } catch (err) {
      const msg =
        err instanceof ShareApiError && err.status === 403
          ? 'Only the uploader can delete a file. The server compares the token subject, not the display name.'
          : err instanceof Error
            ? err.message
            : String(err);
      setListError(msg);
    }
  }

  const files = listing?.files ?? [];

  return (
    <div className="stage__inner stage__inner--wide">
      <header className="stage__head">
        <p className="eyebrow">Shared library</p>
        <h1 className="stage__title">Everyone holds every file. Only some can read them.</h1>
        <p className="prose">
          Anything published here is visible to every signed-in account, and any of them can
          download the sealed bytes. That is deliberate — it is the point. The server stores
          ciphertext it cannot open, and the decision about who gets plaintext is made by the key
          server, per file, every time someone presses <strong>Open</strong>.
        </p>
      </header>

      <Panel
        title="Publish a file"
        aside={
          listing
            ? `${listing.usage.files}/${listing.limits.maxFilesPerUser} of your files · ${formatBytes(listing.usage.bytes)}/${formatBytes(listing.limits.maxBytesPerUser)}`
            : `max ${formatBytes(MAX_UPLOAD_BYTES)} per file`
        }
      >
        <FileDrop
          lead={file ? 'Choose a different file' : 'Drop a file, or click to pick one'}
          hint={`Encrypted here in your browser before anything is sent — max ${formatBytes(MAX_UPLOAD_BYTES)}`}
          file={file}
          onFile={(f) => void onFile(f)}
        />
        {tooBig ? (
          <p className="notice notice--deny" style={{ marginTop: 12 }}>
            That file is {formatBytes(file.size)}; the limit is {formatBytes(MAX_UPLOAD_BYTES)}.
          </p>
        ) : null}

        {presealed ? (
          <div className="notice" style={{ marginTop: 12 }}>
            <p style={{ margin: '0 0 8px' }}>
              That is <strong>already a sealed .tdf</strong>
              {presealed.policy?.body?.dataAttributes?.length
                ? ` bound to ${presealed.policy.body.dataAttributes.map((a) => a.attribute?.split('/attr/').pop()).join(', ')}`
                : ' with no attributes'}
              . Sealing it again would double-wrap it into {file?.name}.tdf, which nobody could open in
              one step.
            </p>
            <div className="chips" role="radiogroup" aria-label="How to publish this .tdf">
              <button
                type="button"
                className="chip"
                role="radio"
                aria-checked={publishAsIs}
                onClick={() => setPublishAsIs(true)}
              >
                <span className="chip__box" aria-hidden="true" />
                Publish as-is
              </button>
              <button
                type="button"
                className="chip"
                role="radio"
                aria-checked={!publishAsIs}
                onClick={() => setPublishAsIs(false)}
              >
                <span className="chip__box" aria-hidden="true" />
                Re-seal it anyway
              </button>
            </div>
          </div>
        ) : null}

        {presealed && publishAsIs ? null : (
          <>
        <p className="eyebrow" style={{ marginTop: 18, marginBottom: 10 }}>
          Who should be able to read it
        </p>
        {values.length === 0 ? (
          <p className="notice">No attribute values available — check the Policy panel.</p>
        ) : (
          <div className="chips">
            {values.map((v) => (
              <button
                key={v.fqn}
                type="button"
                className="chip"
                aria-pressed={selected.includes(v.fqn)}
                onClick={() => toggle(v.fqn)}
                title={v.fqn}
              >
                <span className="chip__box" aria-hidden="true" />
                <span className="chip__ns">{v.attribute}/</span>
                <span>{v.label}</span>
              </button>
            ))}
          </div>
        )}
        {selected.length === 0 && values.length > 0 ? (
          <p className="notice" style={{ marginTop: 12 }}>
            With nothing selected the file carries no attributes, so any signed-in account can open
            it. Useful as a control — publish one and watch it open for everybody.
          </p>
        ) : null}
          </>
        )}

        <div className="btn-row" style={{ marginTop: 16 }}>
          <button className="btn btn--primary" disabled={!file || busy || tooBig} onClick={publish}>
            {phase === 'sealing'
              ? 'Sealing…'
              : phase === 'uploading'
                ? 'Uploading…'
                : presealed && publishAsIs
                  ? 'Publish as-is'
                  : 'Seal and publish'}
          </button>
        </div>
        {phase !== 'idle' ? (
          <Flow
            run={buildEncryptFlow({
              attributes: presealed && publishAsIs ? [] : selected,
              toLibrary: true,
              claims,
              manifest: publishManifest,
              sizeBytes: file?.size,
              error: uploadError,
              reached: phase === 'done' ? 'uploaded' : phase === 'uploading' ? 'sealed' : 'start',
            })}
            running={busy}
          />
        ) : null}
        {phase === 'done' && !uploadError ? (
          <div className="outcome outcome--granted" style={{ marginTop: 18 }}>
            <p className="outcome__flag">Published</p>
            <p className="outcome__lede">
              Sealed in your browser and stored as ciphertext the server cannot open. It now appears
              in the library below for every signed-in account — whether each can <em>read</em> it is
              decided by the key server, per file, at every open.
            </p>
          </div>
        ) : null}
        {uploadError ? (
          <p className="notice notice--deny" style={{ marginTop: 12 }}>
            {uploadError}
          </p>
        ) : null}
      </Panel>

      <Panel
        title="Library"
        aside={
          <button className="btn btn--ghost btn--small" onClick={() => void refresh()} disabled={loading}>
            {loading ? 'Reading…' : 'Refresh'}
          </button>
        }
      >
        {listError ? (
          <p className="notice notice--deny" style={{ marginBottom: 14 }}>
            {listError}
          </p>
        ) : null}

        {files.length === 0 ? (
          <div className="empty">
            <p className="empty__lead">Nothing published yet.</p>
            <p className="prose">
              Publish something above and it appears here for every account in the realm — user-a,
              user-b, anyone. They will all be able to list it and download the sealed bytes. Whether
              they can <em>read</em> it depends on the attributes you attach and on what the policy
              says about them, and that question is answered fresh at every open.
            </p>
            <p className="prose">
              The instructive first experiment: publish one file as{' '}
              <span className="material">classification/secret</span>, sign in as user-b, and try.
            </p>
          </div>
        ) : (
          <ul className="lib">
            {files.map((f) => {
              const guess = guessAccess(f, observations);
              const isOpen = outcome?.id === f.id;
              return (
                <li className="lib__row" key={f.id}>
                  <div className="lib__main">
                    <div className="lib__title">
                      <span className="lib__name">{f.filename}</span>
                      <span className={`tag ${GUESS_CLASS[guess]}`} title={GUESS_TITLE[guess]}>
                        {GUESS_LABEL[guess]}
                      </span>
                      {f.mine ? <span className="tag">yours</span> : null}
                    </div>
                    <div className="lib__meta">
                      {f.uploader} · {formatBytes(f.size)} · {formatWhen(f.uploadedAt)}
                    </div>
                    <div className="lib__attrs">
                      {f.attributes.length ? (
                        f.attributes.map((a) => (
                          <span className="tag tag--material" key={a} title={a}>
                            {a.split('/attr/').pop()}
                          </span>
                        ))
                      ) : (
                        <span className="muted">no attributes</span>
                      )}
                    </div>
                  </div>
                  <div className="lib__actions">
                    <button
                      className="btn btn--primary btn--small"
                      disabled={openingId === f.id}
                      onClick={() => void open(f)}
                    >
                      {openingId === f.id ? 'Asking…' : 'Open'}
                    </button>
                    <button className="btn btn--small" onClick={() => void fetchSealed(f)}>
                      Get .tdf
                    </button>
                    <button
                      className="btn btn--small"
                      data-testid="get-html"
                      disabled={f.size > MAX_HTML_WRAP_BYTES}
                      title={
                        f.size > MAX_HTML_WRAP_BYTES
                          ? 'Too large to wrap as HTML: base64 inflates it by a third.'
                          : 'The same sealed bytes as a self-decrypting HTML page'
                      }
                      onClick={() => void fetchSealedHtml(f)}
                    >
                      Get .html
                    </button>
                    {f.mine ? (
                      <button
                        className={`btn btn--small ${confirmDelete === f.id ? 'btn--danger' : 'btn--ghost'}`}
                        onClick={() => onDeleteClick(f)}
                        onBlur={() => setConfirmDelete((c) => (c === f.id ? null : c))}
                        title={
                          confirmDelete === f.id
                            ? 'Click again to permanently delete — this is the only copy'
                            : 'Delete this file'
                        }
                      >
                        {confirmDelete === f.id ? 'Confirm delete' : 'Delete'}
                      </button>
                    ) : null}
                  </div>

                  {(isOpen && outcome) || openingId === f.id ? (
                    <div className="lib__flow" ref={openingId === f.id ? openFlowRef : undefined}>
                      <Flow
                        run={buildDecryptFlow({
                          outcome: isOpen && outcome ? outcome.result : null,
                          running: openingId === f.id,
                          fromLibrary: true,
                          attributes: f.attributes,
                          manifest: openedManifest,
                          claims,
                          mappings: (policy?.subjectMappings ?? []).filter((m) =>
                            f.attributes.includes(m.valueFqn),
                          ),
                          rewrapCall: calls
                            .filter((c) => c.path.includes('/kas.AccessService/Rewrap'))
                            .slice(-1)[0],
                          filename: f.filename,
                        })}
                        running={openingId === f.id}
                      />
                    </div>
                  ) : null}
                  {isOpen && outcome ? <Outcome outcome={outcome.result} record={f} username={username} policy={policy} /> : null}
                </li>
              );
            })}
          </ul>
        )}

        <p className="prose" style={{ marginTop: 18 }}>
          <strong>Get .tdf</strong> always works, for every file, for everyone. Downloading is not
          access — you get the same sealed bytes the server holds, and they stay inert until a key
          server agrees to unwrap them. <strong>Get .html</strong> is the same bytes in a page that
          can read its own manifest anywhere and say plainly why it still cannot open itself there.
        </p>
        <WrapperWarning compact />
      </Panel>
    </div>
  );
}

function Outcome({
  outcome,
  record,
  username,
  policy,
}: {
  outcome: DecryptOutcome;
  record: LibraryFile;
  username: string;
  policy: PolicySnapshot | null;
}) {
  if (outcome.outcome === 'granted') {
    return (
      <div className="outcome outcome--granted lib__outcome">
        <p className="outcome__flag">Access granted</p>
        <p className="outcome__lede">
          The key server unwrapped {record.filename} for {username} —{' '}
          {formatBytes(outcome.plaintext.byteLength)} of plaintext, decrypted in this tab.
        </p>
        {outcome.text !== null ? (
          <pre className="code">{outcome.text}</pre>
        ) : (
          <p className="notice">Not UTF-8 text, so there is nothing to show inline.</p>
        )}
        <div className="btn-row" style={{ marginTop: 12 }}>
          <button
            className="btn"
            onClick={() =>
              download(outcome.plaintext, record.filename.replace(/\.tdf$/i, '') || 'payload', outcome.mimeType)
            }
          >
            <span>Download</span>{' '}
            <span className="btn__filename">{record.filename.replace(/\.tdf$/i, '') || 'payload'}</span>
          </button>
        </div>
      </div>
    );
  }

  if (outcome.kind === 'denied') {
    const mappings = (policy?.subjectMappings ?? []).filter((m) => record.attributes.includes(m.valueFqn));
    const unmapped = record.attributes.filter(
      (fqn) => !(policy?.subjectMappings ?? []).some((m) => m.valueFqn === fqn),
    );
    return (
      <div className="outcome outcome--denied lib__outcome">
        <p className="outcome__flag">Access denied</p>
        <p className="outcome__lede">
          {username} has the file. {username} cannot read it. The bytes downloaded fine — the key
          server simply refused to unwrap the key, because policy says this account is not entitled.
        </p>
        <div className="verdict">
          <div className="kv">
            <span className="kv__k">result</span>
            <span className="kv__v">
              <span className="tag tag--deny">{outcome.serviceCode ?? 'permission_denied'}</span>
            </span>
            <span className="kv__k">message</span>
            <span className="kv__v">{outcome.serviceMessage ?? outcome.sdkMessage}</span>
          </div>
          <p className="prose">
            The rewrap call itself returned <em>HTTP 200</em>. This platform carries the refusal{' '}
            <em>inside</em> the response, as a per-key result whose status is{' '}
            <span className="material">permission_denied</span> — a decision was made and answered,
            not an error.
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
                requires{' '}
                {m.conditions
                  .map((c) => `${c.selector} ${c.operator} [${c.values.join(', ')}]`)
                  .join(` ${m.booleanOperator} `)}
              </p>
            ))}
            <p className="prose" style={{ marginTop: 12 }}>
              That reads a Keycloak user attribute, not a token claim. Change it and press Open
              again — no new token, no sign-out.
            </p>
          </>
        ) : null}
        {unmapped.length ? (
          <p className="notice notice--deny" style={{ marginTop: 12 }}>
            No subject mapping grants{' '}
            {unmapped.map((f) => (
              <span className="material" key={f}>
                {f}{' '}
              </span>
            ))}
            — so <strong>no account in this realm can open this file</strong>, including whoever
            published it.
          </p>
        ) : null}
      </div>
    );
  }

  return (
    <div className="outcome outcome--fault lib__outcome">
      <p className="outcome__flag">{outcome.headline}</p>
      <p className="prose">{outcome.serviceMessage ?? outcome.sdkMessage}</p>
    </div>
  );
}
