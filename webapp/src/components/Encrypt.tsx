import { useMemo, useState } from 'react';
import { FileDrop, Panel, WrapperWarning } from './bits';
import { Flow } from './Flow';
import { buildEncryptFlow } from '../flow';
import { allValues, type PolicySnapshot } from '../policy';
import { MAX_UPLOAD_BYTES } from '../config';
import { download, encryptToTdf, type LabClients } from '../tdf';
import { buildSealedHtml, sealedHtmlName, MAX_HTML_WRAP_BYTES } from '../wrapper/html';
import { formatBytes, openTdfFile, type TdfFile, type TdfManifest } from '../manifest';

/**
 * Phases of one encrypt run, advanced by the operation itself.
 *
 * An earlier version inferred progress purely by watching the RPC trace for
 * `/kas.AccessService/PublicKey`. The SDK fetches that key through its own
 * internal client, so the call never reaches this app's interceptor and the
 * step sat "in progress" forever, including long after the file was written.
 * Only the policy lookup is genuinely observable in the trace; everything else
 * is now driven by where `run()` actually is.
 */
type Phase = 'idle' | 'sealing' | 'inspecting' | 'done';

export function Encrypt({
  clients,
  policy,
  claims,
  onLoaded,
  onGoToDecrypt,
}: {
  clients: LabClients;
  policy: PolicySnapshot | null;
  claims: Record<string, unknown> | null;
  onLoaded: (file: TdfFile) => void;
  onGoToDecrypt: () => void;
}) {
  const [file, setFile] = useState<File | null>(null);
  const [selected, setSelected] = useState<string[]>([]);
  const [phase, setPhase] = useState<Phase>('idle');
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<{ name: string; size: number; bytes: Uint8Array } | null>(null);
  const [manifest, setManifest] = useState<TdfManifest | null>(null);
  const [wrapError, setWrapError] = useState<string | null>(null);

  const values = useMemo(() => allValues(policy), [policy]);
  const tooBig = !!file && file.size > MAX_UPLOAD_BYTES;
  const busy = phase === 'sealing' || phase === 'inspecting';

  function toggle(fqn: string) {
    setSelected((s) => (s.includes(fqn) ? s.filter((v) => v !== fqn) : [...s, fqn]));
  }

  /**
   * Emits the sealed file as a single self-contained HTML page (section 10l).
   * The bytes are byte-identical to the .tdf: the wrapper carries them as
   * base64 and adds a reader, and adds no authority of any kind.
   */
  function downloadHtml() {
    if (!result) return;
    setWrapError(null);
    try {
      const html = buildSealedHtml({ tdf: result.bytes, filename: result.name });
      download(new TextEncoder().encode(html), sealedHtmlName(result.name), 'text/html;charset=utf-8');
    } catch (err) {
      setWrapError(err instanceof Error ? err.message : String(err));
    }
  }

  async function run() {
    if (!file) return;
    setError(null);
    setWrapError(null);
    setResult(null);
    setPhase('sealing');
    try {
      const out = await encryptToTdf(clients, file, selected);
      setResult({ name: out.filename, size: out.bytes.byteLength, bytes: out.bytes });
      setPhase('inspecting');
      const parsed = await openTdfFile(out.bytes, out.filename);
      setManifest(parsed.manifest);
      onLoaded(parsed);
      setPhase('done');
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
      setPhase('idle');
    }
  }

  return (
    <div className="stage__inner">
      <header className="stage__head">
        <p className="eyebrow">Step 01 — encrypt</p>
        <h1 className="stage__title">Wrap a file to an attribute</h1>
        <p className="prose">
          The browser generates a data encryption key, encrypts your file with it, then encrypts
          that key to the lab's key server. The attribute values you pick are written into the
          policy and bound to the key with an HMAC. Nothing leaves this page except a request for
          the key server's public key.
        </p>
      </header>

      <Panel title="Payload" aside={file ? formatBytes(file.size) : `max ${formatBytes(MAX_UPLOAD_BYTES)}`}>
        <FileDrop
          lead={file ? 'Choose a different file' : 'Drop a file, or click to pick one'}
          hint="Small text files make the clearest demonstration"
          file={file}
          onFile={(f) => {
            setFile(f);
            setResult(null);
            setError(null);
            setPhase('idle');
          }}
        />
        {tooBig ? (
          <p className="notice notice--deny" style={{ marginTop: 12 }}>
            That file is {formatBytes(file.size)}. This console caps payloads at{' '}
            {formatBytes(MAX_UPLOAD_BYTES)} so the whole operation stays comfortably in browser
            memory. Pick something smaller.
          </p>
        ) : null}
      </Panel>

      <Panel title="Policy attributes" aside={`${selected.length} selected`}>
        {values.length === 0 ? (
          <p className="notice">
            No attribute values came back from the policy service. Either the lab has no policy
            seeded yet, or your token cannot read it — check the Policy tab.
          </p>
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
          <p className="notice" style={{ marginTop: 14 }}>
            With no attribute selected the policy carries no dataAttributes, so the key server has
            nothing to test and any authenticated user can open the file. That is a legitimate TDF —
            and a useful control case.
          </p>
        ) : null}
      </Panel>

      <div className="btn-row">
        <button className="btn btn--primary" disabled={!file || busy || tooBig} onClick={run}>
          {busy ? 'Encrypting…' : 'Encrypt'}
        </button>
        {result ? (
          <button
            className="btn"
            onClick={() => download(result.bytes, result.name, 'application/tdf')}
          >
            {/* the filename must not be uppercased by the button's transform */}
            <span>Download</span> <span className="btn__filename">{result.name}</span>
          </button>
        ) : null}
        {result ? (
          <button
            className="btn"
            data-testid="wrap-html"
            disabled={result.bytes.byteLength > MAX_HTML_WRAP_BYTES}
            title={
              result.bytes.byteLength > MAX_HTML_WRAP_BYTES
                ? `Too large to wrap: base64 inflates the file by a third, so this console caps HTML wrapping at ${formatBytes(MAX_HTML_WRAP_BYTES)}.`
                : 'A single self-contained .html carrying these exact bytes plus a reader'
            }
            onClick={downloadHtml}
          >
            <span>Wrap as</span> <span className="btn__filename">{sealedHtmlName(result.name)}</span>
          </button>
        ) : null}
      </div>
      {wrapError ? (
        <p className="notice notice--deny" style={{ marginTop: 12 }}>
          {wrapError}
        </p>
      ) : null}
      {/* Adjacent to the button that produces the thing being warned about. The
          same warning used to live only in the result block far below the flow
          diagram, which meant scrolling past ~1100px of sequence diagram to
          find out what you had just downloaded. */}
      {result ? <WrapperWarning compact /> : null}

      {phase !== 'idle' || result ? (
        <Flow
          run={buildEncryptFlow({
            attributes: selected,
            toLibrary: false,
            claims,
            manifest,
            sizeBytes: result?.size,
            error,
            reached: phase === 'done' || result ? 'sealed' : 'start',
          })}
          running={busy}
        />
      ) : null}

      {error ? (
        <div className="outcome outcome--fault" style={{ marginTop: 18 }}>
          <p className="outcome__flag">Encrypt failed</p>
          <p className="prose">{error}</p>
        </div>
      ) : null}

      {result ? (
        <div className="outcome outcome--granted" style={{ marginTop: 18 }}>
          <p className="outcome__flag">Sealed</p>
          <p className="outcome__lede">
            {result.name} — {formatBytes(result.size)}. Its manifest is dissected in the envelope
            panel, and it is already loaded — open it in Decrypt to see whether you can read your own
            file.
          </p>
          <div className="btn-row" style={{ marginTop: 14 }}>
            <button className="btn btn--primary" onClick={onGoToDecrypt}>
              Open in Decrypt
            </button>
          </div>
          <hr className="hr" />
          <p className="eyebrow">Wrap as HTML</p>
          <p className="prose">
            The same sealed bytes in a page that can read its own manifest anywhere — offline, from
            an email attachment, from a USB stick — and explain why it still cannot open itself
            there. Served from this console's own origin it goes further and decrypts in place.
          </p>
          <div className="btn-row" style={{ marginTop: 14 }}>
            <button
              className="btn"
              data-testid="wrap-html-2"
              disabled={result.bytes.byteLength > MAX_HTML_WRAP_BYTES}
              onClick={downloadHtml}
            >
              <span>Wrap as</span>{' '}
              <span className="btn__filename">{sealedHtmlName(result.name)}</span>
            </button>
          </div>
        </div>
      ) : null}
    </div>
  );
}
