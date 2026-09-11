import { Blob, KV } from './bits';
import { formatBytes, policyAttributes, type TdfFile } from '../manifest';
import { useState } from 'react';

/**
 * The envelope: a cross-section of the loaded .tdf.
 *
 * This is the learning artifact. Everything here is readable by anyone holding
 * the file — the key server's address, which key wrapped the DEK, and the
 * policy the payload is bound to. Only the wrapped key itself is opaque, and
 * only the KAS can open it.
 */
export function Envelope({ file }: { file: TdfFile | null }) {
  const [rawOpen, setRawOpen] = useState(false);

  if (!file) {
    return (
      <>
        <p className="eyebrow">The envelope</p>
        <div className="envelope__empty">
          Nothing loaded yet.
          <br />
          <br />
          Encrypt a file, drop an existing <span className="material">.tdf</span> on the Decrypt
          panel, or click a sealed cell on the Database panel, and its manifest is dissected here —
          no key required.
        </div>
      </>
    );
  }

  const m = file.manifest;
  const enc = m.encryptionInformation;
  const kaos = enc?.keyAccess ?? [];
  const integrity = enc?.integrityInformation;
  const attrs = policyAttributes(file.policy);
  const payloadEntry = file.entries.find((e) => e.name.endsWith('payload'));
  const manifestEntry = file.entries.find((e) => e.name.endsWith('manifest.json'));

  return (
    <>
      <p className="eyebrow">The envelope</p>
      <div className="spine">
        <div className="node">
          <div className="node__label">
            <span className="material">{file.name}</span>
            <span className="node__size">{formatBytes(file.bytes.byteLength)}</span>
          </div>
          <p className="node__note">
            A .tdf is an ordinary zip archive. Rename it and any unzip tool will open it.
          </p>
          <div className="node__body kv">
            <KV k="entries">{file.entries.map((e) => e.name).join('  ·  ')}</KV>
            <KV k="stored">
              {file.entries.every((e) => e.compressionMethod === 0)
                ? 'uncompressed (method 0), ZIP64'
                : 'mixed compression'}
            </KV>
          </div>
        </div>

        <div className="node">
          <div className="node__label">
            <span>0.manifest.json</span>
            {manifestEntry ? (
              <span className="node__size">{formatBytes(manifestEntry.uncompressedSize)}</span>
            ) : null}
            <span className="node__size">schema {m.schemaVersion ?? '—'}</span>
          </div>
          <p className="node__note">
            Plaintext. It says who can be asked for the key, never what the key is.
          </p>
        </div>

        <div className="node">
          <div className="node__label">
            <span>0.payload</span>
            {payloadEntry ? (
              <span className="node__size">{formatBytes(payloadEntry.uncompressedSize)}</span>
            ) : null}
          </div>
          <div className="node__body kv">
            <KV k="mime">{m.payload?.mimeType ?? '—'}</KV>
            <KV k="encrypted">{String(m.payload?.isEncrypted ?? true)}</KV>
            <KV k="protocol">{m.payload?.protocol ?? '—'}</KV>
          </div>
        </div>

        <div className="node">
          <div className="node__label">
            <span>method</span>
            <span className="node__size">{enc?.type ?? 'split'}</span>
          </div>
          <div className="node__body kv">
            <KV k="algorithm">
              <span className="material">{enc?.method?.algorithm ?? '—'}</span>
            </KV>
            <KV k="streamable">{String(enc?.method?.isStreamable ?? false)}</KV>
          </div>
        </div>

        {kaos.map((kao, i) => (
          <div className="node node--material" key={`${kao.kid ?? 'kao'}-${i}`}>
            <div className="node__label">
              <span className="material">keyAccess[{i}]</span>
              <span className="node__size">{kao.type ?? 'wrapped'}</span>
            </div>
            <p className="node__note">
              The data encryption key, encrypted to this key server's public key. Opening the file
              means asking that server to unwrap it — and it only will if policy says so.
            </p>
            <div className="node__body kv">
              <KV k="kas">{kao.url ?? '—'}</KV>
              <KV k="kid">
                <span className="material">{kao.kid || '—'}</span>
              </KV>
              {kao.sid ? <KV k="split id">{kao.sid}</KV> : null}
              <KV k="protocol">{kao.protocol ?? '—'}</KV>
              <KV k="wrapped key">
                <Blob value={kao.wrappedKey ?? ''} label="wrapped key" />
              </KV>
              <KV k="binding">
                {typeof kao.policyBinding === 'string' ? (
                  <Blob value={kao.policyBinding} label="policy binding" />
                ) : (
                  <>
                    <span className="tag tag--material">{kao.policyBinding?.alg ?? 'HS256'}</span>
                    <Blob value={kao.policyBinding?.hash ?? ''} label="policy binding hash" />
                  </>
                )}
              </KV>
            </div>
            <p className="node__note">
              The binding is an HMAC over the policy, keyed with the DEK. Edit the policy to give
              yourself an attribute and the binding stops matching — the swap is detectable, so the
              policy cannot be rewritten by whoever holds the file.
            </p>
          </div>
        ))}

        <div className="node node--material">
          <div className="node__label">
            <span className="material">policy</span>
            <span className="node__size">base64</span>
          </div>
          <div className="node__body">
            <Blob value={enc?.policy ?? ''} label="encoded policy" />
            <div className="decode">
              <span className="decode__arrow">▼ decoded</span>
              {file.policy ? (
                <div className="kv">
                  <KV k="uuid">{file.policy.uuid ?? '—'}</KV>
                  <KV k="dataAttributes">
                    {attrs.length ? (
                      attrs.map((a) => (
                        <span className="tag tag--material" key={a}>
                          {a}
                        </span>
                      ))
                    ) : (
                      <span className="muted">none — this file is bound to no attribute</span>
                    )}
                  </KV>
                  <KV k="dissem">
                    {file.policy.body?.dissem?.length ? (
                      file.policy.body.dissem.join(', ')
                    ) : (
                      <span className="muted">empty</span>
                    )}
                  </KV>
                </div>
              ) : (
                <span className="muted">could not decode: {file.policyError}</span>
              )}
            </div>
            <p className="node__note">
              These attribute values are the whole question. On decrypt the key server asks the
              policy service whether your entitlements satisfy them.
            </p>
          </div>
        </div>

        {integrity ? (
          <div className="node">
            <div className="node__label">
              <span>integrity</span>
              <span className="node__size">{integrity.segments?.length ?? 0} segments</span>
            </div>
            <div className="node__body kv">
              <KV k="root alg">{integrity.rootSignature?.alg ?? '—'}</KV>
              <KV k="root sig">
                <Blob value={integrity.rootSignature?.sig ?? ''} label="root signature" />
              </KV>
              <KV k="segment alg">{integrity.segmentHashAlg ?? '—'}</KV>
              <KV k="segment size">
                {integrity.segmentSizeDefault
                  ? formatBytes(integrity.segmentSizeDefault)
                  : '—'}
              </KV>
            </div>
          </div>
        ) : null}

        <div className="node">
          <div className="node__label">
            <span>assertions</span>
            <span className="node__size">{m.assertions?.length ?? 0}</span>
          </div>
          <p className="node__note">
            Signed statements bound to the payload. This lab does not add any.
          </p>
        </div>
      </div>

      <hr className="hr" />
      <button className="btn btn--ghost btn--small" onClick={() => setRawOpen((v) => !v)}>
        {rawOpen ? 'Hide raw manifest' : 'Show raw manifest'}
      </button>
      {rawOpen ? (
        <pre className="code" style={{ marginTop: 12 }}>
          {JSON.stringify(JSON.parse(file.manifestJson), null, 2)}
        </pre>
      ) : null}
    </>
  );
}
