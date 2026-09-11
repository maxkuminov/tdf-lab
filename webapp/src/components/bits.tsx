import { useCallback, useRef, useState, type ReactNode } from 'react';

export function Panel({
  title,
  aside,
  children,
}: {
  title: string;
  aside?: ReactNode;
  children: ReactNode;
}) {
  return (
    <section className="panel">
      <header className="panel__head">
        <h2 className="panel__title">{title}</h2>
        {aside ? <span className="panel__aside">{aside}</span> : null}
      </header>
      <div className="panel__body">{children}</div>
    </section>
  );
}

export function KV({ k, children }: { k: string; children: ReactNode }) {
  return (
    <>
      <span className="kv__k">{k}</span>
      <span className="kv__v">{children}</span>
    </>
  );
}

/** Base64 and hashes are long; show four lines and let the reader open them. */
export function Blob({ value, label }: { value: string; label?: string }) {
  const [open, setOpen] = useState(false);
  if (!value) return <span className="muted">—</span>;
  return (
    <button
      type="button"
      className={`blob${open ? ' blob--open' : ''}`}
      onClick={() => setOpen((o) => !o)}
      aria-expanded={open}
      title={open ? 'Collapse' : `Show all ${value.length} characters`}
      aria-label={label ? `${label}, ${value.length} characters` : undefined}
    >
      {value}
    </button>
  );
}

export function FileDrop({
  lead,
  hint,
  accept,
  file,
  onFile,
}: {
  lead: string;
  hint: string;
  accept?: string;
  file: File | null;
  onFile: (file: File) => void;
}) {
  const [over, setOver] = useState(false);
  const input = useRef<HTMLInputElement>(null);

  const take = useCallback(
    (list: FileList | null) => {
      const f = list?.[0];
      if (f) onFile(f);
    },
    [onFile],
  );

  return (
    <>
      <button
        type="button"
        className={`drop${over ? ' drop--over' : ''}`}
        onClick={() => input.current?.click()}
        onDragOver={(e) => {
          e.preventDefault();
          setOver(true);
        }}
        onDragLeave={() => setOver(false)}
        onDrop={(e) => {
          e.preventDefault();
          setOver(false);
          take(e.dataTransfer.files);
        }}
      >
        <span className="drop__lead">{lead}</span>
        <span className="drop__hint">{hint}</span>
        {file ? <span className="drop__file">{file.name}</span> : null}
      </button>
      <input
        ref={input}
        type="file"
        accept={accept}
        hidden
        onChange={(e) => {
          take(e.target.files);
          e.target.value = '';
        }}
      />
    </>
  );
}

export type StepState = 'pending' | 'active' | 'done' | 'skipped';

export function Steps({ steps }: { steps: { label: string; state: StepState }[] }) {
  return (
    <ul className="steps">
      {steps.map((s) => (
        <li key={s.label} className={`step step--${s.state}`}>
          <span className="step__mark" aria-hidden="true">
            {s.state === 'done' ? '■' : s.state === 'active' ? '▸' : s.state === 'skipped' ? '×' : '□'}
          </span>
          <span>
            {s.label}
            {s.state === 'skipped' ? <span className="step__skipped"> — not reached</span> : null}
          </span>
        </li>
      ))}
    </ul>
  );
}

/**
 * The one thing this feature has to say out loud, wherever it is offered.
 *
 * An HTML wrapper is convenient because a browser opens it, and that is
 * precisely why it is a phishing vector: a .html attachment runs code the
 * moment it is opened, and nothing about the file tells the recipient whether
 * that code only reads itself. This lab already teaches "possession is not
 * access"; this is the other half of the lesson, and the console should not
 * hand out an executable document while being coy about it.
 */
export function WrapperWarning({ compact }: { compact?: boolean }) {
  return (
    <p className="notice" style={{ marginTop: compact ? 10 : 14 }}>
      <strong>An HTML wrapper is an executable document.</strong> The sealed bytes inside it are
      inert, but the page around them is code that runs when it is opened — and a recipient cannot
      tell a wrapper like this one from a page written to steal something. Send{' '}
      <span className="material">.tdf</span> to people who have this console; send{' '}
      <span className="material">.html</span> when the convenience is worth explaining. Either way,
      treat an .html arriving from a stranger the way you would treat any other executable.
    </p>
  );
}
