import { Fragment, useEffect, useMemo, useRef, useState } from 'react';
import type { Lane } from '../flow';
import {
  LANE_LABEL,
  LANE_SUB,
  OBS_LABEL,
  OBS_TITLE,
  type Artifact,
  type FlowRun,
  type StepStatus,
} from '../flow';

/** Steps land this far apart, regardless of how fast the real call was. */
const STEP_MS = 420;

function prefersReducedMotion(): boolean {
  return typeof matchMedia === 'function' && matchMedia('(prefers-reduced-motion: reduce)').matches;
}

/**
 * A live sequence diagram of the protocol.
 *
 * Lanes are actors, time runs downward, and each row is one message. The point
 * is not decoration: a denial and a tamper rejection stop at visibly different
 * lanes, and everything downstream is drawn as never reached, which is the
 * clearest way to say *where* the answer came from.
 */
export function Flow({ run, running }: { run: FlowRun; running: boolean }) {
  const [tick, setTick] = useState(0);
  const [open, setOpen] = useState<string | null>(null);
  const timer = useRef<number | undefined>(undefined);

  // Restart playback whenever the shape of the run changes.
  const runKey = useMemo(() => `${run.title}:${run.steps.map((s) => s.id).join(',')}`, [run]);
  useEffect(() => {
    setTick(prefersReducedMotion() ? run.steps.length : 0);
    setOpen(null);
  }, [runKey, run.steps.length]);

  // How far we are ALLOWED to reveal. While the operation is still in flight we
  // never advance past what is actually known, so the diagram cannot claim a
  // step succeeded before it has.
  const known = run.steps.filter((s) => s.status !== 'pending').length;
  const cap = running ? Math.min(known + 1, run.steps.length) : run.steps.length;

  useEffect(() => {
    if (tick >= cap) return;
    timer.current = window.setTimeout(() => setTick((t) => t + 1), STEP_MS);
    return () => window.clearTimeout(timer.current);
  }, [tick, cap]);

  const laneIndex = new Map(run.lanes.map((l, i) => [l, i]));
  const revealed = Math.min(tick, cap);
  const complete = !running && revealed >= run.steps.length;

  return (
    <section className="fl" aria-label={`Protocol steps: ${run.title}`}>
      <header className="fl__head">
        <h3 className="fl__title">{run.title}</h3>
        <span className="fl__count">
          {Math.min(revealed, run.steps.length)} / {run.steps.length} steps
        </span>
        {!complete ? (
          <button className="btn btn--ghost btn--small" onClick={() => setTick(run.steps.length)}>
            Skip
          </button>
        ) : null}
      </header>

      <div className="fl__scroll">
        <div
          className="fl__grid"
          style={{ ['--lanes' as string]: run.lanes.length }}
        >
          {run.lanes.map((l, i) => (
            <div className="fl__lane" key={l} style={{ gridColumn: i + 1, gridRow: 1 }}>
              <span className="fl__laneName">{LANE_LABEL[l]}</span>
              <span className="fl__laneSub">{LANE_SUB[l]}</span>
            </div>
          ))}
          {run.lanes.map((l, i) => (
            <span
              className="fl__life"
              key={`life-${l}`}
              aria-hidden="true"
              // This grid has no explicit row tracks, so `2 / -1` resolves to
              // the last EXPLICIT line (line 2) and the lifeline collapses to
              // the header row. Span the implicit rows explicitly: 3 rows per
              // step (message · note · expanded detail).
              style={{ gridColumn: i + 1, gridRow: `2 / span ${run.steps.length * 3}` }}
            />
          ))}

          {run.steps.map((step, i) => {
            const shown = i < revealed;
            const status: StepStatus =
              !shown ? 'pending' : running && i >= known ? 'active' : step.status;
            const a = laneIndex.get(step.from) ?? 0;
            const b = laneIndex.get(step.to) ?? 0;
            const self = a === b;
            const lo = Math.min(a, b);
            const hi = Math.max(a, b);
            const isOpen = open === step.id;
            const expandable = !!step.artifacts?.length && shown;

            const arrowRow = 2 + i * 3;
            return (
              <Fragment key={step.id}>
                <div
                  className={[
                    'fl__row',
                    `fl__row--${status}`,
                    self ? 'fl__row--self' : a < b ? 'fl__row--fwd' : 'fl__row--back',
                    shown ? 'is-shown' : '',
                  ].join(' ')}
                  style={{ gridColumn: `${lo + 1} / ${hi + 2}`, gridRow: arrowRow }}
                >
                  <button
                    type="button"
                    className="fl__step"
                    disabled={!expandable}
                    aria-expanded={expandable ? isOpen : undefined}
                    onClick={() => expandable && setOpen(isOpen ? null : step.id)}
                  >
                    <span className="fl__n">{i + 1}</span>
                    <span className="fl__label">{step.label}</span>
                    <span className={`fl__obs fl__obs--${step.obs}`} title={OBS_TITLE[step.obs]}>
                      {obsLabel(step)}
                    </span>
                    {expandable ? (
                      <span className="fl__more" aria-hidden="true">
                        {isOpen ? 'hide' : 'show'}
                      </span>
                    ) : null}
                  </button>
                  <span className="fl__wire" aria-hidden="true" />
                </div>

                {/* The note is a FULL-WIDTH grid item, not a child of the narrow
                    message cell: inside the row it laid out at the wide diagram
                    width and clipped mid-sentence on a phone. Full width + a
                    mobile max-width clamp keeps it readable while only the lane
                    boxes and wires scroll sideways. */}
                {shown && step.detail ? (
                  <p className={`fl__note fl__note--${status}`} style={{ gridRow: arrowRow + 1 }}>
                    {step.detail}
                  </p>
                ) : null}

                {shown && isOpen ? (
                  <div className="fl__detail" style={{ gridRow: arrowRow + 2 }}>
                    {step.artifacts?.map((art, k) => (
                      <ArtifactView art={art} key={k} />
                    ))}
                  </div>
                ) : null}
              </Fragment>
            );
          })}
        </div>
      </div>
    </section>
  );
}

/**
 * Name the badge after the actor that actually does the work. A step Keycloak
 * performs on itself must not read "inside the platform" — that is a different
 * service, and being sloppy here undermines the point of having badges at all.
 */
function obsLabel(step: { obs: string; from: Lane; to: Lane }): string {
  if (step.obs !== 'server') return OBS_LABEL[step.obs as 'observed' | 'sdk'];
  return step.from === step.to ? `inside ${LANE_LABEL[step.from]}` : 'server-side';
}

function ArtifactView({ art }: { art: Artifact }) {
  if (art.kind === 'kv') {
    return (
      <div className="fl__art">
        <p className="fl__artLabel">{art.label}</p>
        <div className="kv">
          {art.rows.flatMap(([k, v], i) => [
            <span className="kv__k" key={`k-${i}`}>
              {k}
            </span>,
            <span className="kv__v" key={`v-${i}`}>
              {v}
            </span>,
          ])}
        </div>
      </div>
    );
  }
  if (art.kind === 'json') {
    return (
      <div className="fl__art">
        <p className="fl__artLabel">{art.label}</p>
        <pre className="code">{JSON.stringify(art.value, null, 2)}</pre>
      </div>
    );
  }
  if (art.kind === 'text') {
    return (
      <div className="fl__art">
        <p className="fl__artLabel">{art.label}</p>
        <pre className="code">{art.value}</pre>
      </div>
    );
  }
  // compare — the money shot on a denial
  return (
    <div className={`fl__art fl__cmp${art.failed ? ' fl__cmp--failed' : ''}`}>
      <p className="fl__artLabel">{art.label}</p>
      <div className="fl__cmpGrid">
        <div className="fl__side">
          <p className="fl__sideHead">This file requires</p>
          {art.required.length ? (
            art.required.map((r) => (
              <span className={`tag tag--material${art.failed ? ' tag--failing' : ''}`} key={r}>
                {r}
              </span>
            ))
          ) : (
            <span className="muted">no attributes — anyone signed in can open it</span>
          )}
        </div>
        <div className="fl__vs" aria-hidden="true">
          vs
        </div>
        <div className="fl__side">
          <p className="fl__sideHead">You hold</p>
          <p className="fl__unknown">{art.yoursNote}</p>
        </div>
      </div>
      {art.satisfiedBy.length ? (
        <>
          <p className="fl__artLabel" style={{ marginTop: 12 }}>
            {art.failed ? 'What would have satisfied it' : 'What satisfied it'}
          </p>
          {art.satisfiedBy.map((s) => (
            <pre className="code" key={s}>
              {s}
            </pre>
          ))}
        </>
      ) : (
        <p className="fl__unknown" style={{ marginTop: 10 }}>
          No subject mapping grants these values, so no account in this realm can currently satisfy
          them.
        </p>
      )}
    </div>
  );
}
