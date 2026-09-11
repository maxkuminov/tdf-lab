import { platformConnect } from '@opentdf/sdk/platform';

/**
 * Every call this console makes to the platform - policy reads, the attribute
 * lookup during encrypt, and the KAS rewrap - is a Connect-RPC POST. This
 * interceptor records each one so the console can show what actually went over
 * the wire.
 *
 * It also solves a real problem: the SDK maps a rewrap 403 onto a
 * `PermissionDeniedError` whose message is the fixed string "forbidden", and
 * it does not attach the original error as a cause. The platform's own words -
 * the reason your entitlements did not satisfy the policy - are discarded
 * before any caller can see them. Capturing the ConnectError here, one layer
 * out, is the only place they still exist.
 *
 * `platformConnect` is the SDK's own re-export of `@connectrpc/connect`, so
 * `ConnectError.from` is testing against the same class the SDK threw.
 */

export type RpcCall = {
  id: number;
  /** e.g. `/kas.AccessService/Rewrap` */
  path: string;
  startedAt: number;
  durationMs: number;
  ok: boolean;
  /** Connect status name, e.g. `permission_denied`. */
  code?: string;
  /** The service's own message, before the SDK rewrites it. */
  rawMessage?: string;
};

/**
 * A rewrap refusal does NOT arrive as a transport error on platform v0.25.1.
 * The KAS answers HTTP 200 with a per-key-access-object result whose `result`
 * oneof is set to `error`, carrying the reason as a plain string; only then
 * does the SDK turn it into a thrown `PermissionDeniedError`. An interceptor
 * that only watches for thrown errors therefore records the densest moment in
 * the whole lab as a successful call. Observed in the lab on
 * 2026-08-27.
 *
 * So: unwrap the response too, and report the KAS's own words.
 */
type Rewrapish = {
  responses?: {
    policyId?: string;
    results?: { keyAccessObjectId?: string; status?: string; result?: { case?: string; value?: unknown } }[];
  }[];
};

/**
 * The embedded refusal reads like `invalid_argument: request error\nrpc error:
 * code = InvalidArgument desc = bad request`. Keep the leading Connect status
 * token so callers can tell a policy denial from a rejected request - the
 * difference between "you are not entitled" and "this file was altered".
 */
function kasStatusOf(refusal: string): string {
  const m = /\b(permission_denied|invalid_argument|unauthenticated|not_found|internal|unavailable|failed_precondition)\b/i.exec(refusal);
  return m ? m[1].toLowerCase() : 'refused';
}

function extractKasRefusal(message: unknown): string | undefined {
  const m = message as Rewrapish | undefined;
  if (!m?.responses) return undefined;
  const reasons: string[] = [];
  for (const resp of m.responses) {
    for (const r of resp.results ?? []) {
      if (r.result?.case === 'error' && typeof r.result.value === 'string') {
        reasons.push(`${r.keyAccessObjectId ?? 'kao'}: ${r.result.value}`);
      }
    }
  }
  return reasons.length ? reasons.join(' · ') : undefined;
}

const MAX_CALLS = 60;
let nextId = 1;
let calls: RpcCall[] = [];
const listeners = new Set<(calls: RpcCall[]) => void>();

function publish() {
  const snapshot = calls;
  for (const l of listeners) l(snapshot);
}

export function subscribeToRpc(fn: (calls: RpcCall[]) => void): () => void {
  listeners.add(fn);
  fn(calls);
  return () => listeners.delete(fn);
}

export function getRpcCalls(): RpcCall[] {
  return calls;
}

export function clearRpcCalls() {
  calls = [];
  publish();
}

/**
 * A cursor for scoping later lookups to ONE operation.
 *
 * The trace is global and lives for the whole session, so an unscoped
 * "most recent failure" search reaches back into earlier operations. Decrypt a
 * denied file, then decrypt a tampered one whose rewrap succeeds but whose
 * payload fails its integrity check, and the second failure would be explained
 * with the FIRST one's rewrap denial - reporting "access denied, the file is
 * intact" about a file that is not intact. Take a cursor before an operation
 * and pass it to `lastRpcFailure`.
 */
export function rpcCursor(): number {
  return nextId;
}

/**
 * The most recent failure, which is what the deny panel quotes.
 *
 * @param path  optional substring of the RPC path to match
 * @param afterId  only consider calls started at or after this cursor. ALWAYS
 *   pass one from an operation; omitting it searches the whole session.
 */
export function lastRpcFailure(path?: string, afterId = 0): RpcCall | undefined {
  for (let i = calls.length - 1; i >= 0; i--) {
    const c = calls[i];
    if (c.id < afterId) return undefined; // ids only increase; nothing older can match
    if (!c.ok && (!path || c.path.includes(path))) return c;
  }
  return undefined;
}

function record(call: RpcCall) {
  calls = [...calls, call].slice(-MAX_CALLS);
  publish();
}

function pathOf(url: string): string {
  try {
    return new URL(url).pathname;
  } catch {
    return url;
  }
}

export const traceInterceptor: platformConnect.Interceptor = (next) => async (req) => {
  const id = nextId++;
  const startedAt = Date.now();
  const t0 = performance.now();
  try {
    const res = await next(req);
    const refusal = req.stream ? undefined : extractKasRefusal((res as { message?: unknown }).message);
    record({
      id,
      path: pathOf(req.url),
      startedAt,
      durationMs: performance.now() - t0,
      ok: !refusal,
      code: refusal ? kasStatusOf(refusal) : undefined,
      rawMessage: refusal,
    });
    return res;
  } catch (err) {
    const ce = platformConnect.ConnectError.from(err);
    record({
      id,
      path: pathOf(req.url),
      startedAt,
      durationMs: performance.now() - t0,
      ok: false,
      code: platformConnect.Code[ce.code]
        ? String(platformConnect.Code[ce.code]).replace(/([a-z])([A-Z])/g, '$1_$2').toLowerCase()
        : String(ce.code),
      rawMessage: ce.rawMessage || ce.message,
    });
    throw err;
  }
};
