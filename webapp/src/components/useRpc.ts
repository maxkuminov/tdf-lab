import { useEffect, useState } from 'react';
import { getRpcCalls, subscribeToRpc, type RpcCall } from '../rpc';

export function useRpcCalls(): RpcCall[] {
  const [calls, setCalls] = useState<RpcCall[]>(getRpcCalls);
  useEffect(() => subscribeToRpc(setCalls), []);
  return calls;
}

/** True once a call whose path contains `needle` has completed since `since`. */
export function sawCall(calls: RpcCall[], needle: string, since: number): boolean {
  return calls.some((c) => c.startedAt >= since && c.path.includes(needle));
}
