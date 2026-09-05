// useParserDrift — TanStack-Query hook for `GET /v1/audit/parser-drift`
// (spec 012 S4, plan §10 "parser drift is a product surface").
//
// One row per (api_format, event_type) an LLM-proxy parser could not
// classify, with a keys-only sample, first/last seen and a count, plus
// the node's `new_since_boot` counter (mirrors `/readyz`'s `parser_drift`).
// The Dashboard mounts `ParserDriftPanel`, which renders nothing while the
// list is empty, so this refreshes on a slow cadence: drift is rare and a
// row only ever grows its count.

import { useQuery, type UseQueryResult } from "@tanstack/react-query";

import { api } from "~/lib/api";
import { apiPaths } from "~/lib/apiPaths";
import type { ParserDriftListResponse } from "~/lib/types";

export type ParserDriftEvent = ParserDriftListResponse["events"][number];

export const PARSER_DRIFT_QUERY_KEY = ["audit", "parser_drift"] as const;

export function useParserDrift(): UseQueryResult<ParserDriftListResponse, Error> {
  return useQuery<ParserDriftListResponse, Error>({
    queryKey: PARSER_DRIFT_QUERY_KEY,
    queryFn: () => api.get<ParserDriftListResponse>(apiPaths.audit.parserDrift),
    staleTime: 60_000,
    refetchInterval: 60_000,
    retry: false,
  });
}
