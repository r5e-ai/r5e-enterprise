// Live-tail WebSocket client class (T067 — Phase 3 US1).
//
// Per `contracts/live_tail_transport.md` + `contracts/frontend_architecture.md`
// §"Live-tail integration":
//   - Connects to `/admin/live-tail` (Session Cookie auth — no bearer).
//   - Sends `set_filter` control frames when the SPA's filter changes.
//   - Reconnects with `?last_seen_run_id=` query param after disconnect,
//     using exponential backoff capped at 5 seconds.
//   - Forwards typed `attestation`, `backfill_summary`, `error`, `ping` frames
//     to subscribers. Replies to server `ping` with `pong` automatically.
//   - Closes cleanly on `close()` (lifecycle cleanup from React useEffect).
//
// This module is intentionally framework-free so it can be exercised in
// vitest without React. The hook in `~/hooks/useLiveTail.ts` is the React
// adapter that wires this client into TanStack Query's cache.

/* eslint-disable @typescript-eslint/no-explicit-any */

/** Slim "row shape" frame the dashboard table consumes. */
export interface AttestationFrame {
  type: "attestation";
  run_id: string;
  tenant_id: string;
  session_id: string | null;
  event_kind: string;
  policy_decision: "allow" | "deny";
  principal_subject: string;
  committed_at: string;
  summary: string;
  verification_level: string;
}

export interface BackfillSummaryFrame {
  type: "backfill_summary";
  from_run_id: string;
  to_run_id: string;
  delivered_count: number;
  truncated: boolean;
}

export interface FilterAckFrame {
  type: "filter_acknowledged";
  filter: ReceiptFilter;
  applied_at: string;
}

export interface ErrorFrame {
  type: "error";
  code: string;
  message: string;
}

export interface PingFrame {
  type: "ping";
  ts: string;
}

export type ServerFrame =
  | AttestationFrame
  | BackfillSummaryFrame
  | FilterAckFrame
  | ErrorFrame
  | PingFrame;

/** Filter shape per `live_tail_transport.md` §"Client → Server control frames". */
export interface ReceiptFilter {
  event_kind?: string[];
  policy_decision?: "allow" | "deny" | "any";
  principal_subject?: string;
  tool_name?: string;
  since?: string;
}

type Listener<F extends ServerFrame> = (frame: F) => void;

interface Listeners {
  attestation: Set<Listener<AttestationFrame>>;
  backfill_summary: Set<Listener<BackfillSummaryFrame>>;
  filter_acknowledged: Set<Listener<FilterAckFrame>>;
  error: Set<Listener<ErrorFrame>>;
  open: Set<() => void>;
  close: Set<(ev: CloseEvent) => void>;
}

const RECONNECT_BACKOFF_MS = [250, 500, 1000, 2000, 5000] as const;

/**
 * Construct the upgrade URL. We use `wss://` when the page is served over
 * https, `ws://` otherwise. The origin is always same-origin (the SPA is
 * served under `/admin/*` by the same Gateway that hosts `/admin/live-tail`).
 */
function buildUrl(path: string, params: Record<string, string>): string {
  const proto = window.location.protocol === "https:" ? "wss:" : "ws:";
  const url = new URL(`${proto}//${window.location.host}${path}`);
  for (const [key, value] of Object.entries(params)) {
    if (value !== undefined && value !== null && value !== "") {
      url.searchParams.set(key, value);
    }
  }
  return url.toString();
}

export class LiveTailClient {
  private ws: WebSocket | null = null;
  private filter: ReceiptFilter;
  private path: string;
  private lastSeenRunId: string | null = null;
  private reconnectAttempt = 0;
  private reconnectTimer: number | null = null;
  private closedByCaller = false;
  private listeners: Listeners = {
    attestation: new Set(),
    backfill_summary: new Set(),
    filter_acknowledged: new Set(),
    error: new Set(),
    open: new Set(),
    close: new Set(),
  };

  constructor(path: string, filter: ReceiptFilter) {
    this.path = path;
    this.filter = filter;
  }

  open(): void {
    this.closedByCaller = false;
    this.connect();
  }

  close(): void {
    this.closedByCaller = true;
    if (this.reconnectTimer !== null) {
      window.clearTimeout(this.reconnectTimer);
      this.reconnectTimer = null;
    }
    if (this.ws) {
      this.ws.close(1000, "client_close");
      this.ws = null;
    }
  }

  /** Send a `set_filter` control frame; updates the cached filter. */
  setFilter(filter: ReceiptFilter): void {
    this.filter = filter;
    if (this.ws && this.ws.readyState === WebSocket.OPEN) {
      this.ws.send(JSON.stringify({ type: "set_filter", filter }));
    }
    // If the socket is not open the filter will be passed via the next
    // upgrade URL (we re-encode `last_seen_run_id` + filter on reconnect).
  }

  on(event: "attestation", cb: Listener<AttestationFrame>): void;
  on(event: "backfill_summary", cb: Listener<BackfillSummaryFrame>): void;
  on(event: "filter_acknowledged", cb: Listener<FilterAckFrame>): void;
  on(event: "error", cb: Listener<ErrorFrame>): void;
  on(event: "open", cb: () => void): void;
  on(event: "close", cb: (ev: CloseEvent) => void): void;
  on(event: keyof Listeners, cb: any): void {
    (this.listeners[event] as Set<any>).add(cb);
  }

  off(event: keyof Listeners, cb: any): void {
    (this.listeners[event] as Set<any>).delete(cb);
  }

  private connect(): void {
    const params: Record<string, string> = {};
    if (this.lastSeenRunId) params.last_seen_run_id = this.lastSeenRunId;

    const url = buildUrl(this.path, params);
    const ws = new WebSocket(url);
    this.ws = ws;

    ws.addEventListener("open", () => {
      this.reconnectAttempt = 0;
      // If the caller installed a non-empty filter, push it as soon as we
      // open so the server's filter closure narrows before the first
      // attestation arrives.
      if (Object.keys(this.filter).length > 0) {
        ws.send(JSON.stringify({ type: "set_filter", filter: this.filter }));
      }
      this.listeners.open.forEach((cb) => cb());
    });

    ws.addEventListener("message", (ev) => this.handleMessage(ev));

    ws.addEventListener("close", (ev) => {
      this.ws = null;
      this.listeners.close.forEach((cb) => cb(ev));
      if (!this.closedByCaller && !isFatalCloseCode(ev.code)) {
        this.scheduleReconnect();
      }
    });

    ws.addEventListener("error", () => {
      // Errors are surfaced via the subsequent `close` event; nothing to
      // do here beyond letting the close handler schedule a reconnect.
    });
  }

  private handleMessage(ev: MessageEvent): void {
    let frame: ServerFrame;
    try {
      frame = JSON.parse(ev.data as string) as ServerFrame;
    } catch {
      // Malformed frame — drop silently; subscribers receive nothing.
      return;
    }
    switch (frame.type) {
      case "attestation":
        this.lastSeenRunId = frame.run_id;
        this.listeners.attestation.forEach((cb) => cb(frame));
        break;
      case "backfill_summary":
        this.listeners.backfill_summary.forEach((cb) => cb(frame));
        break;
      case "filter_acknowledged":
        this.listeners.filter_acknowledged.forEach((cb) => cb(frame));
        break;
      case "error":
        this.listeners.error.forEach((cb) => cb(frame));
        break;
      case "ping":
        if (this.ws && this.ws.readyState === WebSocket.OPEN) {
          this.ws.send(
            JSON.stringify({ type: "pong", ts: new Date().toISOString() }),
          );
        }
        break;
      default:
        // Unknown frame type — ignore (forward-compat).
        break;
    }
  }

  private scheduleReconnect(): void {
    const idx = Math.min(
      this.reconnectAttempt,
      RECONNECT_BACKOFF_MS.length - 1,
    );
    const delay = RECONNECT_BACKOFF_MS[idx] ?? 5000;
    this.reconnectAttempt += 1;
    this.reconnectTimer = window.setTimeout(() => {
      this.reconnectTimer = null;
      if (!this.closedByCaller) this.connect();
    }, delay);
  }
}

/**
 * 4001 (cookie expired), 4002 (cross-tenant denial), 4003 (server drain) are
 * fatal — auto-reconnect would just churn. The SPA should surface a toast
 * and stop the live-tail toggle.
 */
function isFatalCloseCode(code: number): boolean {
  return code === 4001 || code === 4002 || code === 4003;
}
