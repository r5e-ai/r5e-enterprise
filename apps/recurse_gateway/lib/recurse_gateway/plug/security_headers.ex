defmodule Recurse.Gateway.Plug.SecurityHeaders do
  @moduledoc """
  Security-header plug for the F004 SPA + audit-API surface (T145, Phase-9
  polish).

  Sets the canonical Content-Security-Policy + clickjacking + MIME-sniffing
  + referrer headers for `/admin/*` static-asset responses and the same-origin
  `/v1/*` API. The CSP is locked down to:

    * `default-src 'self'` — only same-origin assets by default.
    * `script-src 'self' 'wasm-unsafe-eval'` — same-origin JS only;
      `wasm-unsafe-eval` is required for Monaco's Wasm-backed Cedar parser
      (the Policy Simulator's editor).
    * `style-src 'self' 'unsafe-inline'` — Tailwind-injected inline styles
      land in the SPA at runtime; Monaco also injects style tags.
    * `connect-src 'self' wss://<host>` — XHR / fetch only to the same
      origin; the WebSocket scheme `wss://<host>` is parsed at runtime
      from `conn.host` so the directive works across deployments without
      configuration drift.
    * `frame-ancestors 'none'` — clickjacking protection; equivalent to
      `X-Frame-Options: DENY` but enforced via CSP3.
    * `base-uri 'self'` — pin `<base href>` to the same origin to defeat
      base-target-override XSS.
    * `form-action 'self'` — submit forms only to same origin.

  Also sets:

    * `X-Content-Type-Options: nosniff` — never let browsers MIME-sniff a
      response.
    * `Referrer-Policy: strict-origin-when-cross-origin` — leak only the
      origin (not path/query) on cross-origin navigations.
    * `X-Frame-Options: DENY` — defense in depth for browsers without CSP3
      `frame-ancestors` support.

  ## CORS posture (per T145 contract)

  CORS is **strictly off** for `/admin/*` and `/v1/*` (same-origin only —
  the SPA and API share an origin). CORS is **on** for the well-known
  manifest + JSON-Schemas at `/.well-known/r5e-audit.json` and
  `/v1/schemas/*` per `well_known_manifest.md` so third-party verifier
  tooling can fetch them. CORS itself is handled by the `Corsica` plug at
  the route layer (or absent — same-origin is the default); this plug
  only manages the security headers.

  ## Iron Law check (`elixir:phoenix-thinking`)

  Pure module-plug — no GenServer state, no I/O. Reads `conn.host` for the
  WebSocket directive and writes response headers. Iron Law passes
  trivially: no mutable state across calls, no concurrency, no failures
  to isolate. Finishes without raising on every input.

  ## Cross-references

    * `specs/004-audit-console/tasks.md` T145
    * `specs/004-audit-console/contracts/well_known_manifest.md`
    * `apps/recurse_gateway/lib/recurse_gateway/router.ex` — wire-in.
  """

  @behaviour Plug

  import Plug.Conn

  @impl Plug
  @spec init(keyword()) :: keyword()
  def init(opts), do: opts

  @impl Plug
  @spec call(Plug.Conn.t(), keyword()) :: Plug.Conn.t()
  def call(%Plug.Conn{} = conn, _opts) do
    conn
    |> put_resp_header("content-security-policy", csp(conn))
    |> put_resp_header("x-content-type-options", "nosniff")
    |> put_resp_header("x-frame-options", "DENY")
    |> put_resp_header("referrer-policy", "strict-origin-when-cross-origin")
  end

  @doc """
  Compute the CSP directive string for the given conn.

  The `wss://<host>` host is parsed from `conn.host` at runtime so the
  directive works across deployments. The host is taken AS-IS from the
  conn (Bandit normalizes Host headers to lowercase + strips control
  chars before this plug runs); a defense-in-depth `String.replace/3`
  call removes any stray CR/LF that would let a malicious header break
  out of the CSP value.
  """
  @spec csp(Plug.Conn.t()) :: String.t()
  def csp(%Plug.Conn{host: host}) when is_binary(host) and host != "" do
    safe_host =
      host
      |> String.replace(["\r", "\n", ";", " "], "")
      |> case do
        "" -> "self"
        h -> h
      end

    "default-src 'self'; " <>
      "script-src 'self' 'wasm-unsafe-eval'; " <>
      "style-src 'self' 'unsafe-inline'; " <>
      "img-src 'self' data:; " <>
      "font-src 'self' data:; " <>
      "connect-src 'self' wss://#{safe_host}; " <>
      "frame-ancestors 'none'; " <>
      "base-uri 'self'; " <>
      "form-action 'self'"
  end

  def csp(_conn) do
    # Fallback when host is unset (test envs / weird proxies). Drops the
    # WebSocket scheme rather than leaving an empty wss:// directive.
    "default-src 'self'; " <>
      "script-src 'self' 'wasm-unsafe-eval'; " <>
      "style-src 'self' 'unsafe-inline'; " <>
      "img-src 'self' data:; " <>
      "font-src 'self' data:; " <>
      "connect-src 'self'; " <>
      "frame-ancestors 'none'; " <>
      "base-uri 'self'; " <>
      "form-action 'self'"
  end
end
