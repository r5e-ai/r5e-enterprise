defmodule Recurse.Gateway.Admin.WellKnownManifest do
  @moduledoc """
  `GET /.well-known/r5e-audit.json` (F004 T041, FR-045).

  Serves the audit-console's stable, hand-authored manifest from
  `apps/recurse_gateway/priv/schemas/manifest.json` per
  `specs/004-audit-console/contracts/well_known_manifest.md`.

  ## What this endpoint is — and is NOT

  Per project memory `feedback_no_premature_metaapi.md`: the manifest is
  a **stable forward-compatible description** of a typed versioned API.
  It is NOT a runtime-introspective protocol — the manifest source-of-
  truth is a hand-authored JSON file that ships in `priv/schemas/`. The
  Plug below loads that file at boot, normalizes its key ordering for
  byte-determinism, and serves the result on every request without
  re-parsing or re-encoding per-call.

  ## Iron Law check (`elixir:phoenix-thinking` / `elixir:elixir-thinking`)

    1. Mutable state persisting across calls? No — the cached body is
       a `:persistent_term` set once at module-load time (`__MODULE__,
       :body`). Re-loads happen only on a release-restart.
    2. Concurrent execution? No — `:persistent_term.get/1` is lock-free
       and runs on the request process.
    3. Fault isolation? No — boot-time corruption of the manifest file
       is a fatal release-blocking error and rightly so (the file is
       part of the `:recurse_gateway` artifact).

  All three NO → plain functions; no GenServer.

  ## Hostname rewriting

  The on-disk `manifest.json` uses `gateway.example.com` as a literal
  placeholder for absolute URIs in `endpoints[*].schema_uri`,
  `endpoints[*].request_schema_uri`, and `schemas[*].uri`. At serve
  time the placeholder is rewritten to the configured deployment
  hostname (per `:recurse_gateway, :public_hostname`).

  Rewriting happens at module load (in `init/1`) so per-request work
  is just a `:persistent_term.get/1` + `Plug.Conn.send_resp/3`.

  ## Cache headers

  `Cache-Control: public, max-age=300` per the contract. Manifest
  changes are operator-driven (PR + redeploy), so a 5-min cache is
  comfortable.

  ## CORS

  Public endpoint. Build-time tooling under foreign origins (e.g.,
  third-party verifier CLIs) needs cross-origin GET access. CORS
  is configured via `Corsica` at the route layer (T002 dependency
  pulls `corsica`). This module emits the bare `Cache-Control` +
  `Content-Type` headers; CORS headers are layered by the wrapping
  pipeline.

  ## Cross-references

    * `specs/004-audit-console/contracts/well_known_manifest.md`
      \u00a7"`/.well-known/r5e-audit.json`"
    * `apps/recurse_gateway/priv/schemas/manifest.json` (source of truth)
    * F004 FR-045 (manifest publication), FR-046 (schema publication)
  """

  @behaviour Plug

  # Resolve `priv/schemas/manifest.json` at RUNTIME via `:code.priv_dir/1`
  # rather than baking a `Path.expand("../../../priv/...", __DIR__)` value
  # at compile time. The compile-time form gets the SOURCE path frozen
  # into the BEAM file (e.g., `/builds/r5e-group/r5e-enterprise/.../`
  # under GitLab CI), which doesn't exist inside the deployed release
  # container where the file lives under `lib/recurse_gateway-X.Y.Z/priv`.
  # Same idiom as `Plug.AdminStatic` and
  # `SuggestionEngine.LlmRunner`. (Function — not module attribute —
  # because module attributes are evaluated at compile time.)
  @placeholder_host "gateway.example.com"
  @persistent_term_key {__MODULE__, :body}
  @cache_control "public, max-age=300"

  @spec manifest_path() :: String.t()
  defp manifest_path do
    Path.join([:code.priv_dir(:recurse_gateway), "schemas", "manifest.json"])
  end

  @doc false
  @impl Plug
  def init(opts) do
    # Boot-time: read + normalize + cache. We do this in `init/1` rather
    # than at compile time so a deployment can mount a tier-config-
    # overridden hostname before the Plug is mounted. Plug.Router's
    # `forward` macro calls `init/1` once at compile time AND again at
    # boot in some configurations; either way the side effect is
    # idempotent (`:persistent_term.put` with the same value is a
    # no-op).
    body = build_body()
    :persistent_term.put(@persistent_term_key, body)
    opts
  end

  @doc false
  @impl Plug
  def call(%Plug.Conn{} = conn, _opts) do
    body = :persistent_term.get(@persistent_term_key, build_body())

    conn
    |> Plug.Conn.put_resp_content_type("application/json")
    |> Plug.Conn.put_resp_header("cache-control", @cache_control)
    |> Plug.Conn.send_resp(200, body)
  end

  @doc """
  Re-read `manifest.json` from disk, rewrite the hostname placeholder,
  serialize with deterministic key ordering, and return the bytes.

  Exposed for tests and for callers that need to seed the cache out-
  of-band (e.g., property tests that want to assert byte-determinism
  without exercising `init/1`).
  """
  @spec build_body() :: binary()
  def build_body do
    manifest_path()
    |> File.read!()
    |> JSON.decode!()
    |> rewrite_hostname(deployment_hostname())
    |> encode_canonical()
  end

  @doc """
  The currently-configured public hostname used for absolute-URI
  rewriting. Falls back to the local container origin for default-config
  tests and quickstarts.
  """
  @spec deployment_hostname() :: String.t()
  def deployment_hostname do
    Application.get_env(:recurse_gateway, :public_hostname, "http://127.0.0.1:4000")
  end

  # ---------------------------------------------------------------------------
  # Private — placeholder rewriting + canonical encoding
  # ---------------------------------------------------------------------------

  # Walk the parsed manifest and replace every literal substring
  # `gateway.example.com` inside binary values with the configured
  # hostname. Recursive descent over maps + lists; non-string leaves
  # pass through untouched. Cheaper than per-key URI parsing and
  # robust enough because the placeholder is a unique sentinel.
  defp rewrite_hostname(value, host) when is_map(value) do
    Map.new(value, fn {k, v} -> {k, rewrite_hostname(v, host)} end)
  end

  defp rewrite_hostname(value, host) when is_list(value) do
    Enum.map(value, &rewrite_hostname(&1, host))
  end

  defp rewrite_hostname(value, host) when is_binary(value) do
    if host == @placeholder_host do
      value
    else
      String.replace(value, @placeholder_host, host)
    end
  end

  defp rewrite_hostname(value, _host), do: value

  # Deterministic JSON encoding. We can't rely on `JSON.encode!/1` to
  # emit map keys in any particular order — Elixir maps switch from
  # ordered (small) to HAMT (>= 32 keys) representation, so a sorted-
  # then-Map.new round-trip loses ordering at the encode step.
  #
  # Instead we walk the structure ourselves and emit JSON bytes
  # directly, sorting object keys before encoding their entries. The
  # output matches RFC 8259 — the same JSON value as `JSON.encode!/1`
  # would produce, just with deterministic key order. Test asserts:
  # repeat-encoding the same input yields byte-identical output.
  defp encode_canonical(term), do: IO.iodata_to_binary(encode_value(term))

  defp encode_value(value) when is_map(value) do
    pairs =
      value
      |> Enum.sort_by(fn {k, _v} -> to_string(k) end)
      |> Enum.map(fn {k, v} ->
        [encode_string(to_string(k)), ?:, encode_value(v)]
      end)
      |> Enum.intersperse(?,)

    [?{, pairs, ?}]
  end

  defp encode_value(value) when is_list(value) do
    items =
      value
      |> Enum.map(&encode_value/1)
      |> Enum.intersperse(?,)

    [?[, items, ?]]
  end

  defp encode_value(value) when is_binary(value), do: encode_string(value)
  defp encode_value(true), do: "true"
  defp encode_value(false), do: "false"
  defp encode_value(nil), do: "null"
  defp encode_value(value) when is_integer(value), do: Integer.to_string(value)
  defp encode_value(value) when is_float(value), do: Float.to_string(value)

  # Defer to the built-in JSON encoder for string escaping — RFC 8259
  # \\u escape sequences are non-trivial and `JSON.encode!/1` already
  # implements them correctly. Per-string overhead is minor.
  defp encode_string(s) when is_binary(s), do: JSON.encode!(s)
end
