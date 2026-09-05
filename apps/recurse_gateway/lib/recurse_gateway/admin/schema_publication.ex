defmodule Recurse.Gateway.Admin.SchemaPublication do
  @moduledoc """
  Schema-publication endpoints (F004 T042, FR-046):

    * `GET /v1/schemas/index.json` — directory listing of every published
      JSON Schema, with `name`, `uri`, and `version` per schema.
    * `GET /v1/schemas/{name}.json` — serves a single hand-authored
      schema file from `apps/recurse_gateway/priv/schemas/` with
      `Content-Type: application/schema+json`.

  Per `specs/004-audit-console/contracts/well_known_manifest.md`
  \u00a7"`/v1/schemas/index.json`" + \u00a7"Per-schema URIs". Both routes are
  public (no auth). CORS is layered by the wrapping pipeline (corsica).

  ## Iron Law check (`elixir:phoenix-thinking`)

    1. Mutable state across calls? No — index + per-schema bytes are
       cached in `:persistent_term` at module-init.
    2. Concurrent execution? No — `:persistent_term.get/1` is lock-
       free and runs on the request process.
    3. Fault isolation? No — boot-time corruption of any schema file
       is fatal at release time and rightly so.

  All three NO → plain functions; no GenServer.

  ## Why two entrypoints, not one Plug.Static mount

  The schema files need **hostname rewriting** (the on-disk `$id` /
  `$ref` strings reference the literal placeholder
  `gateway.example.com`; serve-time substitution writes the
  configured public hostname). `Plug.Static` cannot rewrite bytes —
  it only sets headers. We read each schema once at boot, rewrite,
  and cache the rewritten bytes.

  ## Routing pattern

  This module exposes two entrypoints:

    * `index/2` — handles `GET /v1/schemas/index.json`. Plug interface.
    * `serve_schema/2` — handles `GET /v1/schemas/:name.json`. Plug
      interface that pulls the `:name` segment from `conn.path_params`
      (set by `Plug.Router`'s `match`).

  The wrapping `Plug.Router` (in W3) wires both routes; this module
  contains no routing macros itself. That keeps the module testable
  in isolation: callers hand a built `%Plug.Conn{}` to either
  function and assert the response.

  ## 404 envelope on schema-not-found

  Serves the F001 error envelope shape per
  `specs/001-api-jido-foundations` error contract — the same JSON
  shape used by every audit-API 4xx so SPA error handling is
  uniform. Distinct from a generic 404 because the schema URIs
  appear in the manifest; the SPA's codegen pipeline must know
  unambiguously when a schema name is unknown vs when the server
  itself is mis-routed.

  ## Cross-references

    * `specs/004-audit-console/contracts/well_known_manifest.md`
    * `apps/recurse_gateway/priv/schemas/*.json` (source of truth)
    * F004 FR-046
  """

  alias Recurse.Gateway.Admin.WellKnownManifest

  # Resolve `priv/schemas/` at RUNTIME via `:code.priv_dir/1` rather than
  # baking a `Path.expand("../../../priv/...", __DIR__)` value at compile
  # time. See the matching note in `WellKnownManifest`: compile-time
  # `__DIR__`-relative paths get the GitLab CI source path frozen into
  # the BEAM, which doesn't exist on the deployed host. Same idiom as
  # `Plug.AdminStatic` and `SuggestionEngine.LlmRunner`.
  @placeholder_host "gateway.example.com"
  @cache_control "public, max-age=300"
  @schema_content_type "application/schema+json"

  @spec schemas_dir() :: String.t()
  defp schemas_dir do
    Path.join(:code.priv_dir(:recurse_gateway), "schemas")
  end

  @doc false
  def init(opts) do
    # Boot-time: enumerate every JSON file in priv/schemas/, rewrite
    # the placeholder hostname in each, cache rewritten bytes per
    # schema name. Also build the canonical index document.
    by_name = build_cache()
    :persistent_term.put({__MODULE__, :by_name}, by_name)
    :persistent_term.put({__MODULE__, :index_body}, build_index_body(by_name))
    opts
  end

  # ---------------------------------------------------------------------------
  # Index — GET /v1/schemas/index.json
  # ---------------------------------------------------------------------------

  @doc """
  Serve `GET /v1/schemas/index.json` — the schema directory listing.

  Plug-shaped: takes a `Plug.Conn` and unused opts; returns the
  responded conn.
  """
  @spec index(Plug.Conn.t(), term()) :: Plug.Conn.t()
  def index(%Plug.Conn{} = conn, _opts) do
    body = :persistent_term.get({__MODULE__, :index_body}, build_index_body(build_cache()))

    conn
    |> Plug.Conn.put_resp_content_type("application/json")
    |> Plug.Conn.put_resp_header("cache-control", @cache_control)
    |> Plug.Conn.send_resp(200, body)
  end

  # ---------------------------------------------------------------------------
  # Per-schema — GET /v1/schemas/:name.json
  # ---------------------------------------------------------------------------

  @doc """
  Serve `GET /v1/schemas/:name.json`.

  Pulls `:name` from `conn.path_params["name"]`. Returns the cached
  rewritten schema bytes with `Content-Type: application/schema+json`,
  or a 404 F001 error envelope if the name is unknown. Manifest itself
  (`name = "manifest"`) is excluded — clients should fetch the
  manifest from `/.well-known/r5e-audit.json`.
  """
  @spec serve_schema(Plug.Conn.t(), term()) :: Plug.Conn.t()
  def serve_schema(%Plug.Conn{path_params: %{"name" => name}} = conn, _opts) do
    by_name = :persistent_term.get({__MODULE__, :by_name}, build_cache())

    case Map.fetch(by_name, name) do
      {:ok, bytes} ->
        conn
        |> Plug.Conn.put_resp_content_type(@schema_content_type)
        |> Plug.Conn.put_resp_header("cache-control", @cache_control)
        |> Plug.Conn.send_resp(200, bytes)

      :error ->
        send_not_found(conn, name)
    end
  end

  # If the wrapping router didn't populate `path_params["name"]` (e.g.,
  # someone hits the module directly in a test) we still respond
  # consistently rather than crashing on a partial conn.
  def serve_schema(%Plug.Conn{} = conn, _opts), do: send_not_found(conn, "")

  # ---------------------------------------------------------------------------
  # Public introspection — used by tests and by WellKnownManifest's
  # property test to assert reference integrity without re-reading disk.
  # ---------------------------------------------------------------------------

  @doc """
  List the bareword names of every published schema, sorted. Excludes
  the manifest itself (`"manifest"`).
  """
  @spec list_schema_names() :: [String.t()]
  def list_schema_names do
    schemas_dir()
    |> File.ls!()
    |> Enum.filter(&String.ends_with?(&1, ".json"))
    |> Enum.map(&Path.rootname/1)
    |> Enum.reject(&(&1 == "manifest"))
    |> Enum.sort()
  end

  # ---------------------------------------------------------------------------
  # Boot-time cache builders
  # ---------------------------------------------------------------------------

  defp build_cache do
    host = deployment_hostname()
    dir = schemas_dir()

    list_schema_names()
    |> Map.new(fn name ->
      bytes =
        Path.join(dir, name <> ".json")
        |> File.read!()
        |> rewrite_hostname(host)

      {name, bytes}
    end)
  end

  # The index is itself a small JSON document. We derive it from the
  # manifest's `schemas` array so there's exactly one source of truth
  # for `(name, uri, version)` tuples — the manifest. The `updated_at`
  # field also comes from the manifest, keeping a single timestamp.
  #
  # `_by_name` is kept as a parameter to make the boot-order
  # contract explicit: the per-schema cache MUST be primed before
  # the index is built (build_index_body is called immediately
  # after the cache assignment in `init/1`). Pulling the data from
  # the cache here, rather than from disk, would couple the index
  # to the cache's internal representation; reading the manifest
  # directly is cleaner.
  defp build_index_body(_by_name) do
    manifest =
      WellKnownManifest.build_body()
      |> JSON.decode!()

    index = %{
      "schemas" => Map.fetch!(manifest, "schemas"),
      "updated_at" => Map.fetch!(manifest, "updated_at")
    }

    encode_canonical(index)
  end

  # ---------------------------------------------------------------------------
  # Hostname rewriting — substring substitution on the file bytes.
  # We rewrite the file bytes (not the parsed JSON) because schema
  # contents are referenced by `$id` / `$ref` inside string values,
  # and the placeholder is a unique sentinel — no risk of false
  # positives. Cheaper than re-encoding (preserves the file's
  # original whitespace + key order, which is the published wire
  # form clients hash against during build-time codegen).
  # ---------------------------------------------------------------------------

  defp rewrite_hostname(bytes, host) when host == @placeholder_host, do: bytes

  defp rewrite_hostname(bytes, host) when is_binary(bytes) and is_binary(host) do
    String.replace(bytes, @placeholder_host, host)
  end

  defp deployment_hostname do
    Application.get_env(:recurse_gateway, :public_hostname, "http://127.0.0.1:4000")
  end

  # ---------------------------------------------------------------------------
  # F001 error envelope — uniform 404 shape across the audit API.
  # ---------------------------------------------------------------------------

  defp send_not_found(conn, name) do
    body =
      JSON.encode!(%{
        "error" => "not_found",
        "error_description" => "No published schema named #{inspect(name)}",
        "correlation_id" => correlation_id_or_new(conn),
        "attested_run_id" => nil
      })

    conn
    |> Plug.Conn.put_resp_content_type("application/json")
    |> Plug.Conn.send_resp(404, body)
  end

  defp correlation_id_or_new(conn) do
    case Plug.Conn.get_req_header(conn, "x-correlation-id") do
      [id | _] when is_binary(id) and id != "" -> id
      _ -> "no-correlation-id"
    end
  end

  # ---------------------------------------------------------------------------
  # Same canonical encoder as WellKnownManifest. Duplicated rather
  # than shared so each module owns its own deterministic-bytes
  # contract; the encoder is small enough that DRY-ing it would cost
  # more in indirection than it saves.
  # ---------------------------------------------------------------------------

  defp encode_canonical(term), do: IO.iodata_to_binary(encode_value(term))

  defp encode_value(value) when is_map(value) do
    pairs =
      value
      |> Enum.sort_by(fn {k, _v} -> to_string(k) end)
      |> Enum.map(fn {k, v} -> [JSON.encode!(to_string(k)), ?:, encode_value(v)] end)
      |> Enum.intersperse(?,)

    [?{, pairs, ?}]
  end

  defp encode_value(value) when is_list(value) do
    items = value |> Enum.map(&encode_value/1) |> Enum.intersperse(?,)
    [?[, items, ?]]
  end

  defp encode_value(value) when is_binary(value), do: JSON.encode!(value)
  defp encode_value(true), do: "true"
  defp encode_value(false), do: "false"
  defp encode_value(nil), do: "null"
  defp encode_value(value) when is_integer(value), do: Integer.to_string(value)
  defp encode_value(value) when is_float(value), do: Float.to_string(value)
end
