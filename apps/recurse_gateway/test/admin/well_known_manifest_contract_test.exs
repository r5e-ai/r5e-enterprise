defmodule Recurse.Gateway.Admin.WellKnownManifestContractTest do
  @moduledoc """
  Manifest <-> code contract canary (issue #30, Tasks H/I/J/K).

  This is the test that prevents the next round of "manifest drifted away
  from the routes / schemas / events the gateway actually serves" from
  shipping silently. Four invariants:

    1. **Schema URI reachability (Task H closed forever).** For every
       entry in `manifest.schemas[*]`, doing the equivalent of `GET <uri>`
       through `Router.call/2` returns 200 with `application/schema+json`
       and a JSON body whose `$id` ends in the schema's bare name.

    2. **Placeholder/contract version honesty (Task I closed forever).**
       For every schema entry: if the schema BODY carries
       `"x-status": "placeholder"`, then the manifest MUST advertise it
       with a pre-1.0 version (e.g., `0.1.0-placeholder`). And vice
       versa: if a schema is stable in the manifest (`x-version: 1.0.0`)
       it MUST NOT carry `"x-status": "placeholder"` in its body.

    3. **Endpoint inventory completeness (Task K closed forever).** For
       every entry in `manifest.endpoints[*]`, the path/method appears
       in the hardcoded P-1 router route list (the same list the auth
       canary keeps current). Drift in either direction (manifest
       advertises a phantom route OR the router serves a route the
       manifest hides) flunks this property — forcing the manifest to
       evolve in lockstep with `router.ex`.

    4. **Endpoint schema reference resolves (Task J semantic-drift
       canary).** For every endpoint's `schema_uri` (and
       `request_schema_uri` when present), `SchemaPublication` can
       actually serve it — the bareword key (suffix-stripped) appears in
       `SchemaPublication.list_schema_names/0`. Catches the next "I
       wired the manifest to a schema that doesn't exist" regression
       and the symmetric "I forgot to mark the new endpoint's schema
       in the schemas array."

  ## Iron Law check (`elixir:elixir-thinking`)

  No process. Plain functions. The test reads files synchronously,
  exercises Router.call/2 against an in-memory conn, and asserts. No
  setup state beyond the same minimal stub-provider posture every other
  router-touching test uses.

  ## Why this is a contract test, not a property test

  The manifest is small (≈15 endpoints, ≈15 schemas) and finite. There's
  no input space to shrink over — every invariant ranges over an
  enumerated finite set. Plain ExUnit `test` blocks with explicit
  `for`-loops give better failure-message granularity than `check all`
  shrinking, and the absence of randomness means CI failures are
  reproducible by line number.

  ## Cross-references

    * `apps/recurse_gateway/priv/schemas/manifest.json` (source of truth)
    * `apps/recurse_gateway/lib/recurse_gateway/admin/well_known_manifest.ex`
    * `apps/recurse_gateway/lib/recurse_gateway/admin/schema_publication.ex`
    * `apps/recurse_gateway/test/router_auth_property_test.exs`
      (the P-1 canary; this test reuses its hardcoded route list shape).
    * Issue #30, Tasks H/I/J/K (gitlab.com/r5e-group/r5e-enterprise/-/work_items/30).
  """

  # `async: false` because the Router reads from the singleton
  # `ProviderRegistry` and Application env. Same posture as
  # `RouterAuthPropertyTest`.
  use ExUnit.Case, async: false

  alias Recurse.Gateway.Admin.SchemaPublication
  alias Recurse.Gateway.ProviderRegistry
  alias Recurse.Gateway.Router

  @manifest_path Path.expand(
                   "../../priv/schemas/manifest.json",
                   __DIR__
                 )
  @schemas_dir Path.expand(
                 "../../priv/schemas",
                 __DIR__
               )

  @opts Router.init([])

  # Hardcoded route inventory. This MUST stay in sync with `router.ex`
  # (the P-1 canary `router_auth_property_test.exs` keeps the auth shape
  # current; this test keeps the manifest-publish-able set current).
  # Format: `{"METHOD", "/concrete/path/with/{params}"}` — the path
  # segments use `{name}` placeholders to match the manifest's RFC 6570
  # template syntax verbatim. The test compares manifest paths to this
  # set as plain strings; no URI-template expansion.
  @router_routes [
    {"GET", "/v1/auth/me"},
    {"GET", "/v1/audit/sessions/{session_id}"},
    {"POST", "/v1/policy/simulate"},
    {"POST", "/v1/policy/replay/{run_id}"},
    {"POST", "/v1/policy/drafts"},
    {"GET", "/v1/policy/drafts/{id}"},
    {"POST", "/v1/policy/drafts/{id}/dry-run"},
    {"GET", "/v1/policy/suggestions"},
    {"GET", "/v1/policy/suggestions/{id}"},
    {"POST", "/v1/policy/suggestions/{id}/adopt"},
    {"POST", "/v1/policy/suggestions/{id}/dismiss"},
    {"POST", "/v1/policy/suggestions/refresh"},
    {"POST", "/v1/chat/messages"},
    {"GET", "/v1/chat/conversations"},
    {"GET", "/v1/chat/conversations/{id}"},
    {"GET", "/v1/mcp/registry"},
    {"GET", "/v1/mcp/registry/{id}"},
    {"PATCH", "/v1/mcp/registry/{id}"},
    {"POST", "/v1/mcp/{server}/tools/{tool}"}
  ]

  setup_all do
    raw = File.read!(@manifest_path)
    parsed = JSON.decode!(raw)
    {:ok, manifest: parsed}
  end

  setup do
    # Minimal stub state — same shape as router_auth_property_test.
    # We only exercise PUBLIC schema routes, which don't need provider
    # state, but installing the stub state is cheap insurance against
    # the router peeking at `tenant_id` during its boot path.
    ProviderRegistry.install_raw!(%{
      llm: {Recurse.Gateway.Test.StubLLM, %{}},
      ledger: {Recurse.Gateway.Test.StubLedger, %{}},
      storage: {Recurse.Gateway.Test.StubStorage, %{}},
      secrets: {Recurse.Gateway.Test.StubSecretsProvider, %{}},
      tenant_id: "01HQZN5K7J8M9N0P1Q2R3S4T5V",
      signer: "observed://gateway/test"
    })

    on_exit(fn -> ProviderRegistry.uninstall() end)
    :ok
  end

  # ---------------------------------------------------------------------------
  # Invariant 1 — every published schema URI returns 200
  # ---------------------------------------------------------------------------

  describe "Invariant 1 — schema URI reachability (Task H canary)" do
    test "every manifest.schemas[*].uri returns 200 with the right body",
         %{manifest: manifest} do
      schemas = Map.fetch!(manifest, "schemas")

      for schema <- schemas do
        name = Map.fetch!(schema, "name")
        uri = Map.fetch!(schema, "uri")
        path = uri_to_path(uri)

        conn =
          :get
          |> Plug.Test.conn(path)
          |> Router.call(@opts)

        assert conn.status == 200,
               "GET #{path} (manifest schema #{inspect(name)}) returned " <>
                 "#{inspect(conn.status)}, expected 200. Body: #{inspect(conn.resp_body)}.\n" <>
                 "This is the Task H regression: route shape `/v1/schemas/:name.json` " <>
                 "must capture the bare schema name, and SchemaPublication must serve it."

        content_type =
          conn
          |> Plug.Conn.get_resp_header("content-type")
          |> List.first()

        assert content_type =~ "application/schema+json",
               "GET #{path} content-type was #{inspect(content_type)}; " <>
                 "expected application/schema+json"

        body = JSON.decode!(conn.resp_body)

        assert Map.fetch!(body, "$id") |> String.ends_with?("#{name}.json"),
               "schema body $id #{inspect(Map.get(body, "$id"))} does not " <>
                 "end with #{name}.json — manifest entry name and on-disk " <>
                 "schema $id are out of sync."
      end
    end
  end

  # ---------------------------------------------------------------------------
  # Invariant 2 — placeholder/contract version honesty (Task I canary)
  # ---------------------------------------------------------------------------

  describe "Invariant 2 — placeholder vs stable version honesty (Task I canary)" do
    test "schemas with x-status:placeholder have pre-1.0 manifest version, and vice versa",
         %{manifest: manifest} do
      schemas = Map.fetch!(manifest, "schemas")

      for schema_entry <- schemas do
        name = Map.fetch!(schema_entry, "name")
        manifest_version = Map.fetch!(schema_entry, "version")

        body =
          @schemas_dir
          |> Path.join("#{name}.json")
          |> File.read!()
          |> JSON.decode!()

        body_status = Map.get(body, "x-status")
        body_version = Map.fetch!(body, "x-version")
        placeholder? = body_status == "placeholder"
        manifest_pre_1? = pre_1_0?(manifest_version)

        cond do
          placeholder? and not manifest_pre_1? ->
            flunk("""
            Schema #{inspect(name)} body declares `x-status: "placeholder"` but \
            manifest publishes it with version #{inspect(manifest_version)} — \
            advertising a placeholder as a stable contract.

            Fix one of:
              (a) Set manifest entry version to "0.1.0-placeholder" (or any \
                  pre-1.0 version) so consumers know it's not yet stable.
              (b) If the schema body is in fact a real shape, drop the \
                  `x-status: "placeholder"` field from #{name}.json.

            Body x-version: #{inspect(body_version)}.
            This is the Task I regression (issue #30).
            """)

          not placeholder? and manifest_pre_1? ->
            flunk("""
            Schema #{inspect(name)} manifest version is #{inspect(manifest_version)} \
            (pre-1.0) but the schema body does NOT carry `x-status: "placeholder"`.

            Either bump manifest entry to a 1.x version (it's stable) or add \
            `"x-status": "placeholder"` to the schema body so clients can \
            machine-detect pre-1.0 status.

            Body x-version: #{inspect(body_version)}.
            """)

          true ->
            :ok
        end
      end
    end
  end

  # ---------------------------------------------------------------------------
  # Invariant 3 — endpoint inventory completeness (Task K canary)
  # ---------------------------------------------------------------------------

  describe "Invariant 3 — endpoint inventory completeness (Task K canary)" do
    test "every manifest.endpoints[*] (path,method) is in the router route list",
         %{manifest: manifest} do
      endpoints = Map.fetch!(manifest, "endpoints")

      router_set = MapSet.new(@router_routes)

      for endpoint <- endpoints do
        path = Map.fetch!(endpoint, "path")
        method = Map.fetch!(endpoint, "method")
        key = {method, path}

        assert MapSet.member?(router_set, key),
               """
               Manifest endpoint #{method} #{path} is not in the router route list.

               Either:
                 (a) The manifest documents a phantom route — remove the entry from \
                     manifest.json.
                 (b) The router list in this test is stale — sync it against \
                     router.ex (and against router_auth_property_test.exs's \
                     classification list).

               This is the Task K regression: the manifest claims to be the \
               discoverable surface; if it advertises routes that don't exist \
               (or the test list omits real ones) it isn't.
               """
      end
    end

    test "every router route in the test list is published in the manifest",
         %{manifest: manifest} do
      manifest_paths =
        manifest
        |> Map.fetch!("endpoints")
        |> Enum.map(fn e -> {Map.fetch!(e, "method"), Map.fetch!(e, "path")} end)
        |> MapSet.new()

      missing =
        @router_routes
        |> Enum.reject(&MapSet.member?(manifest_paths, &1))

      assert missing == [],
             """
             The following router routes are NOT published in manifest.endpoints:

             #{inspect(missing, pretty: true)}

             Add manifest entries for each, including schema_uri, requires_role, \
             cedar_action, and event_kind. Match the values to the handler's \
             actual emission (read the handler — code is authoritative).

             This is the symmetric Task K regression: the router serves a route \
             the manifest hides.
             """
    end
  end

  # ---------------------------------------------------------------------------
  # Invariant 4 — endpoint schema references resolve (Task J semantic-drift)
  # ---------------------------------------------------------------------------

  describe "Invariant 4 — endpoint schema references resolve (Task J canary)" do
    test "every endpoint schema_uri / request_schema_uri resolves to a published schema",
         %{manifest: manifest} do
      endpoints = Map.fetch!(manifest, "endpoints")
      published = MapSet.new(SchemaPublication.list_schema_names())

      for endpoint <- endpoints do
        path = Map.fetch!(endpoint, "path")
        method = Map.fetch!(endpoint, "method")

        check_uri = fn key ->
          case Map.get(endpoint, key) do
            nil ->
              :ok

            uri when is_binary(uri) ->
              name = uri |> uri_to_path() |> path_to_bare_name()

              assert MapSet.member?(published, name),
                     """
                     Endpoint #{method} #{path} declares #{key}=#{inspect(uri)} \
                     but bareword name #{inspect(name)} is NOT in the published \
                     schemas (SchemaPublication.list_schema_names/0).

                     Published: #{inspect(Enum.sort(MapSet.to_list(published)))}

                     This is the Task J regression class: the manifest advertises \
                     a schema that doesn't exist on disk OR the schema name was \
                     renamed without updating the manifest. Add the schema file or \
                     fix the manifest reference.
                     """
          end
        end

        check_uri.("schema_uri")
        check_uri.("request_schema_uri")
      end
    end
  end

  # ---------------------------------------------------------------------------
  # Invariant 5 — manifest + schemas resolve via :code.priv_dir/1 (release
  # path safety). Regression guard for the audit-dev 500 — see issue
  # /closes Batch C / C1. The previous implementation cached
  # `Path.expand("../../../priv/...", __DIR__)` in a module attribute,
  # which froze the GitLab-CI source-tree path into the BEAM and
  # crashed File.read! at request time on the deployed EC2 host.
  # ---------------------------------------------------------------------------

  describe "Invariant 5 — release-safe path resolution" do
    test "manifest.json is discoverable under :code.priv_dir(:recurse_gateway)" do
      priv = :code.priv_dir(:recurse_gateway)
      manifest_path = Path.join([priv, "schemas", "manifest.json"])

      assert File.exists?(manifest_path),
             """
             Expected the manifest to live at #{manifest_path} (i.e., under
             :code.priv_dir(:recurse_gateway)) so it is reachable both from
             the source tree (mix test) AND from a deployed release at
             /opt/r5e/audit/current/lib/recurse_gateway-X.Y.Z/priv/...

             If this fails, someone reintroduced a compile-time
             `Path.expand("../../../priv/...", __DIR__)` module attribute,
             which freezes the build-host source path into the BEAM and
             500s at request time on the deployed audit-dev host.
             """
    end

    test "every schema name discoverable on disk lives under :code.priv_dir" do
      priv = :code.priv_dir(:recurse_gateway)
      schemas_dir = Path.join(priv, "schemas")
      assert File.dir?(schemas_dir)
      # SchemaPublication.list_schema_names/0 enumerates this directory at
      # request time. Its output drives every other invariant in this file;
      # the directory MUST resolve under :code.priv_dir, never under
      # `__DIR__`.
      assert SchemaPublication.list_schema_names() != [],
             "SchemaPublication.list_schema_names/0 returned []; " <>
               "schemas_dir() must point at the deployed priv/schemas/ tree."
    end
  end

  # ---------------------------------------------------------------------------
  # Helpers
  # ---------------------------------------------------------------------------

  # Strip scheme + host from an absolute URI; return only the path.
  # The manifest carries absolute URIs (rewritten at boot from the
  # placeholder host); routing tests only need the path. Works for both
  # the placeholder host and any rewritten host.
  defp uri_to_path(uri) when is_binary(uri) do
    case URI.parse(uri) do
      %URI{path: path} when is_binary(path) -> path
      _ -> uri
    end
  end

  # Convert "/v1/schemas/foo.json" -> "foo".
  defp path_to_bare_name(path) when is_binary(path) do
    path
    |> Path.basename()
    |> Path.rootname()
  end

  # Return true when the version string declares a major-version of 0
  # (i.e., pre-1.0 / placeholder territory). Accepts both "0.1.0" and
  # "0.1.0-placeholder" / "0.1.0-rc1" semver pre-release suffixes.
  defp pre_1_0?(version) when is_binary(version) do
    case String.split(version, ".", parts: 2) do
      ["0", _rest] -> true
      _ -> false
    end
  end
end
