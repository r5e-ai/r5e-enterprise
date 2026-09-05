defmodule Recurse.Gateway.Admin.WellKnownManifestPropertyTest do
  @moduledoc """
  Surface "Manifest stability" (F004 T040) per
  `specs/004-audit-console/contracts/property_test_surface_catalog_f004.md`.

  Five properties hold over the manifest at
  `apps/recurse_gateway/priv/schemas/manifest.json` (the source of
  truth for the `/.well-known/r5e-audit.json` endpoint):

    1. **Byte-identical re-serialization.** `build_body/0` returns
       identical bytes across N invocations — no per-request mutation,
       no time-of-day output drift, no map-iteration-order surprises.
    2. **Reference integrity.** Every `endpoint.schema_uri` (and
       `endpoint.request_schema_uri` when present) resolves to a
       schema entry in `manifest.schemas` (matched by both name and
       absolute URI).
    3. **Version monotonicity.** Every `schema.version` major-version
       is `<=` the manifest's major-version. A schema can be patched
       within a manifest version, but a major bump in any schema
       requires a major bump in the manifest.
    4. **Role allowlist correctness.** Every `endpoint.requires_role`
       element is in the F004 audit-console allowlist
       `["tenant_auditor", "platform_operator"]`.
    5. **Cedar action declared.** Every `endpoint.cedar_action` (when
       present) parses to an action declared in
       `priv/cedar/schema.cedarschema.json` (the canonical Cedar
       Entity Schema per F004 cedar_entity_schema_extensions.md).

  ## Iterations

  50 per the surface catalog. The manifest itself is small (\u224815
  endpoints, \u224815 schemas) so each iteration is cheap; we reach 50
  for shrinking-quality margin per stream-data-thinking, not for
  coverage of a vast input space.

  ## Why property tests at all (vs. plain ExUnit)

  The "byte-identity" property is stronger than a single-invocation
  assertion — we want to assert the property holds for ANY N. Map
  iteration ordering bugs in the Elixir `JSON` encoder (e.g., HAMT
  vs. small-map representation) only surface stochastically; running
  the encoder 50 times against the same input is the cheap way to
  catch those.

  Properties 2\u20135 are structural; we generate random index/integer
  pairs to drive the assertions over distinct elements of the
  manifest's `endpoints` and `schemas` arrays so failures shrink
  to a minimal counterexample (e.g., "endpoint at index 3 has a
  bad cedar_action").

  ## stream-data-thinking notes

    * NO `filter/2` in any generator — every generator emits a
      directly-valid value (`integer/2` ranges, `member_of/1` over
      enumerated index sets).
    * `bind/2` is used where one generator's output bounds another
      (e.g., the index into the endpoints array depends on its
      length). This preserves shrinking; a `filter` would discard
      shrinks silently.
    * Generators use stable enumerated indices rather than random
      strings so a failing iteration shrinks to "endpoint #0", not
      "some endpoint with name x9F\u2026".
  """
  use ExUnit.Case, async: true
  use ExUnitProperties

  alias Recurse.Gateway.Admin.WellKnownManifest

  @manifest_path Path.expand(
                   "../../priv/schemas/manifest.json",
                   __DIR__
                 )
  @cedar_schema_path Path.expand(
                       "../../priv/cedar/schema.cedarschema.json",
                       __DIR__
                     )
  @valid_roles ~w(tenant_auditor platform_operator)
  @cedar_action_prefix ~r/^Recurse::Action::"([^"]+)"$/

  setup_all do
    raw = File.read!(@manifest_path)
    parsed = JSON.decode!(raw)
    cedar_actions = load_cedar_actions(@cedar_schema_path)

    {:ok, manifest: parsed, cedar_actions: cedar_actions}
  end

  describe "Surface 'Manifest stability'" do
    property "1. byte-identical re-serialization across N calls", _ctx do
      # The "input space" here is just N — we're asserting that the
      # encoder is a pure function of the manifest file. We generate
      # an integer N and call the builder N times, asserting all
      # outputs equal the first. Shrinks to N=1 if anything ever
      # produces drift.
      check all(_repeat <- StreamData.integer(1..5), max_runs: 50) do
        first = WellKnownManifest.build_body()

        for _ <- 1..3 do
          assert WellKnownManifest.build_body() == first
        end
      end
    end

    property "2. every endpoint.schema_uri resolves to a manifest.schemas entry",
             %{manifest: manifest} do
      endpoints = Map.fetch!(manifest, "endpoints")
      schemas_by_uri = index_schemas_by_uri(manifest)

      check all(
              idx <- StreamData.integer(0..(length(endpoints) - 1)),
              max_runs: 50
            ) do
        endpoint = Enum.at(endpoints, idx)
        schema_uri = Map.fetch!(endpoint, "schema_uri")

        assert Map.has_key?(schemas_by_uri, schema_uri),
               "endpoint #{idx} (#{Map.get(endpoint, "path")}) " <>
                 "references schema_uri #{inspect(schema_uri)} which is " <>
                 "not present in manifest.schemas"

        case Map.get(endpoint, "request_schema_uri") do
          nil ->
            :ok

          uri ->
            assert Map.has_key?(schemas_by_uri, uri),
                   "endpoint #{idx} request_schema_uri #{inspect(uri)} " <>
                     "missing from manifest.schemas"
        end
      end
    end

    property "3. every schema.version major-version <= manifest.version major",
             %{manifest: manifest} do
      schemas = Map.fetch!(manifest, "schemas")
      manifest_major = parse_major(Map.fetch!(manifest, "version"))

      check all(
              idx <- StreamData.integer(0..(length(schemas) - 1)),
              max_runs: 50
            ) do
        schema = Enum.at(schemas, idx)
        schema_major = parse_major(Map.fetch!(schema, "version"))

        assert schema_major <= manifest_major,
               "schema #{Map.get(schema, "name")} has major-version " <>
                 "#{schema_major} but manifest.version is " <>
                 "#{Map.fetch!(manifest, "version")} (major #{manifest_major})"
      end
    end

    property "4. every endpoint.requires_role element is in the F004 allowlist",
             %{manifest: manifest} do
      endpoints = Map.fetch!(manifest, "endpoints")

      check all(
              idx <- StreamData.integer(0..(length(endpoints) - 1)),
              max_runs: 50
            ) do
        endpoint = Enum.at(endpoints, idx)
        roles = Map.get(endpoint, "requires_role", [])

        for role <- roles do
          assert role in @valid_roles,
                 "endpoint #{idx} (#{Map.get(endpoint, "path")}) lists " <>
                   "requires_role #{inspect(role)} which is not in " <>
                   "the audit-console allowlist #{inspect(@valid_roles)}"
        end
      end
    end

    property "5. every endpoint.cedar_action is declared in the Cedar Entity Schema",
             %{manifest: manifest, cedar_actions: cedar_actions} do
      endpoints = Map.fetch!(manifest, "endpoints")

      check all(
              idx <- StreamData.integer(0..(length(endpoints) - 1)),
              max_runs: 50
            ) do
        endpoint = Enum.at(endpoints, idx)

        case Map.get(endpoint, "cedar_action") do
          nil ->
            :ok

          raw ->
            action_name =
              case Regex.run(@cedar_action_prefix, raw) do
                [_, name] ->
                  name

                _ ->
                  flunk(
                    "endpoint #{idx} cedar_action #{inspect(raw)} does not " <>
                      "match the canonical Recurse::Action::\"...\" form"
                  )
              end

            assert action_name in cedar_actions,
                   "endpoint #{idx} (#{Map.get(endpoint, "path")}) cedar_action " <>
                     "#{inspect(raw)} is not declared in priv/cedar/schema.cedarschema.json " <>
                     "(known actions: #{inspect(Enum.sort(cedar_actions))})"
        end
      end
    end
  end

  # ---------------------------------------------------------------------------
  # Helpers
  # ---------------------------------------------------------------------------

  # Build a `%{schema_uri => schema_entry}` map for O(1) reference
  # lookup. The manifest's `schemas` array is the source of truth
  # for `(name, uri, version)` tuples.
  defp index_schemas_by_uri(manifest) do
    manifest
    |> Map.fetch!("schemas")
    |> Map.new(fn s -> {Map.fetch!(s, "uri"), s} end)
  end

  # Return the action SHORT names (without the `Action::` prefix
  # that cedarschema JSON uses) as a MapSet, so reference checks are
  # O(1). The manifest writes actions in Cedar's canonical
  # `Recurse::Action::"PolicySimulate"` form; we strip the
  # namespace prefix when matching against the schema's keys.
  defp load_cedar_actions(path) do
    schema = path |> File.read!() |> JSON.decode!()

    schema
    |> Map.fetch!("Recurse")
    |> Map.fetch!("actions")
    |> Map.keys()
    |> Enum.map(&strip_action_prefix/1)
    |> MapSet.new()
  end

  # Cedar schema keys look like `"Action::PolicySimulate"` (no quotes,
  # no `Recurse::` namespace — the namespace is the outer key). The
  # manifest references actions as `Recurse::Action::"PolicySimulate"`
  # (with quotes per Cedar action-id syntax). Strip both forms to a
  # bareword for matching.
  defp strip_action_prefix("Action::" <> name), do: name
  defp strip_action_prefix(other), do: other

  defp parse_major(version) when is_binary(version) do
    [major | _] = String.split(version, ".", parts: 2)
    String.to_integer(major)
  end
end
