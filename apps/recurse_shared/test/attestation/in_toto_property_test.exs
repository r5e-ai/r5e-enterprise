defmodule Recurse.Shared.Attestation.InTotoPropertyTest do
  use ExUnit.Case, async: true
  use ExUnitProperties

  alias Recurse.Shared.Attestation.SignedPredicate
  alias Recurse.Shared.Jcs

  # The in-toto v1.0 predicate payload is the map-shaped predicate we
  # eventually wrap inside DSSE. JCS canonicalization must be stable
  # across key-order perturbation and idempotent across re-encoding.
  # Reference: in-toto v1.0 spec, RFC 8785.

  describe "in-toto predicate JCS canonicalization" do
    property "key-order perturbation produces identical bytes" do
      check all(predicate <- predicate_gen()) do
        canonical = Jcs.encode(predicate)

        reversed =
          predicate
          |> Map.to_list()
          |> Enum.reverse()
          |> Map.new()

        assert Jcs.encode(reversed) == canonical
      end
    end

    property "encoding is idempotent under decode/re-encode" do
      check all(predicate <- predicate_gen()) do
        canonical = Jcs.encode(predicate)
        decoded = :json.decode(canonical)
        assert Jcs.encode(decoded) == canonical
      end
    end

    property "nested-map key order does not affect output" do
      check all(predicate <- nested_predicate_gen()) do
        canonical = Jcs.encode(predicate)

        # Perturb: reverse top-level keys + reverse the nested principal
        # map's keys. machine_identity and principal are FLAT siblings
        # per attestation.schema.json#/$defs/RecursePredicate (iteration-2
        # F002 fix on PR #1); the test tracks that shape so it catches
        # regressions if the struct/schema drift again.
        perturbed =
          predicate
          |> Map.update!("principal", fn m ->
            m |> Map.to_list() |> Enum.reverse() |> Map.new()
          end)
          |> Map.to_list()
          |> Enum.reverse()
          |> Map.new()

        assert Jcs.encode(perturbed) == canonical
      end
    end
  end

  # --- generators ---

  defp safe_string, do: StreamData.string(:alphanumeric, min_length: 1, max_length: 16)

  # Read the canonical event_kind list dynamically from
  # `SignedPredicate.event_kinds/0` so this generator automatically
  # extends as new atoms (e.g. `:ui_mcp_quarantine`) are added. This
  # is the F006 fix: previously the list was hardcoded with the F002
  # base 5 atoms only and silently excluded every `:ui_*` and `:mcp_*`
  # surface from canonicalization round-trip coverage. Computed at
  # module-compile time so it is part of the generator's static shape;
  # if the canonical list grows the test recompiles and the new atoms
  # are picked up automatically.
  @event_kind_strings Enum.map(SignedPredicate.event_kinds(), &Atom.to_string/1)

  defp predicate_gen do
    gen all(
          run_id <- safe_string(),
          step_id <- safe_string(),
          session_id <- safe_string(),
          timestamp <- safe_string(),
          tenant_id <- safe_string(),
          event_kind <- StreamData.member_of(@event_kind_strings)
        ) do
      %{
        "envelope_version" => "1.0",
        "run_id" => run_id,
        "step_id" => step_id,
        "session_id" => session_id,
        "session_chain_position" => 0,
        "event_kind" => event_kind,
        "timestamp" => timestamp,
        "tenant_id" => tenant_id
      }
    end
  end

  defp nested_predicate_gen do
    gen all(
          base <- predicate_gen(),
          machine <- safe_string(),
          principal_issuer <- safe_string()
        ) do
      # machine_identity + principal are FLAT top-level siblings per
      # attestation.schema.json (iteration-2 F002 fix). Previous test
      # used nested identities.{machine, principal} and would have
      # masked regressions in the flat-shape canonicalization path.
      base
      |> Map.put("machine_identity", %{"spiffe_id" => "spiffe://x/" <> machine})
      |> Map.put("principal", %{
        "kind" => "obo_human",
        "schema_version" => "1.0",
        "issuer" => principal_issuer,
        "subject" => "alice"
      })
    end
  end
end
