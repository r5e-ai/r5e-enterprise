defmodule Recurse.Shared.PrincipalPropertyTest do
  use ExUnit.Case, async: true
  use ExUnitProperties

  alias Recurse.Shared.{Jcs, Principal}

  describe "canonical_form/1" do
    property "obo_human: decoded JSON equals to_map output" do
      check all(attrs <- obo_human_attrs()) do
        p = Principal.obo_human(attrs)
        bytes = Principal.canonical_form(p)
        decoded = :json.decode(bytes)
        assert decoded == Principal.to_map(p)
      end
    end

    property "service_account: decoded JSON equals to_map output" do
      check all(attrs <- service_account_attrs()) do
        p = Principal.service_account(attrs)
        bytes = Principal.canonical_form(p)
        decoded = :json.decode(bytes)
        assert decoded == Principal.to_map(p)
      end
    end

    property "autonomous: decoded JSON equals to_map output" do
      check all(attrs <- autonomous_attrs()) do
        p = Principal.autonomous(attrs)
        bytes = Principal.canonical_form(p)
        decoded = :json.decode(bytes)
        assert decoded == Principal.to_map(p)
      end
    end

    property "JCS output is byte-stable across key-order perturbation" do
      check all(attrs <- obo_human_attrs()) do
        p = Principal.obo_human(attrs)
        canonical = Principal.canonical_form(p)

        # Perturb the map by reconstructing it key-by-key in reverse order —
        # Map.new with reversed pairs produces a map with the same key set
        # but a potentially different internal ordering. JCS must flatten.
        shuffled =
          p
          |> Principal.to_map()
          |> Map.to_list()
          |> Enum.reverse()
          |> Map.new()

        assert Jcs.encode(shuffled) == canonical
      end
    end
  end

  # --- generators ---

  defp safe_string do
    StreamData.string(:alphanumeric, min_length: 1, max_length: 32)
  end

  defp safe_list do
    StreamData.list_of(safe_string(), max_length: 4)
  end

  defp obo_human_attrs do
    gen all(
          issuer <- safe_string(),
          subject <- safe_string(),
          display_name <- StreamData.one_of([StreamData.constant(nil), safe_string()]),
          groups <- StreamData.one_of([StreamData.constant(nil), safe_list()])
        ) do
      %{issuer: issuer, subject: subject, display_name: display_name, groups: groups}
    end
  end

  defp service_account_attrs do
    gen all(
          issuer <- safe_string(),
          account_id <- safe_string(),
          scope <- StreamData.one_of([StreamData.constant(nil), safe_list()])
        ) do
      %{issuer: issuer, account_id: account_id, scope: scope}
    end
  end

  defp autonomous_attrs do
    gen all(spiffe_id <- safe_string()) do
      %{spiffe_id: "spiffe://example.org/" <> spiffe_id}
    end
  end
end
