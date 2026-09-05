defmodule Recurse.SpiffeTest do
  # Smoke test for the SPIFFE Rustler NIF pipeline. Phase-1 scope is
  # intentionally minimal: just confirm the NIF loads and returns the
  # expected shell value. Full Workload API integration tests land in
  # Feature 002+ alongside the Gateway's ingress path (FR-025).
  #
  # Added per speckit-pr-review iteration-3 F002 — the recurse_spiffe
  # crate was orphaned (no Elixir caller, no test, no CI coverage)
  # before this.
  use ExUnit.Case, async: true

  alias Recurse.Spiffe

  test "fetch_x509_svid/0 returns :not_implemented tag in Phase 1" do
    assert {:not_implemented, :phase_2_plus} = Spiffe.fetch_x509_svid()
  end
end
