defmodule Recurse.Gateway.Property.F004SurfacesSkeletonTest do
  @moduledoc """
  F004 property-test surface catalog skeleton (T055).

  Per `contracts/property_test_surface_catalog_f004.md`, F004 introduces:

    * Surface T — Blast Radius classifier correctness (owned by Phase 5,
      task T081). Placeholder skipped here; real impl at
      `apps/recurse_gateway/test/admin/blast_radius_property_test.exs`.
    * Surface U — Heuristic suggestion engine determinism (owned by
      Phase 7, task T121). Placeholder skipped; real impl at
      `apps/recurse_gateway/test/suggestion_engine/heuristic_property_test.exs`.
    * Surface V — Browser session cookie integrity (owned by THIS task
      group, T032). Real impl at
      `apps/recurse_gateway/test/admin/browser_session_plug_property_test.exs`.
      The placeholder here ASSERTS that the
      `Recurse.Gateway.Admin.BrowserSessionPlug` module is loaded as a
      sentinel — fails CI if T034's module disappears.
    * Manifest stability surface — owned by Phase 2 W2-B (T040).
      Placeholder skipped.
    * Audit-agent tool contracts (six) — owned by Phase 6 (T099–T104).
      Six placeholders skipped, one per tool.

  ## Why this skeleton exists

  Per `feedback_invoke_elixir_skills.md` + `elixir:stream-data-thinking`,
  property-test surfaces should be tracked as a single catalog so a
  reader can see at a glance which surfaces exist + which task owns
  each. The pending skeletons are the contract-level fingerprint: when
  Phase 5 lands T081, that task's PR removes the `:pending` tag below
  AND replaces the placeholder with a real assertion. Same for every
  other surface.

  Default `mix test` runs skip the pending placeholders (see
  `test_helper.exs` `ExUnit.start(exclude: [:pending, ...])`). Opt in
  with `mix test --include pending` to verify the skeleton.

  Mirrors the F002 surface skeleton pattern (which T028 spec'd but
  was not actually authored as a single-file skeleton in F002 — F004
  introduces the convention).

  ## Cross-references

    * `specs/004-audit-console/contracts/property_test_surface_catalog_f004.md`
    * `apps/recurse_gateway/test/admin/browser_session_plug_property_test.exs` (T032 — Surface V real impl)
  """
  use ExUnit.Case, async: true

  describe "Surface V — Browser session cookie integrity (T032 owns)" do
    test "BrowserSessionPlug module is loaded (sentinel)" do
      # The real property test lives at
      # `apps/recurse_gateway/test/admin/browser_session_plug_property_test.exs`.
      # This sentinel guards against accidental removal of the plug
      # module — if BrowserSessionPlug vanishes, this test fails before
      # the real surface test even runs.
      Code.ensure_loaded!(Recurse.Gateway.Admin.BrowserSessionPlug)

      assert function_exported?(
               Recurse.Gateway.Admin.BrowserSessionPlug,
               :encrypt_payload,
               2
             )

      assert function_exported?(
               Recurse.Gateway.Admin.BrowserSessionPlug,
               :decrypt_cookie,
               2
             )
    end
  end

  describe "Surface T — Blast Radius classifier correctness (T081 owns; Phase 5)" do
    @tag :pending
    test "placeholder — see T081" do
      flunk("Surface T property test owned by T081 (Phase 5).")
    end
  end

  describe "Surface U — Heuristic suggestion determinism (T121 owns; Phase 7)" do
    @tag :pending
    test "placeholder — see T121" do
      flunk("Surface U property test owned by T121 (Phase 7).")
    end
  end

  describe "Manifest stability surface (T040 owns; Phase 2 W2-B)" do
    @tag :pending
    test "placeholder — see T040" do
      flunk("Manifest stability surface owned by T040 (Wave 2B).")
    end
  end

  describe "Audit-agent tool contract — query_receipts (T099 owns; Phase 6)" do
    @tag :pending
    test "placeholder — see T099" do
      flunk("query_receipts tool contract owned by T099 (Phase 6).")
    end
  end

  describe "Audit-agent tool contract — fetch_receipt_detail (T100 owns; Phase 6)" do
    @tag :pending
    test "placeholder — see T100" do
      flunk("fetch_receipt_detail tool contract owned by T100 (Phase 6).")
    end
  end

  describe "Audit-agent tool contract — explain_denial (T101 owns; Phase 6)" do
    @tag :pending
    test "placeholder — see T101" do
      flunk("explain_denial tool contract owned by T101 (Phase 6).")
    end
  end

  describe "Audit-agent tool contract — find_similar_receipts (T102 owns; Phase 6)" do
    @tag :pending
    test "placeholder — see T102" do
      flunk("find_similar_receipts tool contract owned by T102 (Phase 6).")
    end
  end

  describe "Audit-agent tool contract — simulate_policy_dryrun (T103 owns; Phase 6)" do
    @tag :pending
    test "placeholder — see T103" do
      flunk("simulate_policy_dryrun tool contract owned by T103 (Phase 6).")
    end
  end

  describe "Audit-agent tool contract — suggest_policy_pattern (T104 owns; Phase 6)" do
    @tag :pending
    test "placeholder — see T104" do
      flunk("suggest_policy_pattern tool contract owned by T104 (Phase 6).")
    end
  end
end
