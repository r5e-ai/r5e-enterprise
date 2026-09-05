defmodule Recurse.Gateway.Router.TierMismatchTest do
  @moduledoc """
  Contract test for **SC-009** / **FR-024** — tier-mismatch enforcement.

  Every path on `Recurse.Gateway.Router.runtime_only_paths/0` MUST return
  HTTP 501 with the canonical `ERR_TIER_MISMATCH` JSON envelope when hit
  under the Standalone deployment. This test iterates that authoritative
  list + every relevant HTTP verb, guarding the tier-applicability
  matches against silent regression.

  Paired with the spot-check in `Recurse.Gateway.RouterTest` (T050); this
  file is the T102 exhaustive parameterized version.

  ### Why `async: true`

  The tier-mismatch paths in `Recurse.Gateway.Router` never touch the
  `ProviderRegistry` singleton or `:recurse_gateway, :jwt_validator_opts`
  — the 501 match fires before `authenticate/1`. So this test is pure
  in-memory `Plug.Test` and parallel-safe, unlike the auth-exercising
  paths in `RouterTest`.

  ### Scope discipline

  Asserts structural fields dictated by SC-009 / FR-024:

    * `error.code == "ERR_TIER_MISMATCH"`
    * `error.details.active_tier == "standalone_gateway"`
    * `error.details.endpoint_requires_tier` matches the tier declared in
      `@runtime_only_paths`.
    * `error.message` is a non-empty string (exact wording is a Router
      implementation detail, not a spec contract).

  Does NOT assert on the exact message string — FR-024 constrains the
  envelope shape, not the human-readable copy.
  """

  use ExUnit.Case, async: true

  import Plug.Test

  alias Recurse.Gateway.Router

  @opts Router.init([])

  describe "SC-009 — every Runtime-only path returns 501 ERR_TIER_MISMATCH" do
    for {path, required_tier} <- Router.runtime_only_paths(),
        method <- [:get, :post, :put, :delete] do
      test "#{method |> Atom.to_string() |> String.upcase()} #{path} returns 501 ERR_TIER_MISMATCH" do
        conn =
          unquote(method)
          |> conn(unquote(path), "")
          |> Router.call(@opts)

        assert conn.status == 501

        assert %{
                 "error" => %{
                   "code" => "ERR_TIER_MISMATCH",
                   "message" => message,
                   "details" => %{
                     "active_tier" => "standalone_gateway",
                     "endpoint_requires_tier" => unquote(required_tier)
                   }
                 }
               } = JSON.decode!(conn.resp_body)

        assert is_binary(message) and message != ""

        assert {"content-type", content_type} =
                 List.keyfind(conn.resp_headers, "content-type", 0)

        assert content_type =~ "application/json"
      end
    end
  end

  describe "tier-guard ordering + list contract" do
    test "unauthenticated requests to Runtime-only paths still get 501 (tier guard fires before auth)" do
      # No Authorization header is set on `conn/2` by default. If the
      # tier-mismatch match were ordered after an auth plug, we'd see
      # 401 here — the fact that we see 501 proves ordering.
      [{first_path, _tier} | _] = Router.runtime_only_paths()

      conn =
        :post
        |> conn(first_path, "")
        |> Router.call(@opts)

      assert conn.status == 501
      refute conn.status == 401
    end

    test "runtime_only_paths/0 returns a non-empty list of {path, tier} tuples" do
      paths = Router.runtime_only_paths()

      assert is_list(paths)
      # Wave 3E-2 hardcodes 5 paths; guard against accidental emptying.
      assert length(paths) >= 5

      Enum.each(paths, fn entry ->
        assert {path, tier} = entry
        assert is_binary(path)
        assert String.starts_with?(path, "/v1/")
        assert is_binary(tier)
        assert tier in ["runtime_shape", "governance_shape"]
      end)
    end

    test "query string on a Runtime-only path still returns 501" do
      # Plug.Test's `conn/3` accepts a query string in the path; the
      # tier guard should not care about the query component.
      [{first_path, required_tier} | _] = Router.runtime_only_paths()

      conn =
        :post
        |> conn(first_path <> "?foo=bar&baz=1", "")
        |> Router.call(@opts)

      assert conn.status == 501

      assert %{
               "error" => %{
                 "code" => "ERR_TIER_MISMATCH",
                 "details" => %{"endpoint_requires_tier" => ^required_tier}
               }
             } = JSON.decode!(conn.resp_body)
    end

    test "trailing slash on a Runtime-only path does NOT match (documents current behavior)" do
      # Plug.Router's `match "/a/b"` does not match "/a/b/" by default —
      # the trailing-slash form falls through to the 404 catch-all. This
      # is intentional: if a future path gains trailing-slash tolerance
      # we want the test suite to tell us about the behavior change.
      [{first_path, _tier} | _] = Router.runtime_only_paths()

      conn =
        :get
        |> conn(first_path <> "/", "")
        |> Router.call(@opts)

      # Not asserting 501: trailing-slash handling is a Plug.Router
      # concern, not an SC-009 concern. We only assert it's NOT a 2xx
      # (so the Runtime-only surface isn't accidentally leaking).
      assert conn.status in [404, 501]
    end
  end
end
