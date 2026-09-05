defmodule Recurse.Gateway.Router.ReleaseSurfaceTest do
  use ExUnit.Case, async: false

  alias Recurse.Gateway.Policy.Active
  alias Recurse.Gateway.PolicyBundleRef
  alias Recurse.Gateway.ProviderRegistry
  alias Recurse.Gateway.Router
  alias Recurse.Gateway.Test.JwtTestHelper
  alias Recurse.Gateway.Test.Mocks
  alias Recurse.Providers.Impls.PostgresMerkleLedger.Schemas.Attestation
  alias Recurse.Providers.Repo

  setup_all do
    Recurse.Gateway.Test.KernelFixture.boot()
  end

  setup do
    :ok = Ecto.Adapters.SQL.Sandbox.checkout(Repo)
    source = "permit(principal, action, resource);"
    hash = Recurse.Cedar.canonical_hash(source)

    :ok =
      Active.update(%Active{
        source: :filesystem,
        source_ref: "release-surface-test",
        loaded_at: DateTime.utc_now(),
        bundle: %PolicyBundleRef{
          bundle_id: Base.encode16(hash, case: :lower),
          canonical_hash: hash,
          loaded_at: DateTime.utc_now(),
          evaluator_handle: source,
          bundle_bytes: source
        }
      })

    # No expectations: any provider dispatch is an unexpected Mox call.
    ProviderRegistry.install_raw!(%{
      llm: {Mocks.LLMProvider, %{}},
      ledger: {Mocks.LedgerProvider, %{}},
      storage: {Mocks.StorageProvider, %{}},
      secrets: {Mocks.SecretsProvider, %{}},
      tenant_id: "01HQZN5K7J8M9N0P1Q2R3S4T5V",
      signer: "observed://gateway/test"
    })

    previous = Application.get_env(:recurse_gateway, :jwt_validator_opts)

    Application.put_env(:recurse_gateway, :jwt_validator_opts,
      audience: "recurse-gateway-test",
      issuer: "https://test-broker.example.invalid",
      known_kids: [{"test-key-rs256", JwtTestHelper.public_jwk(:rs256)}]
    )

    on_exit(fn ->
      ProviderRegistry.uninstall()

      if previous,
        do: Application.put_env(:recurse_gateway, :jwt_validator_opts, previous),
        else: Application.delete_env(:recurse_gateway, :jwt_validator_opts)
    end)

    :ok
  end

  for path <- ["/v1/chat/completions", "/v1/chat/messages", "/v1/mcp/example/tools/execute"],
      stream <- [false, true] do
    test "#{path} stream=#{stream} refuses with ready admission and no execution" do
      before_events = R5e.Log.read_events()
      before_receipts = Repo.aggregate(Attestation, :count)
      jwt = JwtTestHelper.mint_test_jwt(recurse_role: "platform_operator")

      conn =
        Plug.Test.conn(
          :post,
          unquote(path),
          JSON.encode!(%{
            "model" => "test",
            "messages" => [],
            "content" => "hello",
            "stream" => unquote(stream)
          })
        )
        |> Plug.Conn.put_req_header("content-type", "application/json")
        |> Plug.Conn.put_req_header("authorization", "Bearer " <> jwt)
        |> Router.call(Router.init([]))

      assert conn.status == 503
      assert conn.halted
      assert %{"error" => %{"code" => "capability_unavailable"}} = JSON.decode!(conn.resp_body)
      assert R5e.Log.read_events() == before_events
      assert Repo.aggregate(Attestation, :count) == before_receipts
    end
  end
end
