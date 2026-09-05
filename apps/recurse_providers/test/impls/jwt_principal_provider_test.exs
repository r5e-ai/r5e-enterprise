defmodule Recurse.Providers.Impls.JwtPrincipalProviderTest do
  @moduledoc """
  Contract tests for `Recurse.Providers.Impls.JwtPrincipalProvider` (F002 T044).

  T044 wires the provider to `Recurse.Gateway.Identity.JwtValidator` via
  the `:jwt_validator_module` application env. Tests that don't care
  about real JWTs inject a stub validator module to isolate the
  principal-extraction path.
  """

  use ExUnit.Case, async: false

  alias Recurse.Providers.Impls.JwtPrincipalProvider
  alias Recurse.Shared.Principal

  defmodule StubValidator do
    @moduledoc false
    # The stub validator echoes what the test registers in
    # `:persistent_term`. Each test key is scoped by the raw_token so
    # tests can register multiple canned responses if needed.
    def validate(raw_token, _opts) do
      :persistent_term.get({__MODULE__, raw_token}, {:error, :unknown_token_in_stub})
    end

    def stub(raw_token, result),
      do: :persistent_term.put({__MODULE__, raw_token}, result)

    def reset do
      for {key, _} <- :persistent_term.get(),
          match?({__MODULE__, _}, key),
          do: :persistent_term.erase(key)

      :ok
    end
  end

  setup do
    previous = Application.get_env(:recurse_providers, :jwt_validator_module)
    Application.put_env(:recurse_providers, :jwt_validator_module, StubValidator)

    on_exit(fn ->
      StubValidator.reset()

      if previous do
        Application.put_env(:recurse_providers, :jwt_validator_module, previous)
      else
        Application.delete_env(:recurse_providers, :jwt_validator_module)
      end
    end)

    {:ok, state} =
      JwtPrincipalProvider.init(%{
        trusted_issuers: ["https://broker.recurse.test"],
        expected_audience: "recurse-gateway",
        known_kids: [{"kid-1", %{"kid" => "kid-1"}}]
      })

    %{state: state}
  end

  describe "init/1" do
    test "returns {:ok, state} with config carried through", %{state: state} do
      assert %{
               trusted_issuers: ["https://broker.recurse.test"],
               expected_audience: "recurse-gateway"
             } = state
    end

    test "rejects config missing :trusted_issuers" do
      assert {:error, :missing_trusted_issuers} =
               JwtPrincipalProvider.init(%{expected_audience: "recurse-gateway"})
    end

    test "rejects config missing :expected_audience" do
      assert {:error, :missing_expected_audience} =
               JwtPrincipalProvider.init(%{trusted_issuers: ["https://broker.recurse.test"]})
    end
  end

  describe "validate/3" do
    test "returns {:ok, %Principal{}} for a valid JWT (obo_human)", %{state: state} do
      token = "jwt.obo_human.valid"

      StubValidator.stub(
        token,
        {:ok,
         %{
           "iss" => "https://broker.recurse.test",
           "sub" => "user-1",
           "principal" => %{
             "kind" => "obo_human",
             "issuer" => "https://broker.recurse.test",
             "subject" => "user-1",
             "display_name" => "Alice",
             "groups" => ["engineering"],
             "recurse_role" => "platform_operator"
           }
         }}
      )

      assert {:ok, %Principal{kind: :obo_human, subject: "user-1", display_name: "Alice"}} =
               JwtPrincipalProvider.validate(state, token, "recurse-gateway")
    end

    test "returns {:ok, %Principal{}} for service_account", %{state: state} do
      token = "jwt.service_account.valid"

      StubValidator.stub(
        token,
        {:ok,
         %{
           "iss" => "https://broker.recurse.test",
           "sub" => "svc-1",
           "principal" => %{
             "kind" => "service_account",
             "issuer" => "https://broker.recurse.test",
             "account_id" => "svc-1",
             "scope" => ["read", "write"]
           }
         }}
      )

      assert {:ok, %Principal{kind: :service_account, account_id: "svc-1"}} =
               JwtPrincipalProvider.validate(state, token, "recurse-gateway")
    end

    test "returns {:error, :expired} when validator reports :token_expired", %{state: state} do
      token = "jwt.expired"
      StubValidator.stub(token, {:error, :token_expired})

      assert {:error, :expired} =
               JwtPrincipalProvider.validate(state, token, "recurse-gateway")
    end

    test "returns {:error, :invalid_signature} for tampered JWT", %{state: state} do
      token = "jwt.tampered"
      StubValidator.stub(token, {:error, :invalid_signature})

      assert {:error, :invalid_signature} =
               JwtPrincipalProvider.validate(state, token, "recurse-gateway")
    end

    test "returns {:error, :wrong_audience} for validator :invalid_audience", %{state: state} do
      token = "jwt.bad_aud"
      StubValidator.stub(token, {:error, :invalid_audience})

      assert {:error, :wrong_audience} =
               JwtPrincipalProvider.validate(state, token, "recurse-gateway")
    end

    test "rejects issuer outside the trusted_issuers allowlist with :wrong_issuer", %{
      state: state
    } do
      token = "jwt.bad_iss"

      StubValidator.stub(
        token,
        {:ok,
         %{
           "iss" => "https://imposter.example",
           "sub" => "user-1",
           "principal" => %{
             "kind" => "obo_human",
             "issuer" => "https://imposter.example",
             "subject" => "user-1"
           }
         }}
      )

      assert {:error, :wrong_issuer} =
               JwtPrincipalProvider.validate(state, token, "recurse-gateway")
    end

    test "returns :malformed_principal when principal claim shape is wrong", %{state: state} do
      token = "jwt.bad_principal"

      StubValidator.stub(
        token,
        {:ok,
         %{
           "iss" => "https://broker.recurse.test",
           "sub" => "user-1",
           "principal" => %{"kind" => "obo_human"}
         }}
      )

      assert {:error, :malformed_principal} =
               JwtPrincipalProvider.validate(state, token, "recurse-gateway")
    end
  end

  describe "inspect_kind/2" do
    test "returns {:ok, kind} by peeking at the payload" do
      # Hand-craft a JWT whose payload advertises principal.kind = obo_human.
      # No signature check — inspect_kind/2 never verifies.
      payload =
        %{"principal" => %{"kind" => "obo_human"}}
        |> JSON.encode!()
        |> Base.url_encode64(padding: false)

      token = "header." <> payload <> ".sig"

      {:ok, state} =
        JwtPrincipalProvider.init(%{
          trusted_issuers: ["x"],
          expected_audience: "y"
        })

      assert {:ok, :obo_human} = JwtPrincipalProvider.inspect_kind(state, token)
    end

    test "returns {:error, :malformed_token} for garbled input" do
      {:ok, state} =
        JwtPrincipalProvider.init(%{
          trusted_issuers: ["x"],
          expected_audience: "y"
        })

      assert {:error, :malformed_token} =
               JwtPrincipalProvider.inspect_kind(state, "not a jwt")
    end
  end

  describe "supports_rfc8693?/1" do
    test "returns false permanently in F002 Standalone Gateway", %{state: state} do
      refute JwtPrincipalProvider.supports_rfc8693?(state)
    end
  end

  describe "capabilities/1" do
    test "advertises obo_human + service_account + autonomous", %{state: state} do
      caps = JwtPrincipalProvider.capabilities(state)
      assert :obo_human in caps
      assert :service_account in caps
      assert :autonomous in caps
    end
  end

  describe "healthcheck/1" do
    test "reports {:degraded, :no_cache} when known_kids is a static list", %{state: state} do
      assert {:degraded, :no_cache} = JwtPrincipalProvider.healthcheck(state)
    end

    test "reports :ok when configured cache module is alive" do
      # Spawn a local process under a known name and claim it's the cache.
      # `Process.whereis/1` returns the pid, which is truthy.
      # credo:disable-for-next-line Credo.Check.Warning.UnsafeToAtom
      name = :"jwt_principal_cache_#{System.unique_integer([:positive])}"
      Process.register(self(), name)

      {:ok, state} =
        JwtPrincipalProvider.init(%{
          trusted_issuers: ["x"],
          expected_audience: "y",
          known_kids: {:cache, name}
        })

      assert :ok = JwtPrincipalProvider.healthcheck(state)
    end

    test "reports {:down, :cache_not_running} when configured cache module is absent" do
      {:ok, state} =
        JwtPrincipalProvider.init(%{
          trusted_issuers: ["x"],
          expected_audience: "y",
          known_kids: {:cache, :nonexistent_cache_module_xyz}
        })

      assert {:down, :cache_not_running} = JwtPrincipalProvider.healthcheck(state)
    end
  end

  describe "terminate/2" do
    test "returns :ok", %{state: state} do
      assert :ok = JwtPrincipalProvider.terminate(state, :normal)
    end
  end
end
