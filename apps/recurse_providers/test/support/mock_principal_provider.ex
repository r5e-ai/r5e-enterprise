defmodule Recurse.Providers.Support.MockPrincipalProvider do
  @moduledoc """
  Fixed-data stub implementation of `Recurse.Providers.PrincipalProvider`
  (T067).

  Handles all three principal kinds (`:obo_human`, `:service_account`,
  `:autonomous`) by routing on a prefix of the raw token:

    * `"mock-obo:"<subject>` → `:obo_human`
    * `"mock-sa:"<account_id>` → `:service_account`
    * `"mock-auto:"<spiffe_id>` → `:autonomous`

  Advertises `supports_rfc8693?/1 = true` so the composition-with-
  `SecretsProvider` path (FR-047) is covered by the harness.
  """

  @behaviour Recurse.Providers.PrincipalProvider

  alias Recurse.Shared.Principal

  @impl true
  def init(_config), do: {:ok, %{issuer: "https://mock-idp.recurse.test"}}

  @impl true
  def validate(_state, token, _audience) when is_binary(token) do
    case inspect_kind_internal(token) do
      {:ok, :obo_human} ->
        subject = strip_prefix(token, "mock-obo:")

        {:ok,
         Principal.obo_human(%{
           issuer: "https://mock-idp.recurse.test",
           subject: subject,
           display_name: "Mock User #{subject}"
         })}

      {:ok, :service_account} ->
        account_id = strip_prefix(token, "mock-sa:")

        {:ok,
         Principal.service_account(%{
           issuer: "https://mock-idp.recurse.test",
           account_id: account_id,
           scope: ["llm:chat", "tools:mock"]
         })}

      {:ok, :autonomous} ->
        spiffe_id = strip_prefix(token, "mock-auto:")
        {:ok, Principal.autonomous(%{spiffe_id: spiffe_id})}

      _ ->
        {:error, :invalid_signature}
    end
  end

  @impl true
  def inspect_kind(_state, token) when is_binary(token), do: inspect_kind_internal(token)

  @impl true
  def supports_rfc8693?(_state), do: true

  @impl true
  def capabilities(_state),
    do: [:obo_human, :service_account, :autonomous, :rfc8693_exchange]

  @impl true
  def healthcheck(_state), do: :ok

  @impl true
  def terminate(_state, _reason), do: :ok

  defp inspect_kind_internal("mock-obo:" <> _), do: {:ok, :obo_human}
  defp inspect_kind_internal("mock-sa:" <> _), do: {:ok, :service_account}
  defp inspect_kind_internal("mock-auto:" <> _), do: {:ok, :autonomous}
  defp inspect_kind_internal(_), do: {:error, :unknown_kind}

  defp strip_prefix(token, prefix), do: String.replace_prefix(token, prefix, "")
end
