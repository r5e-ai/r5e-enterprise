defmodule Recurse.Providers.Support.MockIdentityProvider do
  @moduledoc """
  Fixed-data stub implementation of `Recurse.Providers.IdentityProvider`
  (T066).

  Returns canonical SPIFFE SVID material for trust domain
  `mock.recurse.test`. The "X.509 SVID" is not cryptographically valid —
  it is a DER-shaped byte blob the harness uses only for structural
  assertions. Real SPIRE workload-API / federated impls ship in Feature
  002+ per Phase-1 research recommendation 3.
  """

  @behaviour Recurse.Providers.IdentityProvider

  @trust_domain "mock.recurse.test"
  @spiffe_id "spiffe://#{@trust_domain}/workload/mock"

  @impl true
  def init(_config), do: {:ok, %{trust_domain: @trust_domain}}

  @impl true
  def fetch_x509_svid(_state) do
    {:ok,
     %{
       cert_chain: [<<0x30, 0x82, 0x01, 0x00>> <> :crypto.strong_rand_bytes(64)],
       private_key: <<0x30, 0x81, 0x80>> <> :crypto.strong_rand_bytes(48),
       expires_at: DateTime.add(DateTime.utc_now(), 3600, :second)
     }}
  end

  @impl true
  def fetch_jwt_svid(_state, audience) do
    _ = audience

    {:ok,
     %{
       token: "eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCJ9.mock.mock",
       expires_at: DateTime.add(DateTime.utc_now(), 3600, :second)
     }}
  end

  @impl true
  def fetch_trust_bundle(_state) do
    {:ok,
     %{
       trust_domain: @trust_domain,
       x509_authorities: [<<0x30, 0x82, 0x02, 0x00>> <> :crypto.strong_rand_bytes(128)]
     }}
  end

  @impl true
  def validate_x509_svid(_state, cert) when is_binary(cert) do
    {:ok, @spiffe_id}
  end

  @impl true
  def provision_workload_svid(_state, netns_id, _attestation) do
    {:ok,
     %{
       spiffe_id: "spiffe://#{@trust_domain}/agent/#{netns_id}",
       workload_handle: :crypto.strong_rand_bytes(16)
     }}
  end

  @impl true
  def capabilities(_state),
    do: [:x509_svid, :jwt_svid, :trust_bundle, :workload_attestation]

  @impl true
  def healthcheck(_state), do: :ok

  @impl true
  def terminate(_state, _reason), do: :ok
end
