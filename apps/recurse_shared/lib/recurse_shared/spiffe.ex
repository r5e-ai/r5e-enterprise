defmodule Recurse.Spiffe do
  @moduledoc """
  Friendly facade over the SPIFFE Workload API Rustler NIF
  (`Recurse.Spiffe.Nif`), which wraps the `spiffe` Rust crate (research D7).

  ## Phase-1 status: scaffold only

  The NIF crate lives at `native/recurse_spiffe/` and compiles cleanly, but
  the actual Workload API integration is Feature 002+ work — specifically,
  the Gateway's ingress path (FR-025) and the Runtime's agent-container
  SVID provisioning (FR-045a). This facade exists now so:

    1. The `spiffe` crate dependency is exercised by CI and cannot rot
       (speckit-pr-review iteration-3 F002 caught that the crate had no
       Elixir wrapper and was compiled by nothing).
    2. Feature 002+ authors have a clear landing place for the real API
       surface — this module is the one that should grow `fetch_x509_svid/0`,
       `fetch_jwt_svid/1`, `validate_x509_svid/1`, etc.
    3. The forward-stub pattern (per `feedback_no_premature_metaapi.md`'s
       refined rule): function signatures are knowable with confidence;
       stub implementations force callers to handle the `:not_implemented`
       return shape, which Feature 002+ will swap for the real value.

  ## Scope boundary (per research D7)

  This module is for the **SPIFFE Workload API client** — fetching SVIDs
  and trust bundles from a SPIRE agent. It is NOT for:

    * OBO human identity propagation (FR-026, FR-047) — handled by
      `PrincipalProvider` + `SecretsProvider` via RFC 8693 token exchange
    * SPIRE Delegated Identity API (`spire-api` crate) — Phase-2 reserved
    * Rust-side mTLS (`spiffe-rustls`) — Phase 1 terminates mTLS on the
      BEAM side via Bandit
  """

  alias Recurse.Spiffe.Nif

  @typedoc "SPIFFE ID, e.g. `\"spiffe://trust-domain.example/workload/abc\"`"
  @type spiffe_id :: String.t()

  @doc """
  Fetch the current X.509 SVID for the calling workload.

  Phase-1 shell: returns `{:not_implemented, :phase_2_plus}`. Feature
  002+ will swap this for `{:ok, %{cert_chain, private_key, expires_at}}`
  from the `spiffe` crate's `WorkloadApiClient`.
  """
  @spec fetch_x509_svid() ::
          {:ok,
           %{
             cert_chain: [binary()],
             private_key: binary(),
             spiffe_id: spiffe_id(),
             expires_at: DateTime.t()
           }}
          | {:not_implemented, atom()}
          | {:error, term()}
  def fetch_x509_svid do
    case Nif.fetch_x509_svid() do
      nil -> {:not_implemented, :phase_2_plus}
      other -> other
    end
  end
end
