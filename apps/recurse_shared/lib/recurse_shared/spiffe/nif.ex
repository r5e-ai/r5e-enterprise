defmodule Recurse.Spiffe.Nif do
  @moduledoc """
  Rustler NIF bindings for the `recurse_spiffe` Rust crate (SPIFFE Workload
  API client — wraps `spiffe` 0.13.0 per research D7).

  Implementation detail; application code should call `Recurse.Spiffe`.
  Exposed here because Rustler requires the `use Rustler` module to match
  the Rust-side `rustler::init!` target (`Elixir.Recurse.Spiffe.Nif`).

  ## Phase-1 scope

  The NIF exposes a single stub (`fetch_x509_svid/0`) that returns `nil`
  as a smoke-test of the Rustler pipeline. The real `WorkloadApiClient`
  wiring is Feature 002+.
  """

  use Rustler,
    otp_app: :recurse_shared,
    crate: :recurse_spiffe,
    path: "../../native/recurse_spiffe"

  @doc """
  Fetch X.509 SVID — scaffold only. Returns `nil` in Phase 1; Feature 002+
  replaces this with a map containing `cert_chain`, `private_key`,
  `spiffe_id`, `expires_at`.
  """
  @spec fetch_x509_svid() :: nil | map()
  def fetch_x509_svid, do: :erlang.nif_error(:nif_not_loaded)
end
