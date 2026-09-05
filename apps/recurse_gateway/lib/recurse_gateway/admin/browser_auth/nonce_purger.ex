defmodule Recurse.Gateway.Admin.BrowserAuth.NoncePurger do
  @moduledoc """
  Oban worker that hard-deletes expired `oidc_login_nonces` rows
  (F004 T038, `contracts/browser_oidc_flow.md` Step 2).

  ## Iron Law check (`elixir:oban-thinking` + `elixir:otp-thinking`)

  Oban worker. The Iron Law is satisfied by Oban's job model — each
  perform run is an isolated unit with its own retry/backoff semantics
  managed by the supervisor; the worker module itself is stateless.

  ## Schedule

  Registered as an `Oban.Plugins.Cron` entry every **5 minutes** in the
  Gateway's Oban config. The `Recurse.Gateway.Application` Oban
  supervisor child (Wave W2-C / T044) owns the registration; this
  module just defines the worker. The schedule slot reservation is
  documented in T048's task spec.

  ## Behavior

  Deletes rows where `expires_at < now() - INTERVAL '1 hour'`:

    * The 1-hour grace AFTER `expires_at` ensures any race where a
      callback transaction held the row for longer than the 10-minute
      TTL window completes cleanly before the row vanishes.
    * Hard delete (NOT soft delete) per data-model.md §1.6 — the table
      has no `deleted_at` column. These rows are operational scratch,
      not auditable state. The receipts FOR sign-in (`:ui_login`) live
      in the F002 attestations table for 7-year retention; THIS table
      is a transient correlation aid only.

  ## Iron-Law fault-isolation note

  Per `oban-thinking`'s "Let It Crash" guidance, we let Postgres
  errors propagate so Oban's retry+backoff handles them naturally. We
  do NOT wrap in a try/rescue — a transient connection blip should
  retry; a sustained failure should land in the Oban dashboard for the
  operator to investigate.

  ## Cross-references

    * `specs/004-audit-console/contracts/browser_oidc_flow.md` Step 2
    * `apps/recurse_gateway/lib/recurse_gateway/admin/browser_auth/schemas/oidc_login_nonce.ex`
    * `apps/recurse_providers/priv/repo/migrations/20260424000006_f004_oidc_login_nonces.exs`
    * Wave 3 owns the Oban supervisor + Cron schedule registration (T044).
  """

  use Oban.Worker,
    queue: :retention,
    max_attempts: 3,
    unique: [period: 60]

  import Ecto.Query

  alias Recurse.Gateway.Admin.BrowserAuth.Schemas.OidcLoginNonce
  alias Recurse.Providers.Repo

  require Logger

  # Grace period AFTER `expires_at` before hard-delete. Picked so that any
  # in-flight `consume_nonce/1` transaction (which holds a row lock for the
  # duration of an IdP token-exchange round-trip) has time to complete before
  # the row vanishes underneath it. 1 hour is generous; a 10-minute TTL
  # nonce + a multi-minute IdP exchange + clock skew across nodes still fits
  # well under the grace.
  @grace_seconds 3_600

  @impl Oban.Worker
  def perform(%Oban.Job{} = _job) do
    cutoff = DateTime.add(DateTime.utc_now(), -@grace_seconds, :second)

    {deleted_count, _} =
      from(n in OidcLoginNonce, where: n.expires_at < ^cutoff)
      |> Repo.delete_all()

    if deleted_count > 0 do
      Logger.info(fn ->
        "OidcLoginNonce purge: deleted=#{deleted_count} cutoff=#{DateTime.to_iso8601(cutoff)}"
      end)
    end

    :telemetry.execute(
      [:recurse, :browser_auth, :nonce_purge],
      %{count: deleted_count},
      %{cutoff: cutoff}
    )

    :ok
  end
end
