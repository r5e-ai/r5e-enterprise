defmodule Recurse.Gateway.Admin.BrowserAuth.NonceStore do
  @moduledoc """
  Postgres-backed OIDC PKCE state store for the browser sign-in flow
  (F004 T035, `contracts/browser_oidc_flow.md` Step 2).

  Pure module talking directly to `Recurse.Providers.Repo`. No process.
  Iron Law (`elixir:elixir-thinking`):

    1. Mutable state persisting across calls? No — every call is a pure
       function of `(args)` plus the side-effecting Repo write/read.
    2. Concurrent execution? No — serialization is provided by Postgres
       row locks (`SELECT ... FOR UPDATE` in `consume_nonce/1`).
    3. Fault isolation? No — failures are `{:error, _}` tuples; the
       caller (LoginHandler) translates them into HTTP error envelopes.

  All three NO → plain functions on `Repo`.

  ## Why Postgres, not ETS

  Constitution Principle I (federation-ready). A user starting login on
  Gateway node A and returning to Gateway node B (round-robin LB, no
  sticky sessions) MUST succeed. Node-local ETS fails on round-robin;
  Postgres survives the cross-node hop because all Gateway nodes point
  at the same database.

  ## Single-use enforcement

  `consume_nonce/1` runs inside a `Repo.transact/1` block:

    1. `SELECT ... FOR UPDATE WHERE state = ? AND used_at IS NULL AND
       expires_at > now()`. The `FOR UPDATE` row lock serializes any
       concurrent callbacks racing on the same `state` — only the first
       transaction wins; the others see `used_at IS NOT NULL` after the
       winner commits.
    2. If found, set `used_at = now()` and return the row.
    3. If not found, return a structured error distinguishing
       `:state_invalid` (no row at all) from `:state_already_used` /
       `:state_expired` (row exists but ineligible).

  This is the load-bearing race-free guard. The schema-level UNIQUE on
  `state` prevents INSERT replay; the row lock prevents consume replay.

  ## Cross-references

    * `specs/004-audit-console/contracts/browser_oidc_flow.md` Step 2 + 4
    * `specs/004-audit-console/data-model.md` §1.6
    * `apps/recurse_gateway/lib/recurse_gateway/admin/browser_auth/schemas/oidc_login_nonce.ex`
    * `apps/recurse_providers/priv/repo/migrations/20260424000006_f004_oidc_login_nonces.exs`
  """

  import Ecto.Query

  alias Recurse.Gateway.Admin.BrowserAuth.Schemas.OidcLoginNonce
  alias Recurse.Providers.Repo

  @typedoc """
  Result of `consume_nonce/1`. Distinct error atoms drive the per-failure
  `:ui_login` `outcome` discriminator (per `browser_oidc_flow.md` Step 4
  failure-path table).
  """
  @type consume_error :: :state_invalid | :state_already_used | :state_expired

  # Default 10-minute TTL per `browser_oidc_flow.md` Step 2.
  @default_ttl_seconds 600

  @doc """
  Insert a fresh PKCE state row. Returns `{:ok, %OidcLoginNonce{}}` or
  `{:error, changeset}`.

  Arguments:

    * `state` — opaque CSRF token (32+ random bytes, base64url).
    * `code_verifier` — PKCE verifier, 43..128 chars per RFC 7636.
    * `attrs` — keyword/map with `:return_to` (absolute URL) and
      `:tenant_id` (string). Optional `:ttl_seconds` overrides the
      default 600s for tests.

  Caller MUST validate `return_to` is a Gateway-relative path BEFORE
  passing here (schema validation only enforces the URL format guard,
  not the open-redirect allowlist).
  """
  @spec insert_nonce(String.t(), String.t(), map() | keyword()) ::
          {:ok, OidcLoginNonce.t()} | {:error, Ecto.Changeset.t()}
  def insert_nonce(state, code_verifier, attrs)
      when is_binary(state) and is_binary(code_verifier) do
    attrs_map = Enum.into(attrs, %{})
    ttl_seconds = Map.get(attrs_map, :ttl_seconds, @default_ttl_seconds)
    now = DateTime.utc_now()

    row_attrs = %{
      state: state,
      code_verifier: code_verifier,
      return_to: Map.fetch!(attrs_map, :return_to),
      tenant_id: Map.fetch!(attrs_map, :tenant_id),
      created_at: now,
      expires_at: DateTime.add(now, ttl_seconds, :second),
      used_at: nil
    }

    %OidcLoginNonce{}
    |> OidcLoginNonce.changeset(row_attrs)
    |> Repo.insert()
  end

  @doc """
  Atomically consume a nonce by `state`. Returns the loaded row on
  success or a tagged error on any failure path.

  Failure atoms map 1:1 to `:ui_login` `outcome` discriminators:

    * `:state_invalid` — no row with this `state` exists.
    * `:state_already_used` — row exists but `used_at IS NOT NULL`.
    * `:state_expired` — row exists but `expires_at <= now()`.

  The `SELECT ... FOR UPDATE` lock guarantees that two concurrent
  callbacks racing on the same `state` resolve as exactly one winner +
  exactly one `:state_already_used` loser.
  """
  @spec consume_nonce(String.t()) ::
          {:ok, OidcLoginNonce.t()} | {:error, consume_error()}
  def consume_nonce(state) when is_binary(state) do
    state
    |> consume_in_transaction()
    |> normalize_transaction_result()
  end

  defp consume_in_transaction(state) do
    Repo.transaction(fn -> dispatch_locked_row(Repo.one(lock_query(state))) end)
  end

  # No row; could be never-issued (state_invalid) OR purged-after-expiry
  # (state_invalid from the consumer's POV is indistinguishable). Both
  # collapse to `:state_invalid` today.
  defp dispatch_locked_row(nil), do: Repo.rollback(:state_invalid)

  defp dispatch_locked_row(%OidcLoginNonce{used_at: %DateTime{}}),
    do: Repo.rollback(:state_already_used)

  defp dispatch_locked_row(%OidcLoginNonce{expires_at: expires_at} = row) do
    if DateTime.compare(expires_at, DateTime.utc_now()) == :gt do
      mark_used(row)
    else
      Repo.rollback(:state_expired)
    end
  end

  # SELECT ... FOR UPDATE by state. Note: we do NOT pre-filter `used_at IS
  # NULL` here because we want to surface the `:state_already_used` error
  # from a row found in the locked SELECT — pre-filtering would collapse
  # it to "no row" and we'd lose the audit-distinguishable atom.
  defp lock_query(state) do
    from n in OidcLoginNonce,
      where: n.state == ^state,
      lock: "FOR UPDATE"
  end

  defp mark_used(%OidcLoginNonce{} = row) do
    {:ok, updated} =
      row
      |> OidcLoginNonce.changeset(%{used_at: DateTime.utc_now()})
      |> Repo.update()

    updated
  end

  # `Repo.transaction/1` returns `{:ok, value}` on commit (where `value` is
  # whatever the inner fn returned) or `{:error, reason}` on `Repo.rollback/1`.
  # Both shapes already match our public typespec so we just pass through.
  defp normalize_transaction_result({:ok, %OidcLoginNonce{} = row}), do: {:ok, row}
  defp normalize_transaction_result({:error, reason}) when is_atom(reason), do: {:error, reason}
end
