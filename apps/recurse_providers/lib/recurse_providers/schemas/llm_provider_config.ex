defmodule Recurse.Providers.Schemas.LlmProviderConfig do
  @moduledoc """
  Ecto schema for the `llm_provider_configs` table — per-tenant + per-provider
  configuration that drives the `Recurse.Gateway.LlmProxy.UpstreamResolver`
  (Phase 3) and is recorded into `LlmCallRecord` rows by the attestation
  emitter (Phase 5).

  Source of truth: `specs/009-llm-api-proxy/data-model.md` §LlmProviderConfig.
  Migration: `priv/repo/migrations/20260507000001_llm_provider_configs.exs`.

  Why this lives at `lib/recurse_providers/schemas/` rather than under
  `lib/recurse_providers/impls/<vendor>/schemas/`: this is tenant-config
  data, not Provider-Interface-impl-bound state. The
  `Recurse.Providers.Repo` boundary is preserved (Postgres-Merkle ledger's
  Repo also owns these rows) but the row's meaning is "what upstream does
  this tenant's traffic go to?" — orthogonal to which `LedgerProvider`
  impl is wired up.

  ## Enum shapes

    * `:provider` — free-form key into the proxy's per-provider parser
      registry. Common values: `"openai_chatgpt"`, `"openai_api_key"`,
      `"anthropic"`, `"google_gemini"`, `"vllm"`. NOT validated server-side
      against a closed enum because new providers ship without schema
      changes.
    * `:transport_modes` — non-empty subset of `["wss", "https-sse"]`.
    * `:auth_mode` — `:bearer | :bearer_plus_chatgpt_account_id | :api_key
      | :aws_sigv4 | :internal_none | :passthrough`. `:passthrough` (spec 012
      S2) means the gateway stores no credential for this upstream and
      forwards whatever the client sent (`Authorization: Bearer …` or
      `x-api-key`) verbatim — the Claude Code default-upstream mode.
    * `:api_format` — `:openai_responses | :openai_chat_completions
      | :anthropic_messages | :google_gemini | :openai_compatible`.

  Whitelist enforcement is two-layered: in-memory `Ecto.Enum` rejects
  unknown atoms at changeset time; Postgres CHECK constraints reject
  unknown strings inserted via `Ecto.Adapters.SQL.query!/3` or other
  bypass paths. Drift between the two layers is a bug — keep them in
  lockstep with the migration.
  """

  use Ecto.Schema

  import Ecto.Changeset

  alias Recurse.Providers.Impls.PostgresMerkleLedger.Schemas.Tenant

  @transport_mode_values ["wss", "https-sse"]

  @auth_mode_values [
    :bearer,
    :bearer_plus_chatgpt_account_id,
    :api_key,
    :aws_sigv4,
    :internal_none,
    :passthrough
  ]

  @api_format_values [
    :openai_responses,
    :openai_chat_completions,
    :anthropic_messages,
    :google_gemini,
    :openai_compatible
  ]

  @derive {Jason.Encoder,
           only: [
             :id,
             :tenant_id,
             :provider,
             :upstream_host,
             :upstream_port,
             :transport_modes,
             :auth_mode,
             :api_format,
             :enabled,
             :model_allowlist,
             :default_token_budget_per_call,
             :metadata,
             :inserted_at,
             :updated_at
           ]}

  schema "llm_provider_configs" do
    belongs_to(:tenant, Tenant,
      foreign_key: :tenant_id,
      references: :tenant_id,
      type: :string
    )

    field(:provider, :string)
    field(:upstream_host, :string)
    field(:upstream_port, :integer, default: 443)
    field(:transport_modes, {:array, :string})
    field(:auth_mode, Ecto.Enum, values: @auth_mode_values)
    field(:api_format, Ecto.Enum, values: @api_format_values)
    field(:enabled, :boolean, default: true)
    field(:model_allowlist, {:array, :string}, default: [])
    field(:default_token_budget_per_call, :integer)
    field(:metadata, :map, default: %{})

    timestamps(type: :utc_datetime_usec)
  end

  @type t :: %__MODULE__{}

  @cast_fields [
    :tenant_id,
    :provider,
    :upstream_host,
    :upstream_port,
    :transport_modes,
    :auth_mode,
    :api_format,
    :enabled,
    :model_allowlist,
    :default_token_budget_per_call,
    :metadata
  ]

  @required_fields [
    :tenant_id,
    :provider,
    :upstream_host,
    :transport_modes,
    :auth_mode,
    :api_format
  ]

  @doc """
  Cast + validate an `LlmProviderConfig` row.

  In-memory validations:
    * required fields present
    * `:transport_modes` is non-empty and every element is in
      `#{inspect(@transport_mode_values)}`
    * `:auth_mode` and `:api_format` are valid `Ecto.Enum` atoms (rejected
      automatically by the Ecto cast)
    * `:upstream_port` ∈ (0, 65535]
    * `:default_token_budget_per_call` is positive when present

  Hash/length / array-containment invariants enforced at the DB layer
  (see migration) are NOT duplicated here — that would create a drift
  surface. Tests against the live SQL Sandbox cover the DB-only
  invariants (`migration_exec_test.exs`).
  """
  @spec changeset(t() | %__MODULE__{}, map()) :: Ecto.Changeset.t()
  def changeset(struct, attrs) do
    struct
    |> cast(attrs, @cast_fields)
    |> validate_required(@required_fields)
    |> validate_inclusion_subset(:transport_modes, @transport_mode_values)
    |> validate_number(:upstream_port, greater_than: 0, less_than_or_equal_to: 65_535)
    |> validate_number(:default_token_budget_per_call, greater_than: 0)
    |> validate_length(:transport_modes, min: 1)
    |> foreign_key_constraint(:tenant_id)
    |> unique_constraint([:tenant_id, :provider, :upstream_host],
      name: :llm_provider_configs_tenant_provider_host_index
    )
  end

  # Cheap inline validator: every element of an array field must be in the
  # allowlist. `Ecto.Changeset.validate_inclusion/3` works for scalars; for
  # arrays we walk the list ourselves.
  defp validate_inclusion_subset(changeset, field, allowed) do
    validate_change(changeset, field, fn ^field, values ->
      bad = Enum.reject(values, &(&1 in allowed))

      case bad do
        [] -> []
        _ -> [{field, "contains invalid value(s): #{inspect(bad)}; allowed: #{inspect(allowed)}"}]
      end
    end)
  end
end
