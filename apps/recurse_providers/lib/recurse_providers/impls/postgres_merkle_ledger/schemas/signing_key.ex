defmodule Recurse.Providers.Impls.PostgresMerkleLedger.Schemas.SigningKey do
  @moduledoc """
  Ecto schema for the `signing_keys` table — append-only archive of every
  KMS signing-key version the Gateway has ever observed per F001 FR-046 +
  F001 signing_key_archive contract + F002 FR-015 + F002 US5.

  Cross-references:
    * `specs/001-api-jido-foundations/contracts/signing_key_archive.md`
      — durable, auditor-visible archive contract.
    * `specs/002-standalone-gateway-vertical-slice/data-model.md` §SigningKey.
    * Migration — `priv/repo/migrations/20260423100000_f002_initial_schemas.exs`
      (columns); `20260423100002_f002_signing_keys_append_only.exs` (DELETE
      deny + UPDATE restricted to `last_seen_at`).

  ## Append-only chain integrity

  Each row's `chain_hash` is `SHA-256(prev_chain_hash || row_bytes)`, where
  `row_bytes` is the JCS (`Recurse.Shared.Jcs.encode/1`) encoding of the row
  fields that define the archive entry's identity. The first row's
  `prev_chain_hash` is the all-zeroes 32-byte anchor. This gives the archive
  a hash-chain invariant that `Recurse.Gateway.KmsRotationWatcher` verifies
  at Gateway boot (F002 T075) — any mutation or out-of-order insertion
  breaks the chain and boots the Gateway into safe-closed mode (per F001
  FR-033 semantics).

  ## Immutability

  Only `last_seen_at` may be updated after insert. The Postgres trigger
  `enforce_signing_keys_update_last_seen_only` enforces this; DELETE is
  rejected outright by `enforce_signing_keys_no_delete`. Both triggers were
  installed by the Wave 3B migration referenced above.
  """

  use Ecto.Schema

  import Ecto.Changeset

  alias Recurse.Providers.Impls.PostgresMerkleLedger.Schemas.Tenant

  @algorithm_values [:ed25519, :ecdsa_p256, :rsa_pss_2048]

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id
  @derive {Jason.Encoder,
           only: [
             :id,
             :tenant_id,
             :kms_key_id,
             :key_version,
             :public_key_pem,
             :algorithm,
             :first_seen_at,
             :last_seen_at,
             :chain_hash,
             :inserted_at
           ]}

  schema "signing_keys" do
    belongs_to(:tenant, Tenant,
      foreign_key: :tenant_id,
      references: :tenant_id,
      type: :string
    )

    field(:kms_key_id, :string)
    field(:key_version, :string)
    field(:public_key_pem, :binary)
    field(:algorithm, Ecto.Enum, values: @algorithm_values)
    field(:first_seen_at, :utc_datetime_usec)
    field(:last_seen_at, :utc_datetime_usec)
    field(:chain_hash, :binary)
    field(:inserted_at, :utc_datetime_usec)
  end

  @type t :: %__MODULE__{}

  @required_fields [
    :tenant_id,
    :kms_key_id,
    :key_version,
    :public_key_pem,
    :algorithm,
    :first_seen_at,
    :last_seen_at,
    :chain_hash,
    :inserted_at
  ]

  @doc """
  Full-row changeset used by `KmsRotationWatcher` on insert. All fields are
  required — the row is immutable-except-for-`last_seen_at` once persisted
  (see moduledoc) so there is no partial-insert surface.
  """
  @spec insert_changeset(t() | %__MODULE__{}, map()) :: Ecto.Changeset.t()
  def insert_changeset(signing_key, attrs) do
    signing_key
    |> cast(attrs, @required_fields)
    |> validate_required(@required_fields)
    |> validate_change(:chain_hash, &validate_chain_hash_bytes/2)
    |> unique_constraint([:kms_key_id, :key_version],
      name: :signing_keys_kms_key_id_key_version_index
    )
    |> check_constraint(:chain_hash, name: :signing_keys_chain_hash_len)
  end

  # `validate_length(:chain_hash, is: 32)` uses String.length which crashes
  # on the non-UTF8 bytes in a raw SHA-256 digest. Validate byte_size
  # directly instead — matches the DB check_constraint (`octet_length = 32`).
  defp validate_chain_hash_bytes(:chain_hash, value) when is_binary(value) do
    if byte_size(value) == 32, do: [], else: [chain_hash: "must be exactly 32 bytes"]
  end

  defp validate_chain_hash_bytes(:chain_hash, _), do: [chain_hash: "must be a 32-byte binary"]

  @doc """
  Changeset that only touches `last_seen_at` — the single sanctioned mutation
  surface per the `enforce_signing_keys_update_last_seen_only` trigger. Used
  by `KmsRotationWatcher` to bump `last_seen_at` when an already-archived
  key_version is still being used at poll time.
  """
  @spec touch_changeset(t(), DateTime.t()) :: Ecto.Changeset.t()
  def touch_changeset(signing_key, %DateTime{} = last_seen_at) do
    signing_key
    |> cast(%{last_seen_at: last_seen_at}, [:last_seen_at])
    |> validate_required([:last_seen_at])
  end

  @doc """
  Deterministic byte sequence over the immutable identity fields of the row.
  Fed into `SHA-256(prev_chain_hash || canonical_bytes)` to produce
  `chain_hash`. JCS encoding guarantees byte-stability across platforms
  (RFC 8785 canonical order + formatting).

  The excluded fields (`id`, `last_seen_at`, `chain_hash`, `inserted_at`)
  are either (a) allowed to mutate (`last_seen_at`), (b) the hash output
  itself (`chain_hash`), or (c) not semantically part of the archive entry's
  identity (`id` / `inserted_at`).
  """
  @spec canonical_row_bytes(%{
          :tenant_id => String.t(),
          :kms_key_id => String.t(),
          :key_version => String.t(),
          :public_key_pem => binary(),
          :algorithm => atom(),
          :first_seen_at => DateTime.t()
        }) :: binary()
  def canonical_row_bytes(fields) when is_map(fields) do
    Recurse.Shared.Jcs.encode(%{
      "tenant_id" => Map.fetch!(fields, :tenant_id),
      "kms_key_id" => Map.fetch!(fields, :kms_key_id),
      "key_version" => Map.fetch!(fields, :key_version),
      "public_key_pem" => encode_pem_for_canonicalization(Map.fetch!(fields, :public_key_pem)),
      "algorithm" => Atom.to_string(Map.fetch!(fields, :algorithm)),
      "first_seen_at" => DateTime.to_iso8601(Map.fetch!(fields, :first_seen_at))
    })
  end

  # JCS operates on JSON strings; the PEM body is already ASCII but may
  # contain embedded newlines. Pass the PEM through verbatim — JCS escapes
  # any control chars per RFC 8259 §7 which is what we want for a stable
  # encoding.
  defp encode_pem_for_canonicalization(pem) when is_binary(pem), do: pem
end
