defmodule Recurse.Shared.Principal do
  @moduledoc """
  Principal claim struct + RFC 8785 JCS canonical serialization per FR-026.

  The `PrincipalProvider` validates and produces a principal with three
  `kind` values and explicit canonical serialization:

    * `:obo_human` — `{kind, schema_version, issuer, subject, display_name?, groups?[]}`
    * `:service_account` — `{kind, schema_version, issuer, account_id, scope?[]}`
    * `:autonomous` — `{kind, schema_version, spiffe_id}`

  `canonical_form/1` returns RFC 8785 JCS-encoded bytes suitable for the
  `identities.principal` field of the signed attestation predicate
  (FR-021) and for the `principal_canonical` column in the `Attestation`
  Ecto schema.

  ## Invariant (property-tested)

  Byte-stability: re-serializing the decoded struct yields identical bytes.
  Keys are emitted in lexicographic (Unicode code-point) order, arrays
  preserve insertion order, and absent optional fields are omitted (not
  emitted as `null`).
  """

  @type kind :: :obo_human | :service_account | :autonomous

  @type t :: %__MODULE__{
          kind: kind(),
          schema_version: String.t(),
          issuer: String.t() | nil,
          subject: String.t() | nil,
          display_name: String.t() | nil,
          groups: [String.t()] | nil,
          account_id: String.t() | nil,
          scope: [String.t()] | nil,
          spiffe_id: String.t() | nil,
          recurse_role: String.t() | nil
        }

  defstruct kind: nil,
            schema_version: "1.0",
            issuer: nil,
            subject: nil,
            display_name: nil,
            groups: nil,
            account_id: nil,
            scope: nil,
            spiffe_id: nil,
            recurse_role: nil

  @doc """
  Build an `:obo_human` principal.
  """
  @spec obo_human(map()) :: t()
  def obo_human(%{issuer: issuer, subject: subject} = attrs) do
    %__MODULE__{
      kind: :obo_human,
      schema_version: Map.get(attrs, :schema_version, "1.0"),
      issuer: issuer,
      subject: subject,
      display_name: Map.get(attrs, :display_name),
      groups: Map.get(attrs, :groups),
      recurse_role: Map.get(attrs, :recurse_role)
    }
  end

  @doc """
  Build a `:service_account` principal.
  """
  @spec service_account(map()) :: t()
  def service_account(%{issuer: issuer, account_id: account_id} = attrs) do
    %__MODULE__{
      kind: :service_account,
      schema_version: Map.get(attrs, :schema_version, "1.0"),
      issuer: issuer,
      account_id: account_id,
      scope: Map.get(attrs, :scope),
      recurse_role: Map.get(attrs, :recurse_role)
    }
  end

  @doc """
  Build an `:autonomous` principal.
  """
  @spec autonomous(map()) :: t()
  def autonomous(%{spiffe_id: spiffe_id} = attrs) do
    %__MODULE__{
      kind: :autonomous,
      schema_version: Map.get(attrs, :schema_version, "1.0"),
      spiffe_id: spiffe_id,
      recurse_role: Map.get(attrs, :recurse_role)
    }
  end

  @doc """
  Convert a principal struct to its canonical map form (kind-dependent
  field set). Absent optional fields are omitted.

  This is the intermediate representation fed to `canonical_form/1`.
  """
  @spec to_map(t()) :: map()
  def to_map(%__MODULE__{kind: :obo_human} = p) do
    %{
      "kind" => "obo_human",
      "schema_version" => p.schema_version,
      "issuer" => p.issuer,
      "subject" => p.subject
    }
    |> maybe_put("display_name", p.display_name)
    |> maybe_put("groups", p.groups)
  end

  def to_map(%__MODULE__{kind: :service_account} = p) do
    %{
      "kind" => "service_account",
      "schema_version" => p.schema_version,
      "issuer" => p.issuer,
      "account_id" => p.account_id
    }
    |> maybe_put("scope", p.scope)
  end

  def to_map(%__MODULE__{kind: :autonomous} = p) do
    %{
      "kind" => "autonomous",
      "schema_version" => p.schema_version,
      "spiffe_id" => p.spiffe_id
    }
  end

  @doc """
  RFC 8785 JCS canonical form of the principal.

  Returns bytes (binary) — the caller decides whether to wrap in a string,
  hash, or stream further.
  """
  @spec canonical_form(t()) :: binary()
  def canonical_form(%__MODULE__{} = p) do
    p |> to_map() |> Recurse.Shared.Jcs.encode()
  end

  defp maybe_put(map, _key, nil), do: map
  defp maybe_put(map, key, value), do: Map.put(map, key, value)
end
