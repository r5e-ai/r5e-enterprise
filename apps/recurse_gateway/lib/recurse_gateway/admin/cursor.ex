defmodule Recurse.Gateway.Admin.Cursor do
  @moduledoc """
  Server-signed opaque pagination cursor for F004 audit-console endpoints
  (research D8).

  Encodes a `(timestamp_us :: integer, run_id_uuid :: String.t())` tuple
  into a URL-safe base64 string + HMAC-SHA256 signature derived from a
  tier-config-supplied server key. Tampered cursors (signature mismatch
  or malformed payload) are rejected with `{:error, :invalid_cursor}`,
  which audit-API handlers translate into the F001 `ERR_BAD_REQUEST` 400
  envelope.

  ## Why a separate utility

  Per `audit_api_extensions.md` §"Cross-cutting rules":

      Pagination cursors are opaque server-signed (D8); tampered cursors
      are rejected with 400.

  Every paginated endpoint added in F004 (session timeline, policy drafts
  list, policy suggestions list, chat conversations list) needs the same
  cursor-encoding semantics. Centralizing the format here means a single
  signing key + a single canonical wire format; rotation, format
  versioning, and integrity-test surfaces all live in one place.

  ## Why HMAC-SHA256 (and not a JWT or `:erlang.term_to_binary`)

  - JWT brings JOSE bloat for a 2-tuple payload; the audit API doesn't
    expose claims to a third party.
  - `term_to_binary` is BEAM-only (a future SDK consumer would need a
    BEAM to decode a cursor — wrong layering); it also exposes Erlang
    term grammar to anyone who can read a base64 string.
  - HMAC-SHA256 over a stable JSON shape is the same primitive
    `Plug.Crypto.MessageVerifier` uses; we lean on the canonical
    Plug-ecosystem helper so the threat model + crypto choices are
    audit-trail-traceable.

  ## Wire format

  The encoded cursor is `Plug.Crypto.MessageVerifier.sign/2`'s output,
  which is `Base.url_encode64(payload, padding: false) <> "." <> signature`.
  The payload is JCS-stable JSON: `{"ts": <integer microseconds>, "run_id": "<uuid>"}`.

  Decoded payloads are returned as `{ts_microseconds, run_id_string}`.

  ## Iron Law check (`elixir:elixir-thinking`, `elixir:otp-thinking`)

    1. Mutable state across calls? No — every call is a pure function
       of `(payload, key)`; the key is read once via
       `Application.get_env/2`.
    2. Concurrent execution? No — runs synchronously on the request
       process. Plug.Crypto.MessageVerifier itself is concurrency-safe.
    3. Fault isolation? No — bad inputs return `{:error, :invalid_cursor}`,
       NEVER raise.

  All three NO → plain functions. No GenServer, no process state.

  ## Configuration

  The signing key is read from
  `Application.get_env(:recurse_gateway, :browser_session)[:secret_key_base]`.
  Reusing the browser-session key is intentional: cursors are scoped to
  the same trust domain (the audit-console operator's browser session)
  and rotating the key naturally invalidates outstanding cursors at the
  same time browser sessions invalidate. A separate cursor key would
  add operational complexity without security benefit at the F004 trust
  boundary (single-tenant per BEAM, Phase-1).

  ## Cross-references

    * `specs/004-audit-console/research.md` D8 (cursor signing)
    * `specs/004-audit-console/contracts/audit_api_extensions.md`
      §"Cross-cutting rules" (cursor invariants)
    * `apps/recurse_gateway/lib/recurse_gateway/admin/browser_session_plug.ex`
      (the same `secret_key_base` is reused as cursor key per the
      single-trust-domain rationale above)
  """

  alias Plug.Crypto.MessageVerifier

  @typedoc "Decoded payload — `(timestamp microseconds since epoch, run_id_uuid)`."
  @type payload :: {integer(), String.t()}

  @doc """
  Encode a `(ts_microseconds, run_id)` tuple into a server-signed cursor
  string. Returns the opaque b64-encoded + HMAC-signed token.

  ## Examples

      iex> Recurse.Gateway.Admin.Cursor.encode({1_714_000_000_000_000, "run-uuid-1"}, key: "k" |> :crypto.hash(:sha256))
      "..." # opaque base64.signature
  """
  @spec encode(payload(), keyword()) :: String.t()
  def encode({ts_us, run_id}, opts \\ [])
      when is_integer(ts_us) and is_binary(run_id) do
    key = Keyword.get(opts, :key) || fetch_key!()
    json = JSON.encode!(%{"ts" => ts_us, "run_id" => run_id})
    MessageVerifier.sign(json, key)
  end

  @doc """
  Decode + verify a server-signed cursor string. Returns
  `{:ok, {ts_microseconds, run_id}}` on success or `{:error, :invalid_cursor}`
  on signature mismatch / malformed payload / unknown shape.

  Never raises — handlers can fan a bad-cursor result into the F001
  `ERR_BAD_REQUEST` envelope without try/rescue.
  """
  @spec decode(any(), keyword()) :: {:ok, payload()} | {:error, :invalid_cursor}
  def decode(cursor, opts \\ [])

  def decode(cursor, opts) when is_binary(cursor) do
    key = Keyword.get(opts, :key) || fetch_key!()

    with {:ok, payload_bytes} <- verify(cursor, key),
         {:ok, %{"ts" => ts_us, "run_id" => run_id}}
         when is_integer(ts_us) and is_binary(run_id) <- JSON.decode(payload_bytes) do
      {:ok, {ts_us, run_id}}
    else
      _ -> {:error, :invalid_cursor}
    end
  end

  def decode(_cursor, _opts), do: {:error, :invalid_cursor}

  # `MessageVerifier.verify/2` returns `{:ok, payload}` or `:error`. We
  # normalize both to the cursor-utility error shape so the public API
  # is uniform.
  defp verify(cursor, key) do
    case MessageVerifier.verify(cursor, key) do
      {:ok, payload} -> {:ok, payload}
      :error -> {:error, :invalid_cursor}
    end
  end

  # Read the signing key from the same `:browser_session` config block
  # the cookie envelope uses. Raises only if the key is missing in
  # non-test environments — tests that exercise the cursor path either
  # set the env or pass `:key` explicitly via `opts`.
  defp fetch_key! do
    env = Application.get_env(:recurse_gateway, :browser_session, [])

    case Keyword.get(env, :secret_key_base) do
      key when is_binary(key) and byte_size(key) >= 32 ->
        key

      _ ->
        raise """
        Recurse.Gateway.Admin.Cursor requires `:secret_key_base` in
        config :recurse_gateway, :browser_session, secret_key_base: <32-byte binary>

        See specs/004-audit-console/research.md D8 (cursor signing) and
        BrowserSessionPlug's identical configuration requirement.
        """
    end
  end
end
