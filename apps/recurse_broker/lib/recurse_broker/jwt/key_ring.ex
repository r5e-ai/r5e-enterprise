defmodule RecurseBroker.JWT.KeyRing do
  @moduledoc """
  Broker JWT signing keyring (F002 T086).

  State-bearing GenServer per research D2 — the three questions of the
  otp-thinking Iron Law all answer YES for this module:

    1. **Mutable state across calls?** Yes — the active `kid` plus a
       multi-key map valid during a rotation overlap window.
    2. **Concurrent access?** Yes — many concurrent mint calls plus
       JWKS endpoint reads plus the occasional operator-driven rotate
       cast all converge on the same state.
    3. **Fault isolation?** Yes — if the signing-key directory is
       missing at boot we WANT the process to crash so the supervisor
       surfaces the misconfiguration loudly. No try/rescue on startup.

  Production behavior:

    * Load signing keys from a directory (or a single PEM file) at
      boot. Source is `:signing_key_path` opt or (fallback) the
      `BROKER_JWT_SIGNING_KEY_PATH` env var. If the path resolves to a
      file, that file is the only active key. If it resolves to a
      directory, every `*.pem` is parsed; the file with the newest
      `mtime` becomes the active signing key and every valid key is
      published via `all_active_keys/0` for the JWKS endpoint's
      rotation-overlap window.
    * Enforce ES256 (`kty: EC`, `crv: P-256`) per F002 FR-007 + the
      `minted-JWT shape` rule in `contracts/recurse_broker_api.md`.
      Non-EC / non-P-256 keys are logged and skipped (not fatal — the
      operator may have left an RSA key in the rotation dir during
      the migration to ES256 and we don't want one stray file to take
      the broker down).
    * Derive `kid` from the filename stem
      (`broker-2026-04-23-v1.pem` → `broker-2026-04-23-v1`). If the
      filename doesn't look kid-shaped we fall back to the SHA-256
      thumbprint of the JWK, url-base64-encoded.
    * `current_key/0` + `all_active_keys/0` serve via
      `GenServer.call/2` (state read; acceptable at mint-time for
      F002 throughput targets — no premature ETS optimization).
    * `rotate/0` (cast) re-scans the directory and re-picks
      newest-mtime as active. Intended wiring: `SIGHUP` handler at
      the release level calls this.

  ## Test-only ephemeral mode

  The `:generate_ephemeral?` opt (default `false`) asks the GenServer
  to generate one ES256 keypair in-memory on init when no
  `:signing_key_path` is configured. This is strictly a convenience
  for the contract test (T090 / SA3) so it can exercise the sign +
  JWKS round-trip without a PEM on disk. **Never** enable it in
  production config — its output is transient and disappears on
  restart, which means downstream verifiers can't replay audits.

  ## Cross-references

    * `specs/002-standalone-gateway-vertical-slice/research.md` D2
    * `specs/002-standalone-gateway-vertical-slice/contracts/recurse_broker_api.md`
      (minted-JWT shape + JWKS publication rules, "Security discipline")
    * `specs/002-standalone-gateway-vertical-slice/tasks.md` T086
  """

  use GenServer
  require Logger

  @type kid :: String.t()
  @type jwk :: JOSE.JWK.t()

  # Public API

  @doc """
  Start the KeyRing GenServer registered under the module name.

  Opts:

    * `:signing_key_path` — file or directory. Falls back to the
      `BROKER_JWT_SIGNING_KEY_PATH` env var.
    * `:generate_ephemeral?` — test-only (see @moduledoc).
  """
  @spec start_link(keyword()) :: GenServer.on_start()
  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  Return the currently-active signing key + its kid.

  Returns `{:error, :no_active_key}` if the keyring is empty (which in
  practice only happens in the ephemeral-mode + broken-generator path
  — production boot crashes on missing-path instead).
  """
  @spec current_key() :: {:ok, {kid(), jwk()}} | {:error, atom()}
  def current_key, do: GenServer.call(__MODULE__, :current_key)

  @doc """
  Return every non-expired signing key in the rotation overlap window,
  keyed by `kid`. Used by the JWKS endpoint (`T087`).
  """
  @spec all_active_keys() :: {:ok, %{kid() => jwk()}} | {:error, atom()}
  def all_active_keys, do: GenServer.call(__MODULE__, :all_active_keys)

  @doc """
  Re-scan the configured key directory and swap the active key to the
  newest-mtime entry. Intended target for a SIGHUP handler.

  Fire-and-forget: returns `:ok` immediately; failures log and are
  visible via the next `current_key/0` call.
  """
  @spec rotate() :: :ok
  def rotate, do: GenServer.cast(__MODULE__, :rotate)

  # Callbacks

  @impl true
  def init(opts) do
    signing_key_path =
      Keyword.get(opts, :signing_key_path) ||
        System.get_env("BROKER_JWT_SIGNING_KEY_PATH")

    ephemeral? = Keyword.get(opts, :generate_ephemeral?, false)

    cond do
      is_binary(signing_key_path) ->
        case load_from_path(signing_key_path) do
          {:ok, {active_kid, keys, kids_sorted}} ->
            {:ok,
             %{
               active_kid: active_kid,
               keys: keys,
               signing_key_dir: signing_key_path,
               kids_sorted: kids_sorted
             }}

          {:error, reason} ->
            {:stop, {:broker_signing_key_load_failed, signing_key_path, reason}}
        end

      ephemeral? ->
        {active_kid, keys} = generate_ephemeral_keypair()

        {:ok,
         %{
           active_kid: active_kid,
           keys: keys,
           signing_key_dir: nil,
           kids_sorted: [active_kid]
         }}

      true ->
        {:stop, {:broker_signing_key_missing, nil}}
    end
  end

  @impl true
  def handle_call(:current_key, _from, %{active_kid: nil} = state) do
    {:reply, {:error, :no_active_key}, state}
  end

  def handle_call(:current_key, _from, %{active_kid: kid, keys: keys} = state) do
    case Map.fetch(keys, kid) do
      {:ok, jwk} -> {:reply, {:ok, {kid, jwk}}, state}
      :error -> {:reply, {:error, :no_active_key}, state}
    end
  end

  def handle_call(:all_active_keys, _from, %{keys: keys} = state) do
    {:reply, {:ok, keys}, state}
  end

  @impl true
  def handle_cast(:rotate, %{signing_key_dir: nil} = state) do
    Logger.warning("KeyRing rotate requested but no :signing_key_path configured; ignoring")
    {:noreply, state}
  end

  def handle_cast(:rotate, %{signing_key_dir: path} = state) do
    case load_from_path(path) do
      {:ok, {active_kid, keys, kids_sorted}} ->
        Logger.info("KeyRing rotated; active kid=#{active_kid}, total keys=#{map_size(keys)}")

        {:noreply, %{state | active_kid: active_kid, keys: keys, kids_sorted: kids_sorted}}

      {:error, reason} ->
        Logger.error("KeyRing rotate failed at path=#{path}: #{inspect(reason)}")
        {:noreply, state}
    end
  end

  # Internals

  defp load_from_path(path) do
    cond do
      not File.exists?(path) ->
        {:error, :path_missing}

      File.regular?(path) ->
        load_single_pem(path)

      File.dir?(path) ->
        load_directory(path)

      true ->
        {:error, :path_unusable}
    end
  end

  defp load_single_pem(path) do
    case parse_pem(path) do
      {:ok, {kid, jwk}} ->
        {:ok, {kid, %{kid => jwk}, [kid]}}

      {:error, reason} ->
        {:error, reason}
    end
  end

  defp load_directory(dir) do
    entries =
      dir
      |> Path.join("*.pem")
      |> Path.wildcard()
      |> Enum.sort()
      |> Enum.map(&parse_pem_with_mtime/1)
      |> Enum.reject(&is_nil/1)

    case entries do
      [] ->
        {:error, :no_pem_files_found}

      _ ->
        %{kid: active_kid} = Enum.max_by(entries, & &1.mtime)

        keys =
          entries
          |> Enum.map(fn %{kid: k, jwk: j} -> {k, j} end)
          |> Map.new()

        kids_sorted =
          entries
          |> Enum.map(& &1.kid)
          |> Enum.sort()

        {:ok, {active_kid, keys, kids_sorted}}
    end
  end

  defp parse_pem_with_mtime(path) do
    case parse_pem(path) do
      {:ok, {kid, jwk}} ->
        case File.stat(path, time: :posix) do
          {:ok, %File.Stat{mtime: mtime}} -> %{kid: kid, jwk: jwk, mtime: mtime, path: path}
          {:error, _} -> nil
        end

      {:error, reason} ->
        Logger.warning("KeyRing skipping #{path}: #{inspect(reason)}")
        nil
    end
  end

  defp parse_pem(path) do
    jwk = JOSE.JWK.from_pem_file(path)
    assert_es256!(jwk)
    {:ok, {derive_kid(path, jwk), jwk}}
  rescue
    ArgumentError -> {:error, :not_es256}
    e -> {:error, {:pem_parse_failed, Exception.message(e)}}
  catch
    :throw, reason -> {:error, reason}
  end

  # ES256 = kty EC + crv P-256 per F002 FR-007.
  defp assert_es256!(%JOSE.JWK{} = jwk) do
    {_, fields} = JOSE.JWK.to_map(jwk)

    case {Map.get(fields, "kty"), Map.get(fields, "crv")} do
      {"EC", "P-256"} -> :ok
      _ -> raise ArgumentError, "signing key not ES256 (kty=EC, crv=P-256)"
    end
  end

  # Kid derivation: filename stem if it looks id-shaped, else SHA-256
  # thumbprint of the JWK url-base64-encoded.
  defp derive_kid(path, %JOSE.JWK{} = jwk) do
    stem = path |> Path.basename() |> Path.rootname()

    if kid_shaped?(stem) do
      stem
    else
      # JOSE.JWK.thumbprint/1 returns an already-base64-url-encoded binary
      # per RFC 7638; hash it once more for a stable kid even for keys
      # whose thumbprint happens to not be filename-safe.
      thumb = JOSE.JWK.thumbprint(jwk)
      Base.url_encode64(:crypto.hash(:sha256, thumb), padding: false)
    end
  end

  defp kid_shaped?(stem) do
    # Conservative: require at least one char, all chars alphanumeric
    # / dash / underscore / dot, and at least one non-dot char.
    stem != "" and
      String.match?(stem, ~r/^[A-Za-z0-9_.\-]+$/) and
      String.replace(stem, ".", "") != ""
  end

  defp generate_ephemeral_keypair do
    jwk = JOSE.JWK.generate_key({:ec, "P-256"})
    thumb = JOSE.JWK.thumbprint(jwk)
    kid = "ephemeral-" <> Base.url_encode64(:crypto.hash(:sha256, thumb), padding: false)
    {kid, %{kid => jwk}}
  end
end
