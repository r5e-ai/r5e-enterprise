defmodule Recurse.Shared.Ulid do
  @moduledoc """
  ULID generator + parser.

  Canonical 26-character Crockford-Base32 form per
  [ulid/spec](https://github.com/ulid/spec). Used throughout Recurse for
  `session_id`, `run_id`, `step_id`, `turn_id`, `correlation_id`, `tenant_id`,
  and related identifiers (see spec.md FR-018, FR-021, FR-026, FR-036).

  ## Invariants (property-tested in `test/ulid_property_test.exs`)

    * Length is always 26 Crockford-Base32 characters (`0-9A-HJKMNP-TV-Z`).
    * ULIDs generated within the same millisecond are monotonically
      increasing (random component incremented, not regenerated).
    * `generate/0` → `parse!/1` is reversible: the string form round-trips
      through `parse!/1` and `to_string/1`.

  ## Struct form

  `%Recurse.Shared.Ulid{}` exposes the parsed 48-bit timestamp and 80-bit
  randomness, useful for ordering / auditing. The string form is the wire
  format and the canonical persistence form.
  """

  import Bitwise

  @type t :: %__MODULE__{
          timestamp_ms: non_neg_integer(),
          randomness: non_neg_integer(),
          string: String.t()
        }

  defstruct [:timestamp_ms, :randomness, :string]

  # Crockford-Base32 alphabet (excludes I, L, O, U to avoid ambiguity).
  @crockford ~c"0123456789ABCDEFGHJKMNPQRSTVWXYZ"
  @char_to_val @crockford
               |> Enum.with_index()
               |> Map.new(fn {ch, idx} -> {ch, idx} end)

  # Monotonicity: if the clock hasn't advanced since the last generate, we
  # bump the randomness by 1 rather than re-roll it. The
  # `Recurse.Shared.Ulid.Monotonic` GenServer serializes access so concurrent
  # callers within the same millisecond see strictly-increasing randomness.

  @doc """
  Generate a new ULID string (canonical 26-char Crockford-Base32 form).
  """
  @spec generate() :: String.t()
  def generate do
    ts_ms = System.system_time(:millisecond)
    rand = monotonic_randomness(ts_ms)
    encode(ts_ms, rand)
  end

  @doc """
  Generate a new ULID and return the parsed struct form.
  """
  @spec generate_struct() :: t()
  def generate_struct do
    str = generate()
    parse!(str)
  end

  @doc """
  Parse a canonical 26-char Crockford-Base32 ULID string into a struct.

  Raises `ArgumentError` if the input is not a valid ULID.
  """
  @spec parse!(String.t()) :: t()
  def parse!(string) when is_binary(string) do
    case parse(string) do
      {:ok, ulid} -> ulid
      {:error, reason} -> raise ArgumentError, "invalid ULID: #{inspect(reason)}"
    end
  end

  @doc """
  Parse a canonical 26-char Crockford-Base32 ULID string into a struct.

  Returns `{:ok, %Recurse.Shared.Ulid{}}` or `{:error, reason}`.
  """
  @spec parse(String.t()) :: {:ok, t()} | {:error, atom()}
  def parse(string) when is_binary(string) do
    upcased = String.upcase(string)

    with :ok <- check_length(upcased),
         {:ok, value} <- decode_to_integer(upcased) do
      <<timestamp::unsigned-integer-size(48), randomness::unsigned-integer-size(80)>> =
        <<value::unsigned-integer-size(128)>>

      {:ok,
       %__MODULE__{
         timestamp_ms: timestamp,
         randomness: randomness,
         string: upcased
       }}
    end
  end

  @doc """
  Convert a ULID struct back to its canonical string form.
  """
  @spec to_string(t()) :: String.t()
  def to_string(%__MODULE__{string: s}), do: s

  @doc """
  Assert that a string is a syntactically valid ULID.
  """
  @spec valid?(String.t()) :: boolean()
  def valid?(string) when is_binary(string) do
    case parse(string) do
      {:ok, _} -> true
      _ -> false
    end
  end

  def valid?(_), do: false

  # ---- internals ----

  @spec encode(non_neg_integer(), non_neg_integer()) :: String.t()
  defp encode(timestamp_ms, randomness)
       when timestamp_ms >= 0 and timestamp_ms < 1 <<< 48 and
              randomness >= 0 and randomness < 1 <<< 80 do
    <<value::unsigned-integer-size(128)>> =
      <<timestamp_ms::unsigned-integer-size(48), randomness::unsigned-integer-size(80)>>

    encode_base32(value, 26, [])
    |> IO.iodata_to_binary()
  end

  defp encode_base32(_value, 0, acc), do: acc

  defp encode_base32(value, remaining, acc) do
    char = Enum.at(@crockford, rem(value, 32))
    encode_base32(div(value, 32), remaining - 1, [char | acc])
  end

  defp check_length(s) when byte_size(s) == 26, do: :ok
  defp check_length(_), do: {:error, :wrong_length}

  defp decode_to_integer(s) do
    value =
      s
      |> :binary.bin_to_list()
      |> Enum.reduce(0, fn ch, acc ->
        case Map.fetch(@char_to_val, ch) do
          {:ok, v} -> acc * 32 + v
          :error -> throw({:invalid_char, ch})
        end
      end)

    if value < 1 <<< 128 do
      {:ok, value}
    else
      {:error, :overflow}
    end
  catch
    {:invalid_char, _} -> {:error, :invalid_character}
  end

  # Concurrency-safe monotonic-randomness bump. Previous implementation used a
  # lookup → compute → insert sequence in ETS, which raced under concurrent
  # generators in the same millisecond: two processes could read the same
  # `last_rand`, both add 1, both insert, and emit the same ULID. Fixed per
  # speckit-pr-review F002.
  #
  # Design: route every call through the `Recurse.Shared.Ulid.Monotonic`
  # GenServer so access is serialized. The GenServer is started under the
  # `RecurseShared.Application` supervision tree (see application.ex). For
  # test/tool callers that run outside the supervision tree, we lazy-start
  # the server on first use.
  #
  # Concurrency contract (tested in ulid_property_test.exs):
  #
  #   1. Within the same millisecond, concurrent calls produce strictly
  #      increasing (and therefore unique) randomness values.
  #   2. When the timestamp advances, the new random is seeded from
  #      :crypto.strong_rand_bytes/1.
  #   3. On 80-bit overflow within a millisecond (practically impossible
  #      but bounded), we fall back to a fresh seed rather than wrap.
  @spec monotonic_randomness(non_neg_integer()) :: non_neg_integer()
  defp monotonic_randomness(ts_ms) do
    Recurse.Shared.Ulid.Monotonic.next(ts_ms)
  end
end

defmodule Recurse.Shared.Ulid.Monotonic do
  @moduledoc false
  # Serializes ULID randomness generation across processes. Started by
  # RecurseShared.Application; lazy-starts on first call for scripts/tests
  # that run outside the supervision tree.

  use GenServer
  import Bitwise

  @max_rand (1 <<< 80) - 1

  def start_link(_), do: GenServer.start_link(__MODULE__, :ok, name: __MODULE__)

  def next(ts_ms) do
    ensure_started()
    GenServer.call(__MODULE__, {:next, ts_ms})
  end

  defp ensure_started do
    case Process.whereis(__MODULE__) do
      nil ->
        # Best-effort lazy start; ignore race where another caller wins.
        case start_link(:ok) do
          {:ok, _} -> :ok
          {:error, {:already_started, _}} -> :ok
          # Never block test code on a startup failure.
          {:error, _} -> :ok
        end

      _pid ->
        :ok
    end
  end

  @impl true
  def init(:ok), do: {:ok, %{last_ts_ms: -1, last_rand: 0}}

  @impl true
  def handle_call({:next, ts_ms}, _from, %{last_ts_ms: last_ts_ms, last_rand: last_rand} = state) do
    {rand, state1} =
      if ts_ms == last_ts_ms and last_rand + 1 <= @max_rand do
        r = last_rand + 1
        {r, %{state | last_rand: r}}
      else
        r = fresh_seed()
        {r, %{last_ts_ms: ts_ms, last_rand: r}}
      end

    {:reply, rand, state1}
  end

  defp fresh_seed do
    :crypto.strong_rand_bytes(10) |> :binary.decode_unsigned()
  end
end
