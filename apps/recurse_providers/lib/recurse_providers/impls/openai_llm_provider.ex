defmodule Recurse.Providers.Impls.OpenAiLlmProvider do
  @moduledoc """
  F002 Phase-3 implementation of `Recurse.Providers.LLMProvider` targeting
  the OpenAI (or any OpenAI-compatible) Chat Completions API.

  ## Hot-path architecture

  The hot path is a **synchronous caller-process `Req.post/2` call over a
  named `Finch` pool (`:openai_pool`, supervised by the Gateway)**. There
  is no GenServer between the Plug handler and the upstream HTTP socket
  — the BEAM's natural TCP-backpressure chain is the concurrency model.
  Adding a sibling process would serialize all LLM traffic through a
  single mailbox and defeat the point of per-request HTTP/2 multiplexing.
  This is the Iron-Law-compliant shape per `research.md` D3.

  ## Sync vs streaming

    * `chat_complete/3` — single `Req.post/2` with `retry: false`, returns
      `{:ok, body}` on 2xx, `{:upstream_error, status, body, headers}` on
      non-2xx, or `{:upstream_error, :timeout | :connection, _, _}` on
      transport failure.

    * `chat_complete_stream/3` — `Req.post!/2` with `into: :self`. The
      response body is a `Req.Response.Async` struct that implements the
      `Enumerable` protocol; each `data:` chunk arrives in the caller's
      mailbox. The caller (Gateway `SseProxy`, T052) enumerates the
      stream, forwards each chunk downstream via `Plug.Conn.chunk/2`, and
      halts the enumeration on downstream disconnect. Halting triggers
      `Req.Response.Async`'s `cancel_fun` → the upstream Finch connection
      is released back to the pool.

  ### Why `:self` over `into: fn ... end`

  Both patterns keep the HTTP I/O in the caller process. `:self` is the
  cleaner fit for this seam because:

    1. The behaviour declares `chat_complete_stream/3 :: {:ok, Enumerable.t()}`
       — the caller is meant to drive enumeration, which matches the
       `Req.Response.Async` protocol directly.
    2. `SseProxy` (T052) provides its OWN per-chunk callback; pushing a
       provider-level `:into` callback would require plumbing that
       callback through two seams. With `:self`, SseProxy wraps the
       Enumerable in `Enum.reduce_while/3` with its own `Plug.Conn.chunk/2`
       side-effect — single seam.
    3. `Req.Response.Async`'s `{:halt, acc}` reducer invokes `cancel_fun`
       which closes the upstream Finch connection deterministically —
       the cancellation test's required behaviour.

  Identity-context handling: the `identity_context` argument is used for
  telemetry correlation ONLY. Per FR-026, identity is NEVER injected
  into the outbound request body — that is the Gateway's responsibility
  at policy-evaluation time. The provider's responsibility is (a) add the
  OpenAI `Authorization: Bearer <api_key>` header, (b) forward the
  caller-supplied OpenAI-shape body verbatim, (c) surface upstream bytes
  + status + headers unchanged on error.

  ## Contract

    * Contract doc — `specs/002-standalone-gateway-vertical-slice/contracts/provider_impls.md`
      (§ `OpenAiLlmProvider`).
    * Behaviour — `Recurse.Providers.LLMProvider` (F001).
    * Research — `specs/002-standalone-gateway-vertical-slice/research.md` (§ D3).
  """

  @behaviour Recurse.Providers.LLMProvider

  alias Recurse.Shared.IdentityContext

  @typedoc """
  Opaque state returned from `init/1`. Carries the validated configuration
  plus the resolved API key (opaque — never logged, never serialized).
  """
  @type state :: %{
          required(:base_url) => String.t(),
          required(:api_key) => String.t(),
          required(:finch_pool) => atom(),
          required(:timeout_ms) => pos_integer(),
          required(:pool_timeout_ms) => pos_integer()
        }

  @telemetry_prefix [:recurse, :providers, :openai_llm]

  # Pre-constructed full telemetry event names. Telemetry prefixes are
  # positional (handlers attach to the exact list), so we materialize
  # the full event names at compile time rather than rebuilding them
  # with `prefix ++ [:event]` on every hot-path call (O(N) per call in
  # the streaming path — measurable under sustained QPS).
  @telemetry_event_start @telemetry_prefix ++ [:start]
  @telemetry_event_stop @telemetry_prefix ++ [:stop]
  @telemetry_event_stream_opened @telemetry_prefix ++ [:stream_opened]

  # Headers that MUST NOT leak from caller-supplied request_body onto the
  # outbound wire. `Authorization` is constructed here from the resolved
  # API key; identity/correlation headers are the Gateway's concern at a
  # separate seam (FR-026, FR-047).
  @forbidden_outbound_header_names MapSet.new([
                                     "authorization",
                                     "x-observed-identity",
                                     "x-correlation-id"
                                   ])

  # Default pool-checkout timeout — covers a warm pool under sustained
  # load (D1 / D3 budget). Callers can override via config.
  @default_pool_timeout_ms 5_000

  # --- init/1 -------------------------------------------------------------

  @doc """
  Validate config and materialize the opaque provider state.

  Accepts EITHER a resolved api key (`:resolved_api_key`, used by contract
  tests that inject a mock) OR an `:api_key_ref` for Phase-3
  `SecretsProvider.resolve_ref/2` resolution (wired in T033+).
  """
  @impl true
  @spec init(Recurse.Providers.LLMProvider.config()) :: {:ok, state()} | {:error, term()}
  def init(config) when is_map(config) do
    with {:ok, base_url} <- fetch_required(config, :base_url),
         {:ok, finch_pool} <- fetch_required(config, :finch_pool),
         {:ok, api_key} <- resolve_api_key(config) do
      {:ok,
       %{
         base_url: String.trim_trailing(base_url, "/"),
         api_key: api_key,
         finch_pool: finch_pool,
         timeout_ms: Map.get(config, :timeout_ms, 30_000),
         pool_timeout_ms: Map.get(config, :pool_timeout_ms, @default_pool_timeout_ms)
       }}
    end
  end

  defp fetch_required(config, key) do
    case Map.fetch(config, key) do
      {:ok, value} when is_binary(value) or is_atom(value) -> {:ok, value}
      {:ok, _} -> {:error, {:invalid_config, key}}
      :error -> {:error, {:missing_config, key}}
    end
  end

  # Priority: explicit `:resolved_api_key` (test/injection path) →
  # `:api_key_ref` through `SecretsProvider.resolve_ref/2` (Phase-3 wiring
  # pending — T033). Absence of both is a hard failure so no unauthenticated
  # traffic ever leaves the Gateway.
  defp resolve_api_key(%{resolved_api_key: key}) when is_binary(key) and byte_size(key) > 0,
    do: {:ok, key}

  defp resolve_api_key(%{api_key_ref: _ref}),
    do: {:error, {:api_key_ref_resolution_pending, :wire_secrets_provider_at_t033}}

  defp resolve_api_key(_), do: {:error, {:missing_config, :api_key}}

  # --- chat_complete/3 (sync) ---------------------------------------------

  @doc """
  Sync Chat Completions call. Forwards `request_body` verbatim to
  `<base_url>/chat/completions` over `:openai_pool` with `Authorization:
  Bearer <api_key>` injected. Retries are disabled at this layer — the
  Gateway's orchestration decides retry policy. Timeout semantics are
  governed by the `timeout_ms` state field (maps to `:receive_timeout`).
  """
  @impl true
  @spec chat_complete(
          state(),
          Recurse.Providers.LLMProvider.completion_request(),
          IdentityContext.t()
        ) ::
          {:ok, Recurse.Providers.LLMProvider.completion_response()}
          | {:upstream_error, non_neg_integer() | :timeout | :connection, term(), list()}
          | {:error, term()}
  def chat_complete(state, request_body, %IdentityContext{} = identity_context)
      when is_map(state) and is_map(request_body) do
    start_time = System.monotonic_time()

    telemetry_meta = %{
      correlation_id: identity_context.correlation_id,
      tenant_id: identity_context.tenant_id,
      mode: :sync
    }

    :telemetry.execute(
      @telemetry_event_start,
      %{system_time: System.system_time()},
      telemetry_meta
    )

    outcome = do_chat_complete(state, request_body)

    :telemetry.execute(
      @telemetry_event_stop,
      %{duration: System.monotonic_time() - start_time},
      Map.put(telemetry_meta, :outcome, telemetry_outcome(outcome))
    )

    outcome
  end

  defp do_chat_complete(state, request_body) do
    case Req.post(
           url: state.base_url <> "/chat/completions",
           json: request_body,
           headers: outbound_headers(state),
           finch: state.finch_pool,
           retry: false,
           receive_timeout: state.timeout_ms,
           pool_timeout: state.pool_timeout_ms
         ) do
      {:ok, %Req.Response{status: status, body: body}} when status in 200..299 ->
        {:ok, body}

      {:ok, %Req.Response{status: status, body: body, headers: headers}} ->
        {:upstream_error, status, body, Map.to_list(headers)}

      {:error, %Req.TransportError{reason: :timeout}} ->
        {:upstream_error, :timeout, nil, []}

      {:error, %Req.TransportError{reason: reason}} ->
        {:upstream_error, :connection, reason, []}

      {:error, reason} ->
        {:upstream_error, :connection, reason, []}
    end
  end

  # --- chat_complete_stream/3 (SSE) ---------------------------------------

  @doc """
  Streaming Chat Completions. Returns `{:ok, Enumerable.t()}` whose
  elements are raw upstream body chunks (verbatim SSE `data: {...}\\n\\n`
  framing, including the `data: [DONE]\\n\\n` terminator).

  Enumeration MUST happen in the caller process (the one that invoked
  this function) — `Req.Response.Async`'s `reduce/3` raises otherwise.
  That matches the T052 `SseProxy` flow, where the Plug handler owns the
  whole request lifecycle.

  Halting the Enumerable (e.g. `Enum.take/2`, a reducer returning
  `{:halt, acc}`) invokes `Req.Response.Async`'s `cancel_fun`, which
  closes the upstream Finch connection and releases the pool slot.
  """
  @impl true
  @spec chat_complete_stream(
          state(),
          Recurse.Providers.LLMProvider.completion_request(),
          IdentityContext.t()
        ) ::
          {:ok, Recurse.Providers.LLMProvider.completion_stream()}
          | {:upstream_error, non_neg_integer() | :timeout | :connection, term(), list()}
          | {:error, term()}
  def chat_complete_stream(state, request_body, %IdentityContext{} = identity_context)
      when is_map(state) and is_map(request_body) do
    start_time = System.monotonic_time()

    telemetry_meta = %{
      correlation_id: identity_context.correlation_id,
      tenant_id: identity_context.tenant_id,
      mode: :stream
    }

    :telemetry.execute(
      @telemetry_event_start,
      %{system_time: System.system_time()},
      telemetry_meta
    )

    # Force `stream: true` on the outbound body so the OpenAI endpoint
    # actually SSEs back. The caller should have already set it, but
    # this is defense-in-depth against a caller that forgot.
    body = Map.put(request_body, "stream", true)

    case Req.post(
           url: state.base_url <> "/chat/completions",
           json: body,
           headers: outbound_headers(state, streaming: true),
           finch: state.finch_pool,
           retry: false,
           receive_timeout: state.timeout_ms,
           pool_timeout: state.pool_timeout_ms,
           into: :self
         ) do
      {:ok, %Req.Response{status: status, body: %Req.Response.Async{} = async}}
      when status in 200..299 ->
        :telemetry.execute(
          @telemetry_event_stream_opened,
          %{duration: System.monotonic_time() - start_time},
          telemetry_meta
        )

        {:ok, async}

      {:ok, %Req.Response{status: status, body: body, headers: headers}} ->
        :telemetry.execute(
          @telemetry_event_stop,
          %{duration: System.monotonic_time() - start_time},
          Map.put(telemetry_meta, :outcome, :upstream_error)
        )

        # `into: :self` means `body` is a `Req.Response.Async` struct on
        # ALL responses including non-2xx — Req doesn't buffer differently
        # for errors. Drain the async into a binary so callers get the
        # documented shape (`{:upstream_error, status, binary, headers}`).
        {:upstream_error, status, drain_async_body(body), Map.to_list(headers)}

      {:error, %Req.TransportError{reason: :timeout}} ->
        :telemetry.execute(
          @telemetry_event_stop,
          %{duration: System.monotonic_time() - start_time},
          Map.put(telemetry_meta, :outcome, :timeout)
        )

        {:upstream_error, :timeout, nil, []}

      {:error, %Req.TransportError{reason: reason}} ->
        :telemetry.execute(
          @telemetry_event_stop,
          %{duration: System.monotonic_time() - start_time},
          Map.put(telemetry_meta, :outcome, :connection)
        )

        {:upstream_error, :connection, reason, []}

      {:error, reason} ->
        :telemetry.execute(
          @telemetry_event_stop,
          %{duration: System.monotonic_time() - start_time},
          Map.put(telemetry_meta, :outcome, :connection)
        )

        {:upstream_error, :connection, reason, []}
    end
  end

  # Construct the canonical outbound header list. Guarantees `Authorization`
  # carries the resolved API key and no identity/correlation headers leak
  # from request-body composition back onto the wire.
  defp outbound_headers(state, opts \\ []) do
    streaming? = Keyword.get(opts, :streaming, false)

    base = [
      {"authorization", "Bearer " <> state.api_key},
      {"content-type", "application/json"}
    ]

    accept =
      if streaming? do
        [{"accept", "text/event-stream"}]
      else
        [{"accept", "application/json"}]
      end

    # Defense-in-depth: drop any name we consider forbidden. This list is
    # constructed here, so in practice nothing is dropped — the filter
    # documents the invariant for future maintainers who might wire an
    # opts-passthrough.
    Enum.reject(base ++ accept, fn {name, _} ->
      MapSet.member?(@forbidden_outbound_header_names, String.downcase(name)) and
        name != "authorization"
    end)
  end

  # `into: :self` returns `%Req.Response.Async{}` as the body on non-2xx
  # too. On error paths the Enumerable is drained synchronously so the
  # caller gets the documented binary-body contract.
  defp drain_async_body(%Req.Response.Async{} = async) do
    async |> Enum.to_list() |> IO.iodata_to_binary()
  rescue
    # A drained async that was already halted raises; fall back to empty
    # string so we never crash the error-surface path.
    _ -> ""
  end

  defp drain_async_body(body) when is_binary(body), do: body
  defp drain_async_body(_), do: ""

  defp telemetry_outcome({:ok, _}), do: :ok

  defp telemetry_outcome({:upstream_error, status, _, _}) when is_integer(status),
    do: :upstream_5xx

  defp telemetry_outcome({:upstream_error, :timeout, _, _}), do: :timeout
  defp telemetry_outcome({:upstream_error, :connection, _, _}), do: :connection

  # --- capabilities/1 + healthcheck/1 + terminate/2 -----------------------

  @doc """
  Phase-3: advertise `[:sync, :streaming, :tool_calls, :function_calling]`
  for OpenAI endpoints; `:vision` only when `base_url` is the canonical
  OpenAI `api.openai.com/v1` (compatible endpoints vary).
  """
  @impl true
  @spec capabilities(state()) :: [Recurse.Providers.LLMProvider.capability()]
  def capabilities(_state), do: [:sync, :streaming, :tool_calls, :function_calling]

  @doc """
  Phase-3: HEAD `<base_url>/models` via the configured Finch pool; map HTTP
  5xx → `{:degraded, ...}`, connection failures → `{:down, ...}`.

  This shipment doesn't wire `healthcheck/1` yet — it returns `:down`
  pending T044.
  """
  @impl true
  @spec healthcheck(state()) :: :ok | {:degraded, term()} | {:down, term()}
  def healthcheck(_state), do: {:down, :not_implemented_yet}

  @doc """
  Finch pools are owned by the Gateway Application supervisor; the
  provider has no per-instance state to tear down.
  """
  @impl true
  @spec terminate(state(), reason :: term()) :: :ok
  def terminate(_state, _reason), do: :ok
end
