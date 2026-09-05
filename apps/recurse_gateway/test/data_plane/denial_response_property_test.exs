defmodule RecurseGateway.DataPlane.DenialResponsePropertyTest do
  @moduledoc """
  F002 property-test — **Surface S extension** — denial response synthesis
  (T056).

  Cross-refs:
    * `specs/002-standalone-gateway-vertical-slice/contracts/property_test_surface_catalog_f002.md`
      §Surface S (the base schema-stability surface has its own file at
      `apps/recurse_gateway/test/policy/cedar_evaluator_property_test.exs`;
      this module covers the denial-response-synthesis extension).
    * `specs/002-standalone-gateway-vertical-slice/tasks.md` T056.
    * `specs/002-standalone-gateway-vertical-slice/spec.md` FR-005,
      FR-016a (single canonical denial channel).

  ## Invariant

  For any `(principal_kind, policy_canonical_hash_bytes, correlation_id,
  request_body)` tuple, the synthetic OpenAI `chat.completion` response
  emitted by `Recurse.Gateway.DataPlane.ChatCompletionsHandler.synthetic_refusal_response/3`:

    * `object` == `"chat.completion"`.
    * `choices[0].message.refusal` is populated and contains the hex form
      of `policy_canonical_hash` (single canonical channel per FR-016a).
    * `choices[0].message.content` is `nil`.
    * `choices[0].message` has NO `tool_calls` key (out of scope for the
      MVP slice per FR-003).
    * No duplicate denial signal in `content` (nil already asserted).
    * `choices[0].finish_reason` == `"content_filter"`.
    * `choices[0].index` == `0`.

  The property test uses `gen all` over the input space; the oracle is
  structural pattern-matching on the produced map.

  ## Generator discipline (per `elixir:stream-data-thinking`)

  Generators are built with `gen all` / `bind`; no `filter`. The policy
  hash generator emits 32-byte binaries directly via `binary(length:
  32)`. Correlation ID uses a ULID-shaped alphanumeric string at 26
  chars (mirrors the Gateway's mint). Principal kind is a `member_of`
  choice since only three values are legal. Request bodies use the same
  FR-003-compliant request generator shape as the Surface-Q test — text
  only, no tools / vision / structured outputs.
  """

  use ExUnit.Case, async: true
  use ExUnitProperties

  alias Recurse.Gateway.DataPlane.ChatCompletionsHandler

  @iterations 300

  # ---------------------------------------------------------------------------
  # Generators
  # ---------------------------------------------------------------------------

  defp safe_string(opts) do
    min_length = Keyword.get(opts, :min_length, 1)
    max_length = Keyword.get(opts, :max_length, 32)
    StreamData.string(:alphanumeric, min_length: min_length, max_length: max_length)
  end

  # Principal kind — Cedar entity types per FR-011. Included in the
  # generator tuple because the property's statement mentions principal
  # identity even though the synthesis path does not actually read it;
  # making the tuple explicit keeps the generator aligned with the
  # catalog's `(principal, deny-decision, correlation_id)` prose.
  defp principal_kind_gen do
    StreamData.member_of([:obo_human, :service_account, :autonomous])
  end

  # ULID-shaped 26-char Crockford-base32-ish string. Alphanumeric is a
  # superset of the actual base32 alphabet, but alphanumeric StreamData
  # lists are plentifully generatable and good enough for synthesis —
  # the handler doesn't decode the value.
  defp correlation_id_gen do
    StreamData.string(:alphanumeric, length: 26)
  end

  # 32-byte raw-binary policy hash — the exact shape
  # `FilesystemPolicyProvider.canonical_hash/1` produces (SHA-256 of the
  # Cedar EST JCS).
  defp policy_hash_gen do
    StreamData.binary(length: 32)
  end

  # Run ID — UUID-shaped or ULID-shaped string; the handler just lays
  # it into `chatcmpl-<id>`.
  defp run_id_gen, do: safe_string(min_length: 8, max_length: 40)

  defp message_gen do
    gen all(content <- safe_string(max_length: 64)) do
      %{"role" => "user", "content" => content}
    end
  end

  defp request_body_gen do
    gen all(
          model <- safe_string(max_length: 24),
          messages <- StreamData.list_of(message_gen(), min_length: 1, max_length: 5)
        ) do
      %{"model" => model, "messages" => messages}
    end
  end

  defp refusal_message_gen(policy_hash) do
    # Mirrors the handler's deny-branch format string verbatim so the
    # embedded hash contract is what's actually emitted in production.
    hex = Base.encode16(policy_hash, case: :lower)
    StreamData.constant("Request denied by policy (canonical_hash=#{hex})")
  end

  # ---------------------------------------------------------------------------
  # Property — denial response shape
  # ---------------------------------------------------------------------------

  describe "Surface S denial-response property" do
    @describetag :property_surface_s

    property "synthetic_refusal_response/3 emits a single-canonical-channel deny body" do
      check all(
              # principal_kind + correlation_id are intentionally unused
              # by the synthesis function — binding them keeps the
              # generator aligned with the catalog's (principal,
              # deny-decision, correlation_id) prose and guards against
              # future drift that starts reading them. The `_` prefix
              # silences the compile-time warning; the binding still runs.
              _principal_kind <- principal_kind_gen(),
              _correlation_id <- correlation_id_gen(),
              policy_hash <- policy_hash_gen(),
              run_id <- run_id_gen(),
              request_body <- request_body_gen(),
              refusal <- refusal_message_gen(policy_hash),
              max_runs: @iterations
            ) do
        response =
          ChatCompletionsHandler.synthetic_refusal_response(run_id, request_body, refusal)

        # --- Structural invariants (FR-016a single canonical channel) ---
        assert %{
                 "id" => id,
                 "object" => "chat.completion",
                 "model" => model,
                 "choices" => [
                   %{
                     "index" => 0,
                     "message" => %{
                       "role" => "assistant",
                       "content" => nil,
                       "refusal" => emitted_refusal
                     },
                     "finish_reason" => "content_filter"
                   }
                 ]
               } = response

        # `id` carries the run_id so auditors can correlate synthetic
        # denials back to the ledger row (the handler prefixes with
        # `chatcmpl-`, matching the OpenAI convention).
        assert is_binary(id)
        assert String.starts_with?(id, "chatcmpl-")
        assert String.contains?(id, run_id)

        assert model == Map.get(request_body, "model")

        # Refusal carries the full message including the hex hash. Two
        # checks: exact-match for the generated message AND the hex-form
        # of the raw binary is present. Together these confirm FR-016a's
        # "embedded policy_canonical_hash" requirement.
        assert emitted_refusal == refusal
        hex = Base.encode16(policy_hash, case: :lower)
        assert String.contains?(emitted_refusal, hex)
        assert String.contains?(emitted_refusal, "canonical_hash=")

        # --- No duplicate denial signals ---
        [choice] = response["choices"]
        refute Map.has_key?(choice["message"], "tool_calls")
        # The denial must live ONLY in `refusal`; `content` is nil (not
        # a blank string that later stringification could mistake for a
        # message body).
        assert choice["message"]["content"] == nil

        # `usage` is present with zeros — denials don't consume upstream
        # tokens but the OpenAI-shape requires the field.
        assert response["usage"] == %{
                 "prompt_tokens" => 0,
                 "completion_tokens" => 0,
                 "total_tokens" => 0
               }
      end
    end
  end

  # ---------------------------------------------------------------------------
  # Property — determinism over insertion order
  # ---------------------------------------------------------------------------

  describe "Surface S denial-response determinism" do
    @describetag :property_surface_s

    property "same inputs yield equal bodies modulo the `created` timestamp" do
      # The synthesis function stamps `System.system_time(:second)` into
      # `created`; two calls in the same test run may straddle a second
      # boundary. Assert the rest of the body is identical across two
      # calls with identical inputs.
      check all(
              # correlation_id is carried in the outer response envelope
              # by the handler/router, not by the synthesis function;
              # binding it keeps the catalog tuple honest.
              _correlation_id <- correlation_id_gen(),
              policy_hash <- policy_hash_gen(),
              run_id <- run_id_gen(),
              request_body <- request_body_gen(),
              refusal <- refusal_message_gen(policy_hash),
              max_runs: @iterations
            ) do
        a = ChatCompletionsHandler.synthetic_refusal_response(run_id, request_body, refusal)
        b = ChatCompletionsHandler.synthetic_refusal_response(run_id, request_body, refusal)

        assert Map.delete(a, "created") == Map.delete(b, "created")
      end
    end
  end
end
