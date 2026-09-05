defmodule RecurseGateway.DataPlane.PayloadCanonicalizationPropertyTest do
  @moduledoc """
  F002 property-test **Surface Q** — payload canonicalization (T030).

  Cross-refs:
    * `specs/002-standalone-gateway-vertical-slice/contracts/payload_canonicalization.md`
      (the load-bearing rule for `payload_hash`)
    * `specs/002-standalone-gateway-vertical-slice/contracts/property_test_surface_catalog_f002.md`
      §Surface Q
    * `specs/002-standalone-gateway-vertical-slice/tasks.md` T030

  Properties 1, 3, 4 run against `Recurse.Shared.Jcs` directly today.
  Property 2 (SSE-reassembly stability) is gated on T040/T052 landing
  `Recurse.Gateway.DataPlane.SseProxy.reassemble/1` — tagged both
  `:pending` (so the default `mix test` exclude list skips it) and
  `skip: "T052"` (so `--include property` doesn't re-include it;
  ExUnit's `skip:` tag beats both include and exclude).

  ## Per-property notes

    * **Property 1 (determinism)** — same input → same bytes → same hash.
      Verified by comparing two independent JCS encodings of the same term.
    * **Property 2 (reassembly stability)** — gated on T052. Re-enable by
      removing the `:pending` tag once `SseProxy.reassemble/1` lands.
    * **Property 3 (key-order independence)** — JCS sorts object keys
      lexicographically on UTF-16 code units (RFC 8785 §3.2.3). Reversing
      the insertion order of a map's pairs must not change encoded bytes.
    * **Property 4 (null member handling)** — RFC 8785 does **NOT** elide
      null members (§3.2.3 requires preserving all members, sorted by key).
      The surface-Q catalog line "(JCS omits null members per canonicalization
      rule — verify)" is inaccurate; this property documents the actual
      RFC-compliant behavior: `system_fingerprint: nil` and absent produce
      DIFFERENT hashes. If the broker later normalizes by stripping nils
      pre-canonicalization, the normalization step — not JCS — is where
      that contract lives.

  ## StreamData discipline (per `elixir:stream-data-thinking` skill)

    * Generators built via `gen all` / `bind` — **no `filter` heavy-handedness**
      (shrinking discards are a known trap).
    * Each generator stays in the valid space by construction: lengths
      bounded, structural invariants enforced via the composition.
    * 300-iteration default per catalog (Constitution Principle VI).
  """
  use ExUnit.Case, async: true
  use ExUnitProperties

  alias Recurse.Shared.Jcs

  @iterations 300

  # ---------------------------------------------------------------------------
  # Generators — OpenAI chat.completion request + response shapes.
  # Scope-cut per FR-003: text-only, no tools / functions / response_format
  # / image-or-audio content parts.
  # ---------------------------------------------------------------------------

  defp safe_string(opts) do
    min_length = Keyword.get(opts, :min_length, 1)
    max_length = Keyword.get(opts, :max_length, 32)
    StreamData.string(:alphanumeric, min_length: min_length, max_length: max_length)
  end

  defp role_gen, do: StreamData.member_of(["system", "user", "assistant"])

  defp message_gen do
    gen all(role <- role_gen(), content <- safe_string(max_length: 64)) do
      %{"role" => role, "content" => content}
    end
  end

  defp optional(gen), do: StreamData.one_of([StreamData.constant(:absent), gen])

  defp maybe_put(map, _key, :absent), do: map
  defp maybe_put(map, key, value), do: Map.put(map, key, value)

  # Valid OpenAI chat.completion REQUEST per FR-003 whitelist
  # (model, messages, optional max_tokens, optional temperature).
  defp request_gen do
    gen all(
          model <- safe_string(max_length: 24),
          messages <- StreamData.list_of(message_gen(), min_length: 1, max_length: 5),
          max_tokens <- optional(StreamData.integer(1..4096)),
          temperature_int <- optional(StreamData.integer(0..20))
        ) do
      %{"model" => model, "messages" => messages}
      |> maybe_put("max_tokens", max_tokens)
      # Temperature is a float on the wire; JCS rejects non-integer floats, so
      # we keep our generator integer-valued (divide by 10 idea rejected to
      # avoid float-round-trip trouble per JCS Phase-1 constraint).
      |> maybe_put("temperature", temperature_int)
    end
  end

  # Valid OpenAI chat.completion RESPONSE (sync, non-streaming) —
  # the shape that `payload_hash` covers after SSE reassembly too.
  defp response_choice_gen do
    gen all(
          role <- StreamData.constant("assistant"),
          content <- safe_string(max_length: 128),
          refusal <- optional(safe_string(max_length: 32)),
          finish_reason <- StreamData.member_of(["stop", "length", "content_filter"])
        ) do
      message =
        %{"role" => role, "content" => content}
        |> maybe_put("refusal", refusal)

      %{"index" => 0, "message" => message, "finish_reason" => finish_reason}
    end
  end

  defp usage_gen do
    gen all(
          p <- StreamData.integer(0..4096),
          c <- StreamData.integer(0..4096)
        ) do
      %{"prompt_tokens" => p, "completion_tokens" => c, "total_tokens" => p + c}
    end
  end

  defp response_gen do
    gen all(
          id <- safe_string(max_length: 40),
          created <- StreamData.integer(1_700_000_000..2_000_000_000),
          model <- safe_string(max_length: 24),
          choice <- response_choice_gen(),
          usage <- usage_gen(),
          system_fingerprint <- optional(safe_string(max_length: 16))
        ) do
      %{
        "id" => id,
        "object" => "chat.completion",
        "created" => created,
        "model" => model,
        "choices" => [choice],
        "usage" => usage
      }
      |> maybe_put("system_fingerprint", system_fingerprint)
    end
  end

  defp envelope_gen do
    gen all(request <- request_gen(), response <- response_gen()) do
      %{"request" => request, "response" => response}
    end
  end

  # Shuffle a map's key insertion order without changing its logical
  # content. Recursive so nested maps are also re-ordered. Shrinking
  # handles this fine because we operate on already-generated terms.
  defp shuffle_map_order(%_{} = struct), do: struct

  defp shuffle_map_order(map) when is_map(map) do
    map
    |> Map.to_list()
    |> Enum.map(fn {k, v} -> {k, shuffle_map_order(v)} end)
    |> Enum.reverse()
    |> Map.new()
  end

  defp shuffle_map_order(list) when is_list(list), do: Enum.map(list, &shuffle_map_order/1)
  defp shuffle_map_order(other), do: other

  defp hash(term), do: :crypto.hash(:sha256, Jcs.encode(term))

  # ---------------------------------------------------------------------------
  # Property 1 — JCS + SHA-256 is deterministic.
  # ---------------------------------------------------------------------------

  describe "Surface Q property 1: determinism" do
    @describetag :property_surface_q

    property "SHA-256(JCS(envelope)) is deterministic" do
      check all(envelope <- envelope_gen(), max_runs: @iterations) do
        a = hash(envelope)
        b = hash(envelope)
        assert a == b
        assert byte_size(a) == 32
      end
    end
  end

  # ---------------------------------------------------------------------------
  # Property 2 — SSE-reassembly stability. PENDING on T052.
  # ---------------------------------------------------------------------------

  describe "Surface Q property 2: SSE-reassembly stability (T052-gated)" do
    @describetag :property_surface_q

    @tag :pending
    @tag skip: "gated on T052 SseProxy.reassemble/1"
    property "reassembly hash is invariant across chunk-granularity permutations" do
      # Full impl requires `Recurse.Gateway.DataPlane.SseProxy.reassemble/1`
      # which lands in T040/T052. Generator shape (per catalog §Surface Q):
      #
      #   bind over {request, final-content, chunk-granularity}
      #     where granularity ∈ [1-char, 10-char, 100-char, random]
      #   generate SSE chunk sequence matching the granularity
      #   reassemble via SseProxy.reassemble/1
      #   hash the reassembled JSON envelope
      #
      # Invariant: for the same (request, final-content), all granularities
      # yield the same hash.
      check all(_ <- StreamData.constant(:placeholder), max_runs: 1) do
        flunk("Surface Q property 2 — pending on T052 SseProxy.reassemble/1")
      end
    end
  end

  # ---------------------------------------------------------------------------
  # Property 3 — JCS key-order independence.
  # RFC 8785 §3.2.3: object members sorted by UTF-16 code-unit value.
  # Insertion order must not affect encoded bytes.
  # ---------------------------------------------------------------------------

  describe "Surface Q property 3: JCS key-order independence" do
    @describetag :property_surface_q

    property "reversed map insertion order yields identical hash" do
      check all(envelope <- envelope_gen(), max_runs: @iterations) do
        shuffled = shuffle_map_order(envelope)
        assert hash(envelope) == hash(shuffled)
      end
    end
  end

  # ---------------------------------------------------------------------------
  # Property 4 — Null member handling per RFC 8785.
  #
  # Per RFC 8785 §3.2.3, JCS does NOT elide null members. An object with
  # `{"system_fingerprint": null}` canonicalizes to `"system_fingerprint":null`;
  # an object WITHOUT that key canonicalizes to the key being absent. These
  # produce DIFFERENT bytes and therefore DIFFERENT hashes.
  #
  # This property documents the RFC-compliant behavior. The surface-Q catalog
  # text ("(JCS omits null members per canonicalization rule — verify)") is
  # inaccurate; "verify" in the catalog invites us to correct the record
  # here. If downstream code wants nil-absent equivalence, the pre-JCS
  # normalization layer (Gateway / Broker) MUST strip nils before JCS —
  # not JCS itself.
  # ---------------------------------------------------------------------------

  describe "Surface Q property 4: null member handling (documents RFC 8785 behavior)" do
    @describetag :property_surface_q

    property "system_fingerprint: nil and absent produce DIFFERENT hashes (RFC 8785)" do
      check all(envelope <- envelope_gen(), max_runs: @iterations) do
        response = envelope["response"]
        # Build both forms from the same base.
        response_without = Map.delete(response, "system_fingerprint")
        response_with_nil = Map.put(response_without, "system_fingerprint", nil)

        env_without = Map.put(envelope, "response", response_without)
        env_with_nil = Map.put(envelope, "response", response_with_nil)

        bytes_without = Jcs.encode(env_without)
        bytes_with_nil = Jcs.encode(env_with_nil)

        # The with-nil form must contain the literal string `"system_fingerprint":null`.
        assert String.contains?(bytes_with_nil, ~s("system_fingerprint":null))
        refute String.contains?(bytes_without, "system_fingerprint")

        # Therefore hashes DIFFER.
        assert hash(env_without) != hash(env_with_nil)
      end
    end

    property "two absent-system_fingerprint envelopes still match under key-reorder" do
      # A narrower sibling of Property 3, scoped to exercise the pre-hash
      # normalization path where a Gateway implementation that strips nils
      # would produce an envelope indistinguishable from one where the key
      # was never present. Both are `response_without` shape here; reversing
      # insertion order must not change the hash.
      check all(envelope <- envelope_gen(), max_runs: @iterations) do
        response = Map.delete(envelope["response"], "system_fingerprint")
        env = Map.put(envelope, "response", response)

        assert hash(env) == hash(shuffle_map_order(env))
      end
    end
  end
end
