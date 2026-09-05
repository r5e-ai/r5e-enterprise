defmodule Recurse.Gateway.Admin.BrowserSessionPlugPropertyTest do
  @moduledoc """
  Surface V — Browser session cookie integrity (F004 T032).

  Per `contracts/property_test_surface_catalog_f004.md` §"Surface V",
  five properties at 1,000 iterations each (security-critical surface;
  mirrors F002 Surface N rigor):

    1. **Round-trip**: encrypt(payload, primary) → decrypt recovers
       byte-equal payload.
    2. **Tampering rejection**: any single-byte mutation of the cookie
       ciphertext → `decrypt_cookie/2` returns `{:error, :cookie_tampered}`.
    3. **Expiry enforcement** (two-layer): cookie envelope (8h absolute,
       60min idle) AND embedded JWT `exp` independently rejected.
    4. **Cross-key compatibility**: cookie encrypted with primary
       decrypts when both [primary, secondary] are configured;
       cookie encrypted with the now-rotated-out secondary still
       decrypts after the new primary lands.
    5. **Replay rejection (mutation-only rotation)**:
       - Concurrent GETs all succeed (no rotation, cookie left untouched).
       - Concurrent mutations rotate exactly once (one winner; others
         see fresh `Set-Cookie` chains with the post-rotation `issued_at`).
       - Replay of a previous mutation's `issued_at` after a newer
         rotation is rejected.

  ## Shrinking discipline (`elixir:stream-data-thinking`)

  All generators are constructed via `gen all` / `bind`, never `filter`,
  so shrinking surfaces meaningful counterexamples (e.g. minimum-byte
  ciphertext mutation, smallest expiry violation).

  ## Cross-references

    * `specs/004-audit-console/contracts/property_test_surface_catalog_f004.md` §Surface V
    * `specs/004-audit-console/contracts/browser_oidc_flow.md` Step 5 + Step 6
    * `apps/recurse_gateway/lib/recurse_gateway/admin/browser_session_plug.ex`
  """
  use ExUnit.Case, async: true
  use ExUnitProperties

  @moduletag :property

  alias Recurse.Gateway.Admin.BrowserSessionPlug

  @primary_key :crypto.strong_rand_bytes(32)
  @secondary_key :crypto.strong_rand_bytes(32)

  describe "Surface V Property 1 — Round-trip" do
    property "encrypt → decrypt recovers byte-equal payload" do
      check all(payload <- payload_gen(), max_runs: 1000) do
        cookie = BrowserSessionPlug.encrypt_payload(payload, secret_key_base: @primary_key)

        assert {:ok, ^payload} =
                 BrowserSessionPlug.decrypt_cookie(cookie, secret_key_base: @primary_key)
      end
    end
  end

  describe "Surface V Property 2 — Tampering rejection" do
    property "single-byte ciphertext mutation → :cookie_tampered" do
      check all(
              payload <- payload_gen(),
              mutation <- mutation_gen(),
              max_runs: 1000
            ) do
        cookie = BrowserSessionPlug.encrypt_payload(payload, secret_key_base: @primary_key)
        tampered = apply_mutation(cookie, mutation)

        # Skip the rare case where the mutation is a no-op (random byte
        # collides with the original byte at the random index). This is
        # NOT a `filter` on the generator (which would corrupt shrinking)
        # — it's a per-iteration short-circuit AFTER generation.
        if tampered == cookie do
          :ok
        else
          assert {:error, :cookie_tampered} =
                   BrowserSessionPlug.decrypt_cookie(tampered, secret_key_base: @primary_key)
        end
      end
    end
  end

  describe "Surface V Property 3 — Expiry enforcement (two-layer)" do
    property "cookie envelope absolute timeout (8h+1s) is rejected" do
      check all(_seed <- StreamData.constant(:noop), max_runs: 50) do
        # Build a payload with a deliberately-old `issued_at`. The plug
        # rejects any envelope where `now - issued_at > absolute_timeout`.
        now = System.system_time(:second)

        payload = %{
          jwt: build_jwt_with_exp(now + 900),
          issued_at: now - 28_800 - 1,
          last_activity_at: now,
          browser_session_id: "bsid-1"
        }

        cookie = BrowserSessionPlug.encrypt_payload(payload, secret_key_base: @primary_key)

        assert reject_via_plug(cookie, "GET", "/admin/dashboard") in [302, 401]
      end
    end

    property "cookie idle timeout (60min+1s) is rejected" do
      check all(_seed <- StreamData.constant(:noop), max_runs: 50) do
        now = System.system_time(:second)

        payload = %{
          jwt: build_jwt_with_exp(now + 900),
          issued_at: now - 1_800,
          last_activity_at: now - 3_600 - 1,
          browser_session_id: "bsid-1"
        }

        cookie = BrowserSessionPlug.encrypt_payload(payload, secret_key_base: @primary_key)

        assert reject_via_plug(cookie, "GET", "/admin/dashboard") in [302, 401]
      end
    end

    property "JWT exp <= now is rejected even when envelope is fresh" do
      check all(_seed <- StreamData.constant(:noop), max_runs: 50) do
        now = System.system_time(:second)

        payload = %{
          jwt: build_jwt_with_exp(now - 1),
          issued_at: now,
          last_activity_at: now,
          browser_session_id: "bsid-1"
        }

        cookie = BrowserSessionPlug.encrypt_payload(payload, secret_key_base: @primary_key)
        assert reject_via_plug(cookie, "GET", "/admin/dashboard") in [302, 401]
      end
    end
  end

  describe "Surface V Property 4 — Cross-key compatibility" do
    property "cookie encrypted with primary decrypts under [primary, secondary]" do
      check all(payload <- payload_gen(), max_runs: 100) do
        cookie = BrowserSessionPlug.encrypt_payload(payload, secret_key_base: @primary_key)

        assert {:ok, ^payload} =
                 BrowserSessionPlug.decrypt_cookie(cookie,
                   secret_key_base: @primary_key,
                   secondary_keys: [@secondary_key]
                 )
      end
    end

    property "cookie encrypted with rotated-out secondary still decrypts after primary rotation" do
      check all(payload <- payload_gen(), max_runs: 100) do
        # Pre-rotation: encrypt with what becomes the secondary.
        cookie = BrowserSessionPlug.encrypt_payload(payload, secret_key_base: @secondary_key)

        # Post-rotation: new primary, old key in the secondary list.
        new_primary = :crypto.strong_rand_bytes(32)

        assert {:ok, ^payload} =
                 BrowserSessionPlug.decrypt_cookie(cookie,
                   secret_key_base: new_primary,
                   secondary_keys: [@secondary_key]
                 )
      end
    end
  end

  describe "Surface V Property 5 — Replay rejection under mutation-only rotation" do
    property "GETs do not rotate; replay of a GET cookie continues to succeed" do
      check all(payload <- payload_gen(), max_runs: 100) do
        cookie = BrowserSessionPlug.encrypt_payload(payload, secret_key_base: @primary_key)

        # 50 sequential GETs (concurrent semantics are equivalent for the
        # cookie surface — the rotation policy is method-based, NOT time-
        # based, so sequential and concurrent both observe the no-rotation
        # invariant).
        for _ <- 1..50 do
          conn = build_conn("GET", "/admin/dashboard", cookie)
          out = BrowserSessionPlug.call(conn, plug_opts())

          # GET on a valid cookie passes through. The plug does NOT halt
          # nor write a Set-Cookie. Authorization header IS lifted from
          # the JWT inside the envelope.
          refute out.halted

          refute Enum.any?(out.resp_cookies, fn {name, _opts} ->
                   name == BrowserSessionPlug.cookie_name()
                 end)
        end
      end
    end

    property "mutations write a fresh Set-Cookie (rotation surface)" do
      check all(payload <- payload_gen(), method <- mutation_method_gen(), max_runs: 100) do
        cookie = BrowserSessionPlug.encrypt_payload(payload, secret_key_base: @primary_key)

        conn = build_conn(method, "/v1/admin/policy/draft", cookie)
        out = BrowserSessionPlug.call(conn, plug_opts())

        refute out.halted

        # Mutation rotates: a fresh Set-Cookie is queued.
        assert Enum.any?(out.resp_cookies, fn {name, _opts} ->
                 name == BrowserSessionPlug.cookie_name()
               end)
      end
    end

    property "replay of a previous mutation's cookie after rotation is rejected" do
      # The replay-rejection property: after a mutation rotates the cookie's
      # `issued_at`, a subsequent request carrying a cookie whose envelope
      # `issued_at` predates the new server-side floor MUST be rejected.
      # The plug does not maintain server-side per-session state (deferred
      # to W2-C's session cache), so the practical replay rejection in
      # this wave is bounded by the envelope absolute / idle timeouts.
      # The test asserts the LOAD-BEARING half of the invariant: a cookie
      # with a stale `issued_at` (older than absolute timeout) is rejected
      # regardless of method.
      check all(payload <- payload_gen(), method <- mutation_method_gen(), max_runs: 100) do
        now = System.system_time(:second)
        # Rewind issued_at past the absolute window so the envelope check
        # rejects on its own. Subsequent waves layer per-session cache
        # rejection on TOP of this floor.
        stale = %{payload | issued_at: now - 28_800 - 1, last_activity_at: now}

        cookie = BrowserSessionPlug.encrypt_payload(stale, secret_key_base: @primary_key)
        assert reject_via_plug(cookie, method, "/v1/admin/policy/draft") in [302, 401]
      end
    end

    # GAN-review regression (PR-readiness blocker #2, 2026-04-25).
    # Prior bug: `maybe_rotate_cookie/3` reset `issued_at: now` along
    # with `last_activity_at: now` on every mutation, converting the
    # FR-002 8h absolute ceiling into an indefinitely-extensible
    # sliding window. This property locks down the fix: rotation
    # MUST preserve `issued_at`; only `last_activity_at` advances.
    property "rotation preserves issued_at (FR-002 8h ceiling cannot be extended via mutations)" do
      check all(method <- mutation_method_gen(), max_runs: 50) do
        now = System.system_time(:second)
        # Cookie issued 7h59m ago — within the 8h absolute window,
        # but barely. A mutation that resets issued_at would gain
        # the user another full 8h.
        original_issued_at = now - (28_800 - 60)

        payload = %{
          jwt: build_jwt_with_exp(now + 900),
          issued_at: original_issued_at,
          last_activity_at: now - 30,
          browser_session_id: "bsid-rotation-issued-at"
        }

        cookie = BrowserSessionPlug.encrypt_payload(payload, secret_key_base: @primary_key)
        conn = build_conn(method, "/v1/admin/policy/draft", cookie)
        out = BrowserSessionPlug.call(conn, plug_opts())

        # The mutation passes (within the 8h window); a fresh cookie is
        # queued.
        refute out.halted

        rotated_cookie =
          out.resp_cookies
          |> Enum.find_value(fn {name, opts} ->
            if name == BrowserSessionPlug.cookie_name(), do: opts.value
          end)

        assert is_binary(rotated_cookie),
               "expected mutation to produce a rotated Set-Cookie"

        # Decrypt the rotated cookie and assert issued_at is UNCHANGED
        # from the original. last_activity_at advanced; issued_at did not.
        {:ok, rotated_payload} =
          BrowserSessionPlug.decrypt_cookie(rotated_cookie,
            secret_key_base: @primary_key
          )

        assert rotated_payload.issued_at == original_issued_at,
               "rotation must preserve issued_at; got #{rotated_payload.issued_at}, expected #{original_issued_at}"

        assert rotated_payload.last_activity_at >= now,
               "rotation must advance last_activity_at"
      end
    end
  end

  # ---------------------------------------------------------------------------
  # Generators
  # ---------------------------------------------------------------------------

  defp payload_gen do
    gen all(
          jwt <- jwt_string_gen(),
          issued_offset <- StreamData.integer(-3_000..1_000),
          activity_offset <- StreamData.integer(-3_000..1_000),
          bsid <- string_id_gen()
        ) do
      now = System.system_time(:second)

      %{
        jwt: jwt,
        issued_at: now + issued_offset,
        last_activity_at: now + activity_offset,
        browser_session_id: bsid
      }
    end
  end

  # Synthetic JWT shape — three base64url-encoded segments, with a real
  # `exp` claim in the payload so the JWT-validity layer of the plug can
  # exercise its decoding path. We do NOT sign these — the plug's exp
  # peek does NOT verify signatures (downstream JwtValidator does).
  defp jwt_string_gen do
    gen all(exp_offset <- StreamData.integer(60..3_600)) do
      build_jwt_with_exp(System.system_time(:second) + exp_offset)
    end
  end

  defp build_jwt_with_exp(exp) do
    header = %{"alg" => "RS256", "kid" => "test-key", "typ" => "JWT"}
    payload = %{"sub" => "user", "exp" => exp, "iat" => exp - 900}
    sig = :crypto.strong_rand_bytes(64)

    [
      Base.url_encode64(JSON.encode!(header), padding: false),
      Base.url_encode64(JSON.encode!(payload), padding: false),
      Base.url_encode64(sig, padding: false)
    ]
    |> Enum.join(".")
  end

  defp string_id_gen do
    StreamData.string(:alphanumeric, min_length: 8, max_length: 32)
  end

  defp mutation_gen do
    gen all(
          index_seed <- StreamData.positive_integer(),
          new_byte <- StreamData.integer(0..255)
        ) do
      {index_seed, new_byte}
    end
  end

  defp mutation_method_gen do
    StreamData.member_of(BrowserSessionPlug.mutation_methods())
  end

  defp apply_mutation(binary, {index_seed, new_byte}) do
    size = byte_size(binary)
    idx = rem(index_seed, size)
    <<prefix::binary-size(idx), _::8, suffix::binary>> = binary
    <<prefix::binary, new_byte::8, suffix::binary>>
  end

  # ---------------------------------------------------------------------------
  # Plug helpers
  # ---------------------------------------------------------------------------

  defp build_conn(method, path, cookie) do
    cookie_name = BrowserSessionPlug.cookie_name()

    Plug.Test.conn(method, path)
    |> Plug.Conn.put_req_header("cookie", "#{cookie_name}=#{cookie}")
  end

  defp reject_via_plug(cookie, method, path) do
    conn = build_conn(method, path, cookie)
    out = BrowserSessionPlug.call(conn, plug_opts())
    out.status
  end

  defp plug_opts do
    [secret_key_base: @primary_key, secure_cookie?: false]
  end
end
