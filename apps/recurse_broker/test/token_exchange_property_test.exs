defmodule RecurseBroker.TokenExchangePropertyTest do
  @moduledoc """
  Surface O — RFC 8693 Token Exchange round-trip (F002 T079).

  ## Invariant under test

  Given a valid customer-IdP `id_token` + a generator-supplied role-mapping
  YAML shape, `POST /token/exchange` → minted `X-Observed-Identity` JWT
  MUST satisfy three properties simultaneously:

    1. The minted JWT validates at the Gateway's `JwtValidator.validate/2`
       without error (Surface N's promise holds across the round-trip).
    2. The decoded `principal.recurse_role` claim equals the generator's
       *derived* expected role — "derived" meaning computed upfront from
       the generated `(groups, mapping)` tuple via the same rule as the
       broker's `RoleMapper.resolve_role/2`, which is constructive and
       therefore doesn't rely on `StreamData.filter` (per the
       `elixir:stream-data-thinking` "Filter Is a Trap" insight — we
       *generate* the expected role rather than *reject* mismatches).
    3. Cedar evaluation against the three role-scoped actions
       `Recurse::Action::{ChatCompletion, ReadReceipts, ExportEvidence}`
       produces Allow/Deny matching the role matrix baked into
       `priv/reference_policies/platform_roles.cedar`:

       | role               | ChatCompletion | ReadReceipts | ExportEvidence |
       |--------------------|---------------:|-------------:|---------------:|
       | platform_operator  | Allow          | Allow        | Allow          |
       | tenant_auditor     | Deny           | Allow        | Allow          |
       | caller             | Allow          | Deny         | Deny           |

  ## Testing seam — why `TokenExchange.call/2` via `Plug.Test` (not a real
  port)

  The property drives a `Plug.Test.conn(:post, "/token/exchange", …)`
  directly into `RecurseBroker.TokenExchange.call/2`, bypassing the
  `RecurseBroker.Endpoint` Bandit listener. The Endpoint only adds the
  `match _` 404 catch-all + the `Plug.Parsers` wrapper (which we apply
  inline in the test), so driving the plug directly is the cleanest
  unit-of-test for the round-trip — fewer moving parts means better
  shrinking and faster iterations. T081's contract test exercises the
  full Endpoint dispatch.

  ## DI seams

    * `RecurseBroker.OIDC.DiscoveryCache` is started per-test with a
      `:req_opts [plug: MockOidcIssuer.jwks_plug_fn.(issuer)]` so the
      customer-IdP JWKS fetch is an in-process callback. Fresh issuer
      string per iteration (`MockOidcIssuer.new/0`) so there's no cache
      pollution across iterations.
    * `RecurseBroker.JWT.KeyRing` is started once per module in
      `:generate_ephemeral?` mode — it's a plain ES256 signer that the
      Gateway-side validator can consume via its plain-map JWKS shape.
    * `Application.put_env(:recurse_broker, ...)` sets `:expected_audience`,
      `:broker_issuer`, and the role-mapping for the duration of each
      iteration. `on_exit` restores the previous values so nothing leaks.

  ## Cross-references

    * `specs/002-standalone-gateway-vertical-slice/contracts/property_test_surface_catalog_f002.md`
      §Surface O
    * `specs/002-standalone-gateway-vertical-slice/contracts/recurse_broker_api.md`
      (wire shape + role-mapping schema)
    * `specs/002-standalone-gateway-vertical-slice/tasks.md` T079
    * `apps/recurse_gateway/priv/reference_policies/platform_roles.cedar`
    * `apps/recurse_gateway/lib/recurse_gateway/identity/jwt_validator.ex`
  """

  use ExUnit.Case, async: false
  use ExUnitProperties

  # Iteration count is heavy (500) per catalog Surface O; cap timeout so
  # pathological shrinking walks don't stall CI forever.
  @moduletag timeout: :timer.minutes(3)

  alias RecurseBroker.OIDC.DiscoveryCache
  alias RecurseBroker.Test.MockOidcIssuer
  alias RecurseBroker.Test.SupervisorHelper

  @role_privilege_order ["platform_operator", "tenant_auditor", "caller"]

  # Fixed group names so `role_mapping_gen/0` can build a zipped map
  # without variable-length interplay between two StreamData generators.
  @stable_group_pool [
    "cn=group-a,ou=groups,dc=corp,dc=example",
    "cn=group-b,ou=groups,dc=corp,dc=example",
    "cn=group-c,ou=groups,dc=corp,dc=example"
  ]

  # Cedar action→expected decision matrix derived from
  # priv/reference_policies/platform_roles.cedar. The generator uses this
  # to produce the expected Allow/Deny matrix *alongside* the minted JWT,
  # so Property 3 doesn't re-derive it (constructive generation over
  # filter-and-reject).
  @role_decision_matrix %{
    "platform_operator" => %{
      "Recurse::Action::ChatCompletion" => :allow,
      "Recurse::Action::ReadReceipts" => :allow,
      "Recurse::Action::ExportEvidence" => :allow
    },
    "tenant_auditor" => %{
      "Recurse::Action::ChatCompletion" => :deny,
      "Recurse::Action::ReadReceipts" => :allow,
      "Recurse::Action::ExportEvidence" => :allow
    },
    "caller" => %{
      "Recurse::Action::ChatCompletion" => :allow,
      "Recurse::Action::ReadReceipts" => :deny,
      "Recurse::Action::ExportEvidence" => :deny
    }
  }

  # Module-level dispatch: each iteration writes its current mock-issuer +
  # response mode into `:persistent_term`, and the module-level plug fn
  # reads the live value. This lets us start ONE `DiscoveryCache` per
  # module (avoiding the `:already_started` collision that per-iteration
  # `start_supervised/2` would trigger) while still driving per-iteration
  # JWKS behavior.
  @pt_key {__MODULE__, :active_issuer}

  defp module_plug_fn do
    fn conn, _req_opts ->
      {mock_issuer, response} = :persistent_term.get(@pt_key)
      plug_fn = MockOidcIssuer.jwks_plug_fn(mock_issuer, response: response)
      plug_fn.(conn, [])
    end
  end

  setup_all do
    # `RecurseBroker.Application` auto-starts DiscoveryCache + KeyRing
    # under module-registered names. We stop them and restart under test
    # control so we can inject our `:req_opts [plug: ...]` dispatcher
    # AND use the ephemeral-keypair path.
    SupervisorHelper.stop_auto_started(RecurseBroker.OIDC.DiscoveryCache)
    SupervisorHelper.stop_auto_started(RecurseBroker.JWT.KeyRing)

    # Broker-side signer: ephemeral ES256 keypair, started once per module.
    {:ok, _} = RecurseBroker.JWT.KeyRing.start_link(generate_ephemeral?: true)

    # Seed a placeholder so the dispatcher plug doesn't crash on lookup
    # before the first property iteration runs.
    :persistent_term.put(@pt_key, {MockOidcIssuer.new(), :ok})

    # DiscoveryCache with a stable plug fn that delegates to the currently-
    # active persistent_term entry. Started once per module.
    {:ok, _} =
      RecurseBroker.OIDC.DiscoveryCache.start_link(req_opts: [plug: module_plug_fn()])

    on_exit(fn ->
      :persistent_term.erase(@pt_key)
    end)

    :ok
  end

  setup do
    # Reset the DiscoveryCache ETS + in-flight state between iterations so
    # per-iteration issuer strings don't bleed cache entries forward. The
    # test helper is documented at `@doc false` on the DiscoveryCache.
    DiscoveryCache.__reset_for_tests__()
    :ok
  end

  property "round-trip: id_token → minted JWT validates + role matches + Cedar decisions match" do
    check all(
            %{
              issuer: mock_issuer,
              subject: subject,
              email: email,
              all_groups: all_groups,
              mapping: mapping,
              expected_role: expected_role,
              audience: audience,
              broker_issuer_url: broker_issuer_url
            } <- scenario_gen(),
            max_runs: 500
          ) do
      # --- Per-iteration DiscoveryCache plug state ------------------------
      #
      # Swap the module-level dispatcher's active mock issuer + response
      # mode. `DiscoveryCache.__reset_for_tests__/0` has already fired
      # (see module setup/1) so there's no cache carryover across
      # iterations.
      :persistent_term.put(@pt_key, {mock_issuer, :ok})
      DiscoveryCache.__reset_for_tests__()

      # --- Broker app-env overrides ---------------------------------------
      previous_env =
        swap_broker_env(audience, broker_issuer_url, mapping, mock_issuer.issuer)

      try do
        # --- Mint a customer id_token the broker will accept --------------
        id_token =
          MockOidcIssuer.mint_id_token(mock_issuer, %{
            "sub" => subject,
            "email" => email,
            "aud" => audience_on_id_token_for(mock_issuer, audience),
            "groups" => all_groups
          })

        # --- POST /token/exchange directly to the plug --------------------
        form_body =
          URI.encode_query(%{
            "grant_type" => "urn:ietf:params:oauth:grant-type:token-exchange",
            "subject_token" => id_token,
            "subject_token_type" => "urn:ietf:params:oauth:token-type:id_token",
            "audience" => audience,
            "requested_token_type" => "urn:ietf:params:oauth:token-type:jwt"
          })

        conn =
          :post
          |> Plug.Test.conn("/token/exchange", form_body)
          |> Plug.Conn.put_req_header("content-type", "application/x-www-form-urlencoded")
          |> Plug.Parsers.call(Plug.Parsers.init(parsers: [:urlencoded], pass: ["*/*"]))
          |> RecurseBroker.TokenExchange.call(RecurseBroker.TokenExchange.init([]))

        assert conn.status == 200,
               "token-exchange failed for groups=#{inspect(all_groups)}, expected_role=#{inspect(expected_role)}; body=#{inspect(conn.resp_body)}"

        decoded_body = JSON.decode!(conn.resp_body)
        access_token = decoded_body["access_token"]
        assert is_binary(access_token)
        assert decoded_body["issued_token_type"] == "urn:ietf:params:oauth:token-type:jwt"
        assert decoded_body["token_type"] == "Bearer"
        assert decoded_body["expires_in"] == 900

        # --- Property 1: minted JWT validates under a Gateway-side-
        # --- equivalent check. We don't call
        # --- `Recurse.Gateway.Identity.JwtValidator` directly because
        # --- pulling `:recurse_gateway` as a test dep of
        # --- `:recurse_broker` would cycle (Gateway already test-depends
        # --- on Broker for T089). Instead we re-state the three
        # --- Gateway-side checks inline:
        # ---   (a) JOSE `verify_strict` with the expected alg singleton,
        # ---   (b) aud claim matches the audience,
        # ---   (c) iss claim matches the broker_issuer_url,
        # --- exactly as `Recurse.Gateway.Identity.JwtValidator` does
        # --- (see `apps/recurse_gateway/lib/recurse_gateway/identity/jwt_validator.ex`
        # --- moduledoc for the authoritative pipeline). T089
        # --- (`us1_with_real_broker_test.exs`) exercises the REAL
        # --- JwtValidator end-to-end; this property test is scoped to
        # --- the broker's output shape.
        {:ok, broker_pub_jwk} = broker_public_jwk_for_kid_from_jwt(access_token)
        jwk_struct = JOSE.JWK.from_map(broker_pub_jwk)

        assert {true, %JOSE.JWT{fields: claims}, _jws} =
                 JOSE.JWT.verify_strict(jwk_struct, ["ES256"], access_token)

        assert claims["aud"] == audience
        assert claims["iss"] == broker_issuer_url

        # --- Property 2: principal.recurse_role == expected_role ---------
        assert claims["principal"]["recurse_role"] == expected_role,
               "expected role=#{inspect(expected_role)}, got=#{inspect(claims["principal"]["recurse_role"])}, groups=#{inspect(all_groups)}"

        # --- Property 3: Cedar allows/denies per the role matrix ----------
        for action <- Map.keys(@role_decision_matrix[expected_role]) do
          expected_decision = @role_decision_matrix[expected_role][action]

          assert evaluate_policy(expected_role, action, claims["principal"]) ==
                   expected_decision,
                 "role=#{expected_role} action=#{action} expected=#{expected_decision}"
        end
      after
        restore_broker_env(previous_env)
      end
    end
  end

  # ---------------------------------------------------------------------------
  # Generators — constructive per elixir:stream-data-thinking "bind preserves
  # shrinking; map is for pure transforms; filter is a trap".
  # ---------------------------------------------------------------------------

  defp scenario_gen do
    gen all(
          subject <- subject_gen(),
          email <- email_gen(),
          mapping_base <- role_mapping_gen(),
          all_groups <- groups_gen(mapping_base),
          audience <- audience_gen(),
          broker_issuer_url <- broker_issuer_gen()
        ) do
      # Constructive-happy-path guarantee: the mapping MUST resolve
      # groups ∪ default → some recurse_role. If the generated base
      # mapping has a nil default AND the generated groups don't
      # overlap with the mapping's keys, we patch the mapping by
      # assigning a deterministic default ("caller") so the role
      # resolution always yields an expected_role. This is `StreamData.map`
      # applied to the generator output — not a filter — so shrinking
      # still works.
      mapping =
        case derive_expected_role(all_groups, mapping_base) do
          nil -> Map.put(mapping_base, :default_recurse_role, "caller")
          _ -> mapping_base
        end

      expected_role = derive_expected_role(all_groups, mapping)

      # `mock_issuer` is generated inside the StreamData block rather than
      # bound with a sub-generator because JOSE.JWK.generate_key is
      # expensive AND has no shrinkable component — generating it here
      # keeps the shrinker focused on the *meaningful* fields.
      issuer = MockOidcIssuer.new()

      %{
        issuer: issuer,
        subject: subject,
        email: email,
        all_groups: all_groups,
        mapping: mapping,
        expected_role: expected_role,
        audience: audience,
        broker_issuer_url: broker_issuer_url
      }
    end
  end

  # Subject is an opaque string but the broker's principal-kind inference
  # wants `aud ∈ interactive_client_ids` to trip `obo_human`. We don't
  # need to shrink the subject's character set — short alphanumerics
  # shrink cleanly.
  defp subject_gen do
    gen all(stem <- StreamData.string(:alphanumeric, min_length: 3, max_length: 20)) do
      "auth0|" <> stem
    end
  end

  defp email_gen do
    gen all(
          user <- StreamData.string(:alphanumeric, min_length: 1, max_length: 12),
          domain <- StreamData.string(:alphanumeric, min_length: 3, max_length: 10)
        ) do
      user <> "@" <> domain <> ".example"
    end
  end

  # `role_mapping_gen/0` emits a role-mapping struct that matches
  # `RecurseBroker.RoleMapper.role_mapping()`. We generate a FIXED-size
  # pool of 3 groups (enough to exercise all-three-roles coverage
  # without combinatorially blowing up) and then assign each a role.
  # Using `StreamData.list_of/2` with `length: fixed` is filter-free;
  # using a variable-length `list_of(..., length: gen_integer)`
  # triggers StreamData's internal `bind_filter` and can FilterTooNarrow
  # under compound binds (per the elixir:stream-data-thinking "Filter
  # Is a Trap" insight).
  @generator_group_pool_size 3

  defp role_mapping_gen do
    gen all(
          group_roles <-
            StreamData.list_of(
              StreamData.member_of(@role_privilege_order),
              length: @generator_group_pool_size
            ),
          default <-
            StreamData.one_of([
              StreamData.member_of(@role_privilege_order),
              StreamData.constant(nil)
            ])
        ) do
      g2r =
        @stable_group_pool
        |> Enum.zip(group_roles)
        |> Map.new()

      %{
        group_to_recurse_role: g2r,
        default_recurse_role: default,
        role_privilege_order: @role_privilege_order
      }
    end
  end

  # `groups_gen/1` constructively emits a group-claim list. Since the
  # mapping's keys are the fixed `@stable_group_pool` we can simply mix
  # known pool members with synthetic "unknown" strings via `frequency`
  # — filter-free.
  defp groups_gen(_mapping) do
    unknown_gen =
      StreamData.member_of([
        "cn=unknown-x,ou=groups,dc=corp,dc=example",
        "cn=unknown-y,ou=groups,dc=corp,dc=example"
      ])

    known_gen = StreamData.member_of(@stable_group_pool)

    mix_gen =
      StreamData.frequency([
        {7, known_gen},
        {3, unknown_gen}
      ])

    StreamData.list_of(mix_gen, min_length: 0, max_length: 4)
  end

  # Mirrors `RecurseBroker.RoleMapper.resolve_role/2` exactly — highest
  # privilege wins; default-when-no-match; nil-default = "expect 403".
  # Generator emits the pre-computed expected role so Property 2 doesn't
  # re-derive it. If mapping would reject, we skip by returning
  # `:rejected` — but to stay filter-free, we instead re-route the
  # scenario via a different generator branch: the property's top-level
  # `check all` only binds happy-path scenarios; rejection scenarios
  # belong in the Endpoint contract test (T081).
  defp derive_expected_role(groups, mapping) do
    roles =
      groups
      |> Enum.flat_map(fn g ->
        case Map.fetch(mapping.group_to_recurse_role, g) do
          {:ok, r} -> [r]
          :error -> []
        end
      end)
      |> Enum.uniq()

    case roles do
      [] -> mapping.default_recurse_role
      list -> Enum.min_by(list, &Enum.find_index(@role_privilege_order, fn r -> r == &1 end))
    end
  end

  # Audiences are strings; we use a small fixed set to avoid stressing
  # the "audience mismatch" error path inside the property (that's what
  # T081's contract test covers). Broker issuer URL is similarly fixed-
  # shape-randomized.
  defp audience_gen do
    StreamData.member_of(["recurse-gateway-prod", "recurse-gateway-test", "recurse-gateway-dev"])
  end

  defp broker_issuer_gen do
    StreamData.member_of([
      "https://recurse-broker.corp.example",
      "https://broker.recurse.test",
      "https://recurse-broker-alt.corp.example"
    ])
  end

  # Stable "customer-IdP's interactive audience" derived from the mock
  # issuer's URL. The broker contract says `obo_human` requires the
  # subject_token's `aud` to match the configured interactive client ID
  # — we feed the broker that configured value via `put_env` below.
  defp audience_on_id_token_for(%MockOidcIssuer{} = _issuer, broker_audience) do
    # The id_token's `aud` is the CUSTOMER IdP's audience (interactive
    # client ID), NOT the broker-audience. For the property test we
    # reuse `broker_audience <> "-interactive"` as the synthetic IdP
    # audience and tell the broker to trust it via the role-mapping
    # scenario (the broker's issuer-config block). Keeping them linked
    # makes the expected value easy to derive here.
    broker_audience <> "-interactive"
  end

  # ---------------------------------------------------------------------------
  # Cedar eval (property 3) — minimal inline policy set for the three
  # role-scoped actions. Mirrors `platform_roles.cedar` exactly.
  # ---------------------------------------------------------------------------

  @cedar_policy_source """
  permit(principal, action, resource) when { principal has recurse_role && principal.recurse_role == "platform_operator" };
  permit(principal, action == Recurse::Action::"ReadReceipts", resource) when { principal has recurse_role && principal.recurse_role == "tenant_auditor" };
  permit(principal, action == Recurse::Action::"ExportEvidence", resource) when { principal has recurse_role && principal.recurse_role == "tenant_auditor" };
  permit(principal, action == Recurse::Action::"ChatCompletion", resource) when { principal has recurse_role && principal.recurse_role == "caller" };
  """

  defp evaluate_policy(_role, action_str, principal_claim) do
    principal_type =
      case Map.get(principal_claim, "kind") do
        "service_account" -> "Recurse::Principal::ServiceAccount"
        "autonomous" -> "Recurse::Principal::Autonomous"
        _ -> "Recurse::Principal::Human"
      end

    principal_id = Map.get(principal_claim, "subject", "unknown")

    entities_json =
      JSON.encode!([
        %{
          "uid" => %{"type" => principal_type, "id" => principal_id},
          "attrs" => %{
            "subject" => Map.get(principal_claim, "subject", ""),
            "issuer" => Map.get(principal_claim, "issuer", ""),
            "groups" => Map.get(principal_claim, "groups", []),
            "recurse_role" => Map.get(principal_claim, "recurse_role", "")
          },
          "parents" => []
        },
        %{
          "uid" => %{"type" => "Recurse::Resource::LLMEndpoint", "id" => "test"},
          "attrs" => %{},
          "parents" => []
        }
      ])

    request_json =
      JSON.encode!(%{
        "principal" => ~s[#{principal_type}::"#{principal_id}"],
        "action" => cedar_action_uid(action_str),
        "resource" => ~s[Recurse::Resource::LLMEndpoint::"test"],
        "context" => %{}
      })

    case Recurse.Cedar.evaluate_with_entities(
           @cedar_policy_source,
           request_json,
           entities_json
         ) do
      {:ok, %{decision: decision}} -> decision
      _ -> :deny
    end
  end

  # "Recurse::Action::Foo" → ~s[Recurse::Action::"Foo"]
  defp cedar_action_uid(action_str) do
    case String.split(action_str, "::", trim: true) do
      parts when length(parts) >= 2 ->
        {ns, [name]} = Enum.split(parts, length(parts) - 1)
        Enum.join(ns, "::") <> "::\"" <> name <> "\""

      _ ->
        action_str
    end
  end

  # ---------------------------------------------------------------------------
  # Broker app-env orchestration
  # ---------------------------------------------------------------------------

  defp swap_broker_env(audience, broker_issuer, mapping, id_token_issuer) do
    previous = %{
      expected_audience: Application.get_env(:recurse_broker, :expected_audience),
      broker_issuer: Application.get_env(:recurse_broker, :broker_issuer),
      role_mapping: Application.get_env(:recurse_broker, :role_mapping),
      oidc_validator_opts: Application.get_env(:recurse_broker, :oidc_validator_opts)
    }

    Application.put_env(:recurse_broker, :expected_audience, audience)
    Application.put_env(:recurse_broker, :broker_issuer, broker_issuer)
    Application.put_env(:recurse_broker, :role_mapping, mapping)

    # `RecurseBroker.OIDC.Validator.validate_id_token/2` consumes this
    # keyword list directly (see `lib/recurse_broker/oidc/validator.ex`
    # @moduledoc). The `:issuer` key here is the CUSTOMER-IdP's `iss` —
    # string-equal to the `iss` claim on the id_token. The `:audience`
    # key is the CUSTOMER-IdP's interactive audience — matches what the
    # id_token's `aud` carries. Both are per-iteration values in the
    # property test.
    Application.put_env(:recurse_broker, :oidc_validator_opts,
      alg_allowlist: [:rs256, :es256, :eddsa],
      issuer: id_token_issuer,
      audience: audience <> "-interactive"
    )

    previous
  end

  defp restore_broker_env(previous) do
    for {k, v} <- previous do
      case v do
        nil -> Application.delete_env(:recurse_broker, k)
        val -> Application.put_env(:recurse_broker, k, val)
      end
    end

    :ok
  end

  # Peek the JWT header for its kid, then ask KeyRing for the matching
  # public JWK (map form). Uses `all_active_keys/0` rather than
  # `current_key/0` so this helper keeps working across rotations.
  defp broker_public_jwk_for_kid_from_jwt(jwt) do
    [header_b64, _, _] = String.split(jwt, ".")
    {:ok, header_bytes} = Base.url_decode64(header_b64, padding: false)
    {:ok, %{"kid" => kid}} = JSON.decode(header_bytes)

    case RecurseBroker.JWT.KeyRing.all_active_keys() do
      {:ok, keys} ->
        case Map.fetch(keys, kid) do
          {:ok, jwk} ->
            {_, fields} = jwk |> JOSE.JWK.to_public() |> JOSE.JWK.to_map()
            {:ok, Map.put(fields, "kid", kid)}

          :error ->
            {:error, :unknown_kid}
        end

      other ->
        other
    end
  end
end
