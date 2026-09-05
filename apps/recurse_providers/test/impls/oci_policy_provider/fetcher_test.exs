defmodule Recurse.Providers.Impls.OciPolicyProvider.FetcherTest do
  @moduledoc """
  Unit tests for `Recurse.Providers.Impls.OciPolicyProvider.Fetcher`.

  Drives the real implementation against an isolated
  `Recurse.Providers.Support.MockHttpUpstream` (Bypass-equivalent — see
  `test/support/mock_http_upstream.ex` for why we don't use the Hex
  bypass package directly).

  Coverage:

    * Happy path: manifest fetch, layer fetch with declared filenames,
      signature manifest fetch + signature blob extraction
    * Manifest 404 → `{:error, {:manifest_not_found, _}}`
    * 401 on first call (no cached ECR token) triggers
      `aws ecr get-authorization-token` shell-out, retries with bearer,
      succeeds on second attempt
    * Layer digest mismatch (registry returned wrong bytes) →
      `{:error, {:blob_digest_mismatch, ...}}`
  """

  use ExUnit.Case, async: true

  alias Recurse.Providers.Impls.OciPolicyProvider.Fetcher
  alias Recurse.Providers.Support.MockHttpUpstream

  # --- Shared setup -------------------------------------------------------

  setup ctx do
    {:ok, upstream} = MockHttpUpstream.start()
    on_exit(fn -> MockHttpUpstream.stop(upstream) end)

    base_url = MockHttpUpstream.url(upstream)

    base_ctx = %{
      registry: "127.0.0.1:#{upstream.port}",
      repository: "cedar-policies/platform-roles",
      ref: "0.1.0-test",
      auth: :none,
      cosign_key_arn: "alias/test-cosign",
      config: %{registry_base_url: base_url, fetch_timeout_ms: 2_000}
    }

    Map.merge(ctx, %{upstream: upstream, base_ctx: base_ctx, base_url: base_url})
  end

  # --- fetch_manifest/1 ---------------------------------------------------

  describe "fetch_manifest/1" do
    test "happy path returns manifest doc + raw sha-256 digest + bytes", %{
      upstream: upstream,
      base_ctx: ctx
    } do
      manifest_bytes = sample_manifest_bytes()

      MockHttpUpstream.expect(upstream, fn conn ->
        assert conn.method == "GET"
        assert conn.request_path == "/v2/cedar-policies/platform-roles/manifests/0.1.0-test"

        accept = header_value(conn, "accept")
        assert accept == "application/vnd.oci.image.manifest.v1+json"

        conn
        |> Plug.Conn.put_resp_header("content-type", "application/vnd.oci.image.manifest.v1+json")
        |> Plug.Conn.send_resp(200, manifest_bytes)
      end)

      assert {:ok, doc, digest, bytes} = Fetcher.fetch_manifest(ctx)
      assert is_map(doc)
      assert doc["mediaType"] == "application/vnd.oci.image.manifest.v1+json"
      assert is_list(doc["layers"])

      assert byte_size(digest) == 32
      assert digest == :crypto.hash(:sha256, manifest_bytes)
      assert bytes == manifest_bytes
    end

    test "404 from registry returns {:error, {:manifest_not_found, _}}", %{
      upstream: upstream,
      base_ctx: ctx
    } do
      MockHttpUpstream.expect(upstream, fn conn ->
        Plug.Conn.send_resp(conn, 404, ~s|{"errors":[{"code":"MANIFEST_UNKNOWN"}]}|)
      end)

      assert {:error, {:manifest_not_found, url}} = Fetcher.fetch_manifest(ctx)
      assert is_binary(url)
      assert url =~ "/v2/cedar-policies/platform-roles/manifests/0.1.0-test"
    end

    test "401 with ecr_irsa auth refreshes token via aws cli stub and retries", %{
      upstream: upstream,
      base_ctx: ctx
    } do
      manifest_bytes = sample_manifest_bytes()
      parent = self()

      # Each pull-of-the-cache will reuse this mock; one shell-out per
      # uncached region. We use a globally-unique region per test run so
      # the :persistent_term cache from any prior test cannot interfere.
      region = "us-test-#{:erlang.unique_integer([:positive])}"

      ecr_token =
        Base.encode64(
          "AWS:fresh-token-" <> Integer.to_string(:erlang.unique_integer([:positive]))
        )

      ctx =
        %{
          ctx
          | auth: {:ecr_irsa, region},
            config:
              Map.put(ctx.config, :aws_ecr_cmd, fn args ->
                send(parent, {:aws_cmd, args})
                {:ok, ecr_token}
              end)
        }

      # Fully-stateful expectation: counter agent flips behavior across
      # successive requests to the same path.
      {:ok, counter} = Agent.start_link(fn -> 0 end)
      on_exit(fn -> if Process.alive?(counter), do: Agent.stop(counter) end)

      MockHttpUpstream.expect(upstream, fn conn ->
        n = Agent.get_and_update(counter, fn n -> {n, n + 1} end)
        send(parent, {:request, n, header_value(conn, "authorization")})

        case n do
          0 ->
            Plug.Conn.send_resp(conn, 401, ~s|{"errors":[{"code":"UNAUTHORIZED"}]}|)

          _ ->
            conn
            |> Plug.Conn.put_resp_header(
              "content-type",
              "application/vnd.oci.image.manifest.v1+json"
            )
            |> Plug.Conn.send_resp(200, manifest_bytes)
        end
      end)

      assert {:ok, _doc, _digest, ^manifest_bytes} = Fetcher.fetch_manifest(ctx)

      # First call: cached token is empty so we shell out, get back the
      # token, hit the registry, get a 401.
      assert_received {:aws_cmd, args}
      assert "ecr" in args
      assert "get-authorization-token" in args
      assert "--region" in args
      assert region in args

      assert_received {:request, 0, "Basic " <> _}

      # Second call: registry returned 401, we invalidated the cache,
      # re-shelled out, retried — got 200.
      assert_received {:aws_cmd, _}
      assert_received {:request, 1, "Basic " <> _}
    end
  end

  # --- fetch_layers/2 -----------------------------------------------------

  describe "fetch_layers/2" do
    test "pulls each declared layer, uses image.title annotation as filename", %{
      upstream: upstream,
      base_ctx: ctx
    } do
      policy_bytes = "permit(principal, action, resource);"
      schema_bytes = ~s|{"User":{"shape":"Record"}}|
      meta_bytes = ~s|{"name":"platform-roles","version":"0.1.0"}|

      manifest = manifest_with_layers(policy_bytes, schema_bytes, meta_bytes)

      MockHttpUpstream.expect(upstream, fn conn ->
        assert conn.method == "GET"

        case conn.request_path do
          "/v2/cedar-policies/platform-roles/blobs/" <> digest ->
            # URL digest carries the "sha256:" prefix; helper returns hex only.
            stripped = String.replace_prefix(digest, "sha256:", "")

            cond do
              stripped == digest_for(policy_bytes) ->
                Plug.Conn.send_resp(conn, 200, policy_bytes)

              stripped == digest_for(schema_bytes) ->
                Plug.Conn.send_resp(conn, 200, schema_bytes)

              stripped == digest_for(meta_bytes) ->
                Plug.Conn.send_resp(conn, 200, meta_bytes)

              true ->
                Plug.Conn.send_resp(conn, 404, "")
            end

          other ->
            Plug.Conn.send_resp(conn, 500, "unexpected path: #{other}")
        end
      end)

      assert {:ok, layers} = Fetcher.fetch_layers(ctx, manifest)

      filenames = Enum.map(layers, & &1.filename)
      assert "policy.cedar" in filenames
      assert "entities.cedarschema.json" in filenames
      assert "manifest.json" in filenames

      policy_layer = Enum.find(layers, &(&1.filename == "policy.cedar"))
      assert policy_layer.bytes == policy_bytes
      assert policy_layer.media_type == "application/vnd.cedar.policy.v1.layer"
    end

    test "registry-returned bytes that don't match declared digest fail loudly", %{
      upstream: upstream,
      base_ctx: ctx
    } do
      declared_bytes = "the cedar bytes the manifest claims"
      tampered_bytes = "DIFFERENT BYTES THE REGISTRY ACTUALLY RETURNED"

      manifest = %{
        "mediaType" => "application/vnd.oci.image.manifest.v1+json",
        "layers" => [
          %{
            "mediaType" => "application/vnd.cedar.policy.v1.layer",
            "digest" => "sha256:" <> digest_for(declared_bytes),
            "size" => byte_size(declared_bytes),
            "annotations" => %{"org.opencontainers.image.title" => "policy.cedar"}
          }
        ]
      }

      MockHttpUpstream.expect(upstream, fn conn ->
        # Registry hands back tampered bytes — Fetcher's verify step
        # must catch this BEFORE cosign sees the artifact.
        Plug.Conn.send_resp(conn, 200, tampered_bytes)
      end)

      assert {:error, {:blob_digest_mismatch, info}} = Fetcher.fetch_layers(ctx, manifest)
      assert Keyword.fetch!(info, :expected) == digest_for(declared_bytes)
      assert Keyword.fetch!(info, :actual) == digest_for(tampered_bytes)
    end
  end

  # --- fetch_signature_artifact/2 -----------------------------------------

  describe "fetch_signature_artifact/2" do
    test "fetches sha256-<hex>.sig sibling tag, returns {manifest, layer, blob} tuple", %{
      upstream: upstream,
      base_ctx: ctx
    } do
      sig_payload = :crypto.strong_rand_bytes(96)

      manifest_digest = :crypto.hash(:sha256, "fake-manifest-bytes")
      sig_tag = "sha256-" <> Base.encode16(manifest_digest, case: :lower) <> ".sig"
      payload_digest_hex = digest_for(sig_payload)

      sig_manifest = %{
        "mediaType" => "application/vnd.oci.image.manifest.v1+json",
        "layers" => [
          %{
            "mediaType" => "application/vnd.dev.cosign.simplesigning.v1+json",
            "digest" => "sha256:" <> payload_digest_hex,
            "size" => byte_size(sig_payload),
            "annotations" => %{
              "dev.cosignproject.cosign/signature" => Base.encode64("not-a-real-sig")
            }
          }
        ]
      }

      sig_manifest_bytes = JSON.encode!(sig_manifest)

      MockHttpUpstream.expect(upstream, fn conn ->
        cond do
          conn.request_path ==
              "/v2/cedar-policies/platform-roles/manifests/#{sig_tag}" ->
            conn
            |> Plug.Conn.put_resp_header(
              "content-type",
              "application/vnd.oci.image.manifest.v1+json"
            )
            |> Plug.Conn.send_resp(200, sig_manifest_bytes)

          conn.request_path ==
              "/v2/cedar-policies/platform-roles/blobs/sha256:#{payload_digest_hex}" ->
            Plug.Conn.send_resp(conn, 200, sig_payload)

          true ->
            Plug.Conn.send_resp(conn, 404, "")
        end
      end)

      assert {:ok,
              %{
                manifest: returned_manifest,
                layer: returned_layer,
                layer_blob_bytes: ^sig_payload
              }} = Fetcher.fetch_signature_artifact(ctx, manifest_digest)

      assert returned_manifest == sig_manifest
      assert returned_layer["mediaType"] == "application/vnd.dev.cosign.simplesigning.v1+json"
      assert returned_layer["digest"] == "sha256:" <> payload_digest_hex
    end

    test "rejects digests that aren't 32 raw bytes", %{base_ctx: ctx} do
      assert {:error, {:invalid_manifest_digest, _}} =
               Fetcher.fetch_signature_artifact(ctx, "not-a-real-digest")
    end
  end

  # --- helpers ------------------------------------------------------------

  defp sample_manifest_bytes do
    JSON.encode!(%{
      "schemaVersion" => 2,
      "mediaType" => "application/vnd.oci.image.manifest.v1+json",
      "artifactType" => "application/vnd.cedar.policy.v1",
      "layers" => [
        %{
          "mediaType" => "application/vnd.cedar.policy.v1.layer",
          "digest" => "sha256:#{digest_for("permit(principal, action, resource);")}",
          "size" => byte_size("permit(principal, action, resource);"),
          "annotations" => %{"org.opencontainers.image.title" => "policy.cedar"}
        }
      ]
    })
  end

  defp manifest_with_layers(policy_bytes, schema_bytes, meta_bytes) do
    %{
      "schemaVersion" => 2,
      "mediaType" => "application/vnd.oci.image.manifest.v1+json",
      "artifactType" => "application/vnd.cedar.policy.v1",
      "layers" => [
        %{
          "mediaType" => "application/vnd.cedar.policy.v1.layer",
          "digest" => "sha256:" <> digest_for(policy_bytes),
          "size" => byte_size(policy_bytes),
          "annotations" => %{"org.opencontainers.image.title" => "policy.cedar"}
        },
        %{
          "mediaType" => "application/vnd.cedar.schema.v1.layer",
          "digest" => "sha256:" <> digest_for(schema_bytes),
          "size" => byte_size(schema_bytes),
          "annotations" => %{"org.opencontainers.image.title" => "entities.cedarschema.json"}
        },
        %{
          "mediaType" => "application/vnd.cedar.manifest.v1.layer",
          "digest" => "sha256:" <> digest_for(meta_bytes),
          "size" => byte_size(meta_bytes),
          "annotations" => %{"org.opencontainers.image.title" => "manifest.json"}
        }
      ]
    }
  end

  defp digest_for(bytes) when is_binary(bytes) do
    Base.encode16(:crypto.hash(:sha256, bytes), case: :lower)
  end

  defp header_value(conn, name) do
    Enum.find_value(conn.req_headers, fn {k, v} ->
      if String.downcase(k) == String.downcase(name), do: v
    end)
  end
end
