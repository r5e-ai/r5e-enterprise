defmodule Recurse.Gateway.Fold.AdmissionBoundaryTest do
  use ExUnit.Case, async: false

  alias Recurse.Gateway.Fold.Admission
  alias Recurse.Gateway.Policy.Active
  alias Recurse.Gateway.PolicyBundleRef
  alias Recurse.Shared.LlmProxy.ToolUseIntent

  setup do
    previous = Application.get_all_env(:r5e)
    Application.stop(:recurse_fold)
    Application.stop(:r5e)

    dir =
      Path.join(System.tmp_dir!(), "r5e-admission-boundary-#{System.unique_integer([:positive])}")

    Application.put_env(:r5e, :data_dir, dir)
    Application.put_env(:r5e, :start_server, false)
    Application.put_env(:r5e, :seed_kernel_policy, true)
    Application.put_env(:r5e, :policy, Recurse.Fold.Policy.Cedar)
    Application.delete_env(:recurse_fold, :engine_build_address)
    {:ok, _} = Application.ensure_all_started(:recurse_fold)
    Active.erase()

    on_exit(fn ->
      Application.stop(:recurse_fold)
      Application.stop(:r5e)
      for {key, _} <- Application.get_all_env(:r5e), do: Application.delete_env(:r5e, key)
      for {key, value} <- previous, do: Application.put_env(:r5e, key, value)
      Active.erase()
      File.rm_rf!(dir)
    end)

    %{
      context: %{
        principal: %{id: "alice", kind: :user, claims: %{"groups" => ["engineers"]}},
        tenant: "tenant-a",
        model: "test-model",
        started_at: DateTime.utc_now(),
        transport: :https_sse
      }
    }
  end

  defp activate(source) do
    hash = Recurse.Cedar.canonical_hash(source)

    Active.update(%Active{
      source: :filesystem,
      source_ref: "test-policy",
      loaded_at: DateTime.utc_now(),
      bundle: %PolicyBundleRef{
        bundle_id: Base.encode16(hash, case: :lower),
        canonical_hash: hash,
        loaded_at: DateTime.utc_now(),
        evaluator_handle: source,
        bundle_bytes: source
      }
    })
  end

  defp intent(tool) do
    {:ok, intent} =
      ToolUseIntent.new(%{
        call_id: "call-1",
        tool_name: tool,
        tool_args: %{"path" => "/tmp/example"},
        provider_event_span: %{start_byte_offset: 0, end_byte_offset: 1, event_indices: [0]}
      })

    intent
  end

  test "missing admission refuses an opening", %{context: context} do
    Application.stop(:r5e)
    refute Admission.ready?()
    assert {:error, :admission_unavailable} = Admission.open(~s({"model":"test-model"}), context)
  end

  test "model denial is recorded before there can be an opening", %{context: context} do
    assert :ok = activate("forbid(principal, action, resource);")

    assert {:error, {:admission_failed, "LlmCall", {:denied, receipt}}} =
             Admission.open(~s({"model":"test-model"}), context)

    assert receipt["policy"]["decision"] == "deny"
    assert receipt["policy"]["upstreamPolicy"]["decision"] == "allow"
  end

  test "one recorded tool denial, current policy, and completion linked without reevaluation", %{
    context: context
  } do
    assert :ok = activate("permit(principal, action, resource);")
    assert {:ok, opening} = Admission.open(~s({"model":"test-model"}), context)
    opening_hash = Base.encode16(opening.context.cedar_bundle_hash, case: :lower)
    assert {:ok, opening_payload} = R5e.Log.payload(List.last(R5e.Log.read_events()))
    refute Map.has_key?(opening_payload["spec"]["gatewayContext"], "cedar_bundle_hash")

    assert :ok = activate("forbid(principal, action, resource);")
    assert {:ok, {:deny, _}, denial} = Admission.admit_tool(opening, intent("read_file"), context)
    assert {:ok, tool_payload} = R5e.Log.payload(List.last(R5e.Log.read_events()))
    assert tool_payload["spec"]["gatewayContext"]["opening_model_policy_hash"] == opening_hash
    refute Map.has_key?(tool_payload["spec"]["gatewayContext"], "cedar_bundle_hash")

    assert {:ok, actual_source} = R5e.CAS.get(denial["policy"]["source"])
    actual_hash = Recurse.Cedar.canonical_hash(actual_source)
    assert actual_hash == Recurse.Cedar.canonical_hash("forbid(principal, action, resource);")
    refute actual_hash == opening.context.cedar_bundle_hash

    assert {:ok, evaluation} =
             Recurse.Fold.Policy.EvaluationRecord.fetch(denial["policy"]["evaluation"])

    request = evaluation["requestBytes"] |> Base.decode64!() |> Jason.decode!()
    assert request["context"]["opening_model_policy_hash"] == opening_hash
    refute Map.has_key?(request["context"], "cedar_bundle_hash")

    before = length(R5e.Log.read_events())
    bytes = "completed response"

    assert {:ok, response} =
             Admission.complete(
               opening,
               %{
                 response_payload: bytes,
                 response_hash: :crypto.hash(:sha256, bytes),
                 completed_at: DateTime.utc_now()
               },
               [denial]
             )

    assert response["policy"]["decision"] == "allow"

    new_tool_events =
      R5e.Log.read_events()
      |> Enum.drop(before)
      |> Enum.filter(fn event ->
        case R5e.Log.payload(event) do
          {:ok, payload} ->
            R5e.Admission.target_path(payload) == "gateway.r5e.io/v1alpha1/ToolCall"

          _ ->
            false
        end
      end)

    assert new_tool_events == []
    assert {:ok, payload} = R5e.Log.payload(List.last(R5e.Log.read_events()))
    assert payload["spec"]["toolCalls"] == [%{"$ref" => denial["eventRef"]}]
    assert payload["spec"]["llmCall"] == %{"$ref" => opening.llm_call_ref}
    assert {:ok, directory, manifest} = R5e.Export.run()
    assert manifest["missingObjects"] == []
    assert {:ok, report} = RecurseVerify.run(directory)
    assert report.findings == []
  end

  test "observed principal and tenant are available to the admitted workload policy", %{
    context: context
  } do
    assert :ok =
             activate(
               ~s|permit(principal == User::"alice", action, resource) when {context.tenant == "tenant-a"};|
             )

    assert {:ok, _} = Admission.open(~s({"model":"test-model"}), context)

    assert {:error, {:admission_failed, "LlmCall", {:denied, _}}} =
             Admission.open(~s({"model":"test-model"}), %{context | tenant: "tenant-b"})
  end

  test "hash-only arguments and corrupted completion evidence cannot be admitted", %{
    context: context
  } do
    assert :ok = activate("permit(principal, action, resource);")
    assert {:ok, opening} = Admission.open(~s({"model":"test-model"}), context)

    assert {:error, :tool_arguments_unavailable} =
             Admission.admit_tool(
               opening,
               %{intent("read_file") | tool_args: :too_large},
               context
             )

    assert {:error, :response_hash_mismatch} =
             Admission.complete(
               opening,
               %{response_payload: "actual", response_hash: :crypto.hash(:sha256, "different")},
               []
             )
  end

  test "unmigrated execution routes are unavailable before their handlers run" do
    for path <- ["/v1/chat/completions", "/v1/chat/messages", "/v1/mcp/test/tools/execute"] do
      conn =
        Plug.Test.conn(:post, path, "{}")
        |> Plug.Conn.put_req_header("content-type", "application/json")

      result = Recurse.Gateway.Router.call(conn, Recurse.Gateway.Router.init([]))
      assert result.status == 503
      assert result.halted
      assert Jason.decode!(result.resp_body)["error"]["code"] == "capability_unavailable"
    end
  end

  test "queued and direct LLM suggestion work is unavailable before touching providers or storage" do
    assert {:cancel, :capability_unavailable} =
             Recurse.Gateway.SuggestionEngine.LlmRunner.perform(%Oban.Job{args: %{}})

    assert {:error, :capability_unavailable} =
             Recurse.Gateway.SuggestionEngine.LlmRunner.run_for_window("test-tenant")
  end
end
