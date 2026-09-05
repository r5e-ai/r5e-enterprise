defmodule Recurse.Fold.Demo do
  @moduledoc """
  One turn of agent work, as a sequence of acts — the thing
  `scripts/fold-demo.sh` drives and the thing the golden report freezes.

  It lives in `lib/` rather than in the script or in the test because
  those two must be the **same** sequence: a demo whose verifier output
  nobody pins is a story, and a pinned report of a chain no demo produces
  is a fixture. One function, two callers.

  Every act goes through `Recurse.Fold.admit/3` or
  `Recurse.Fold.put_cas/2` — signed by the fold key, citing the fold's
  Endorsement, through the kernel's one gate. Nothing here has a side
  door, which is why the verifier can be handed the result with no
  arguments about provenance.

  The one deliberate refusal is step 4: `rm -rf` under the policy the
  fold seeds at boot. It is a **return value**, and the receipt it
  returns names the bundle, the shape, the engine build and the exact
  bytes Cedar was handed.
  """

  @prompt "list the files, then remove the temp directory"
  @completion ~s({"content":"I'll list the files first, then remove /tmp/scratch."})

  @typedoc "What one run produced, for a caller that wants to print or assert on it."
  @type result :: %{
          prompt: map(),
          call: map(),
          denied: map(),
          allowed: map(),
          response: map(),
          tool_result: map(),
          prompt_ref: String.t(),
          completion_ref: String.t()
        }

  @doc "Run the sequence. Raises if an act the demo expects to be granted is not."
  @spec run() :: result()
  def run do
    prompt_ref = put!(@prompt, "text/plain")

    prompt =
      admit!("Prompt", %{"contentRef" => %{"$ref" => prompt_ref}, "role" => "user"})

    call =
      admit!("LlmCall", %{
        "model" => "claude-sonnet-4",
        "prompt" => %{"$ref" => "gateway.r5e.io/v1alpha1/Prompt/" <> prompt["name"]},
        "provider" => "anthropic",
        "transport" => "https"
      })

    # The act the policy exists to refuse. `{:denied, receipt}` is the
    # answer, not an exception: the receipt is the evidence.
    {:denied, denied} =
      admit("ToolCall", %{
        "tool" => "shell",
        "args" => %{"command" => "rm -rf /tmp/scratch"},
        "llmCall" => %{"$ref" => call["eventRef"]},
        "index" => 0
      })

    allowed =
      admit!("ToolCall", %{
        "tool" => "shell",
        "args" => %{"command" => "ls -la"},
        "llmCall" => %{"$ref" => call["eventRef"]},
        "index" => 1
      })

    completion_ref = put!(@completion, "application/json")

    completion =
      admit!("Completion", %{
        "contentRef" => %{"$ref" => completion_ref},
        "mediaType" => "application/json"
      })

    response =
      admit!("LlmResponse", %{
        "llmCall" => %{"$ref" => call["eventRef"]},
        "outcome" => "ok",
        "completion" => %{
          "$ref" => "gateway.r5e.io/v1alpha1/Completion/" <> completion["name"]
        },
        "toolCalls" => [%{"$ref" => denied["eventRef"]}, %{"$ref" => allowed["eventRef"]}],
        "upstreamStatus" => 200,
        "usage" => %{"inputTokens" => 41, "outputTokens" => 18}
      })

    tool_result =
      admit!("ToolResult", %{
        "toolCall" => %{"$ref" => allowed["eventRef"]},
        "outcome" => "ok",
        "result" => %{"stdout" => "total 0\n"},
        "durationMs" => 12
      })

    %{
      prompt: prompt,
      call: call,
      denied: denied,
      allowed: allowed,
      response: response,
      tool_result: tool_result,
      prompt_ref: prompt_ref,
      completion_ref: completion_ref
    }
  end

  @doc "The prompt bytes the demo puts on the record."
  def prompt_bytes, do: @prompt

  @doc "The completion bytes the demo puts on the record."
  def completion_bytes, do: @completion

  defp admit(kind, spec),
    do: Recurse.Fold.admit("gateway.r5e.io/v1alpha1/#{kind}", spec)

  defp admit!(kind, spec) do
    case admit(kind, spec) do
      {:ok, receipt} ->
        receipt

      {:denied, receipt} ->
        raise "the demo's #{kind} was denied: #{receipt["reason"]}"

      {:refused, reason} ->
        raise "the demo's #{kind} was refused before it was an act: #{reason}"
    end
  end

  defp put!(bytes, media_type) do
    {:ok, _receipt, address} = Recurse.Fold.put_cas(bytes, media_type: media_type)
    address
  end
end
