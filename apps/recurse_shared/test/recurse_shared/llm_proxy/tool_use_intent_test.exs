defmodule Recurse.Shared.LlmProxy.ToolUseIntentTest do
  @moduledoc """
  Unit tests for the canonical `Recurse.Shared.LlmProxy.ToolUseIntent` struct.

  Covers contract invariants from `specs/009-llm-api-proxy/contracts/tool_use_intent.md`:

    * I-001 — `tool_args_hash` is SHA-256 over `Jason.encode!(map)` for decoded
      args, and SHA-256 over the raw JSON bytes for `:too_large`.
    * I-003 — `call_id` is preserved verbatim from input (no local generation).
    * `:too_large` sentinel handling (raw-JSON path).
    * `parallel_index` nil-vs-int passthrough.
  """

  use ExUnit.Case, async: true

  alias Recurse.Shared.LlmProxy.ToolUseIntent

  @valid_span %{
    start_byte_offset: 0,
    end_byte_offset: 100,
    event_indices: [3, 4, 5]
  }

  describe "new/1 — happy path" do
    test "constructs struct with required fields and computes 32-byte hash" do
      assert {:ok, intent} =
               ToolUseIntent.new(%{
                 call_id: "call_abc123",
                 tool_name: "shell",
                 tool_args: %{"cmd" => "ls -la"},
                 provider_event_span: @valid_span
               })

      assert %ToolUseIntent{
               call_id: "call_abc123",
               tool_name: "shell",
               tool_args: %{"cmd" => "ls -la"},
               parallel_index: nil
             } = intent

      assert byte_size(intent.tool_args_hash) == 32
      assert intent.tool_args_size_bytes > 0
      assert %DateTime{} = intent.extracted_at
    end

    test "extracted_at defaults to a recent DateTime when omitted" do
      before = DateTime.utc_now()

      assert {:ok, %ToolUseIntent{extracted_at: ts}} =
               ToolUseIntent.new(%{
                 call_id: "x",
                 tool_name: "t",
                 tool_args: %{},
                 provider_event_span: @valid_span
               })

      after_ = DateTime.utc_now()
      assert DateTime.compare(ts, before) in [:gt, :eq]
      assert DateTime.compare(ts, after_) in [:lt, :eq]
    end

    test "extracted_at honors explicitly supplied DateTime" do
      ts = ~U[2026-05-07 12:00:00.000000Z]

      assert {:ok, %ToolUseIntent{extracted_at: ^ts}} =
               ToolUseIntent.new(%{
                 call_id: "x",
                 tool_name: "t",
                 tool_args: %{},
                 provider_event_span: @valid_span,
                 extracted_at: ts
               })
    end
  end

  describe "I-001: tool_args_hash invariant" do
    test "hash equals SHA-256 of Jason.encode!(args) for a decoded-map args" do
      args = %{"cmd" => "rm -rf /", "force" => true}

      {:ok, intent} =
        ToolUseIntent.new(%{
          call_id: "c1",
          tool_name: "shell",
          tool_args: args,
          provider_event_span: @valid_span
        })

      expected = :crypto.hash(:sha256, Jason.encode!(args))
      assert intent.tool_args_hash == expected
      assert intent.tool_args_size_bytes == byte_size(Jason.encode!(args))
    end

    test "structurally-equivalent maps with same Jason encoding hash equally" do
      # Same args, two construction sites; hashes must match (determinism gate
      # for downstream attestation correlation).
      args = %{"a" => 1, "b" => "two"}

      {:ok, i1} =
        ToolUseIntent.new(%{
          call_id: "c1",
          tool_name: "t",
          tool_args: args,
          provider_event_span: @valid_span
        })

      {:ok, i2} =
        ToolUseIntent.new(%{
          call_id: "c2",
          tool_name: "t",
          tool_args: args,
          provider_event_span: @valid_span
        })

      assert i1.tool_args_hash == i2.tool_args_hash
    end

    test "different args produce different hashes" do
      {:ok, a} =
        ToolUseIntent.new(%{
          call_id: "c1",
          tool_name: "t",
          tool_args: %{"x" => 1},
          provider_event_span: @valid_span
        })

      {:ok, b} =
        ToolUseIntent.new(%{
          call_id: "c1",
          tool_name: "t",
          tool_args: %{"x" => 2},
          provider_event_span: @valid_span
        })

      refute a.tool_args_hash == b.tool_args_hash
    end
  end

  describe ":too_large sentinel handling (I-001)" do
    test "hashes the raw JSON bytes, NOT the literal atom" do
      raw = ~s({"huge_field":"#{String.duplicate("x", 1000)}"})

      {:ok, intent} =
        ToolUseIntent.new(%{
          call_id: "c1",
          tool_name: "t",
          tool_args: :too_large,
          raw_json: raw,
          provider_event_span: @valid_span
        })

      assert intent.tool_args == :too_large
      # Hash MUST be over the original raw JSON, not Jason.encode!(:too_large),
      # which would silently collide across all oversize blobs.
      assert intent.tool_args_hash == :crypto.hash(:sha256, raw)
      assert intent.tool_args_size_bytes == byte_size(raw)
      # Sanity: the wrong-shape hash MUST differ.
      refute intent.tool_args_hash == :crypto.hash(:sha256, Jason.encode!(:too_large))
    end

    test "rejects :too_large without :raw_json" do
      assert {:error, {:missing, :raw_json}} =
               ToolUseIntent.new(%{
                 call_id: "c1",
                 tool_name: "t",
                 tool_args: :too_large,
                 provider_event_span: @valid_span
               })
    end

    test "rejects :too_large with empty :raw_json" do
      assert {:error, {:missing, :raw_json}} =
               ToolUseIntent.new(%{
                 call_id: "c1",
                 tool_name: "t",
                 tool_args: :too_large,
                 raw_json: "",
                 provider_event_span: @valid_span
               })
    end
  end

  describe "I-003: call_id passthrough (no local generation)" do
    test "preserves the provider-issued call_id verbatim" do
      ids = ["call_abc", "call_0", "fc-uuid-9d4e3a", "any-binary-id"]

      for id <- ids do
        {:ok, intent} =
          ToolUseIntent.new(%{
            call_id: id,
            tool_name: "t",
            tool_args: %{},
            provider_event_span: @valid_span
          })

        assert intent.call_id == id
      end
    end
  end

  describe "I-004: parallel_index" do
    test "defaults to nil when omitted" do
      {:ok, intent} =
        ToolUseIntent.new(%{
          call_id: "c1",
          tool_name: "t",
          tool_args: %{},
          provider_event_span: @valid_span
        })

      assert intent.parallel_index == nil
    end

    test "accepts explicit non-negative integer for parallel calls" do
      for idx <- [0, 1, 7] do
        {:ok, intent} =
          ToolUseIntent.new(%{
            call_id: "c1",
            tool_name: "t",
            tool_args: %{},
            provider_event_span: @valid_span,
            parallel_index: idx
          })

        assert intent.parallel_index == idx
      end
    end

    test "explicit nil is the same as omitted" do
      {:ok, intent} =
        ToolUseIntent.new(%{
          call_id: "c1",
          tool_name: "t",
          tool_args: %{},
          provider_event_span: @valid_span,
          parallel_index: nil
        })

      assert intent.parallel_index == nil
    end
  end

  describe "input validation" do
    test "errors when required fields are missing" do
      assert {:error, {:missing, :call_id}} =
               ToolUseIntent.new(%{
                 tool_name: "t",
                 tool_args: %{},
                 provider_event_span: @valid_span
               })

      assert {:error, {:missing, :tool_name}} =
               ToolUseIntent.new(%{
                 call_id: "c1",
                 tool_args: %{},
                 provider_event_span: @valid_span
               })

      assert {:error, {:missing, :provider_event_span}} =
               ToolUseIntent.new(%{
                 call_id: "c1",
                 tool_name: "t",
                 tool_args: %{}
               })
    end

    test "errors when call_id is not a binary" do
      assert {:error, {:invalid, :call_id}} =
               ToolUseIntent.new(%{
                 call_id: 123,
                 tool_name: "t",
                 tool_args: %{},
                 provider_event_span: @valid_span
               })
    end

    test "errors when tool_args is neither map nor :too_large" do
      assert {:error, {:invalid, :tool_args}} =
               ToolUseIntent.new(%{
                 call_id: "c1",
                 tool_name: "t",
                 tool_args: "not a map",
                 provider_event_span: @valid_span
               })
    end

    test "errors when provider_event_span is malformed" do
      bad_spans = [
        %{},
        %{start_byte_offset: -1, end_byte_offset: 0, event_indices: []},
        %{start_byte_offset: 10, end_byte_offset: 5, event_indices: []},
        %{start_byte_offset: 0, end_byte_offset: 5, event_indices: [-1]},
        "definitely not a span"
      ]

      for span <- bad_spans do
        assert {:error, {:invalid, :provider_event_span}} =
                 ToolUseIntent.new(%{
                   call_id: "c1",
                   tool_name: "t",
                   tool_args: %{},
                   provider_event_span: span
                 }),
               "expected invalid for span=#{inspect(span)}"
      end
    end
  end
end
