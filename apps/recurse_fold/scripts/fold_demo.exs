# fold_demo.exs — the acts of the fold demo, run inside the fold's own node.
#
#   mix run scripts/fold_demo.exs acts <summary.json>
#   mix run scripts/fold_demo.exs restart <summary.json>
#
# Why an Elixir script rather than curl: since spec 011 every admission
# carries an ed25519 signature over the canonical request object, and the
# signing key is the fold's own, held under the data directory. A shell
# cannot produce that envelope, and giving it one would mean handing the
# fold's private key to a script. So the *acts* run in the node that holds
# the key, through `Recurse.Fold.admit/3` — the same function spec 012's
# LLM proxy calls — and the shell orchestrates: boot, restart, export,
# verify offline.
#
# Reads stay over HTTP in the driving script; nothing about reading needs a
# signature.

defmodule FoldDemoScript do
  def main(["acts", summary]) do
    banner("the fold's own boot — a key, an endorsement, nine Kinds, a bundle, three shapes")

    IO.puts("  fold key      : #{Recurse.Fold.key_id()}")
    IO.puts("  node key      : #{R5e.DSSE.node_key_id()}")
    IO.puts("  endorsement   : #{Recurse.Fold.authority()}")
    IO.puts("  (every act below is signed by the fold key and cites that Endorsement)")

    {group, version, kind, name} = Recurse.Fold.bundle_coordinates()
    {:ok, bundle, _} = R5e.ResourceStore.get(group, version, kind, name)
    IO.puts("  policy bundle : #{bundle["specAddress"]}")
    IO.puts("  policy text   : #{bundle["spec"]["sourceRef"]["$ref"]}  (retention: public-record)")

    banner("steps 1-9: one turn of agent work, every act through Recurse.Fold.admit/3")
    result = Recurse.Fold.Demo.run()

    IO.puts("  1. PUT /cas prompt bytes      -> #{result.prompt_ref}")
    IO.puts("  2. Prompt                     -> #{result.prompt["name"]}")
    IO.puts("  3. LlmCall                    -> #{result.call["eventRef"]}")
    IO.puts("  4. ToolCall `rm -rf`          -> #{result.denied["outcome"]}  (the policy refused it)")
    IO.puts("       reason     : #{result.denied["reason"]}")
    IO.puts("       bundle     : #{result.denied["policy"]["bundle"]}")
    IO.puts("       shape      : #{result.denied["policy"]["shape"]}")
    IO.puts("       engineBuild: #{result.denied["policy"]["engineBuild"]}")
    IO.puts("       evaluation : #{result.denied["policy"]["evaluation"]}")
    IO.puts("       matched    : #{Enum.join(result.denied["policy"]["matched"], ", ")}")
    IO.puts("  5. ToolCall `ls -la`          -> #{result.allowed["outcome"]}  (the deny is selective)")
    IO.puts("  6. PUT /cas completion bytes  -> #{result.completion_ref}")
    IO.puts("  7. Completion, 8. LlmResponse, 9. ToolResult -> admitted")

    banner("the evaluation record the denial cites — the exact bytes Cedar was handed")
    {:ok, record} =
      Recurse.Fold.Policy.EvaluationRecord.fetch(result.denied["policy"]["evaluation"])

    IO.puts(Jason.encode!(Map.drop(record, ["requestBytes", "entitiesBytes"]), pretty: true))
    IO.puts("  requestBytes, decoded:")
    {:ok, request} = Base.decode64(record["requestBytes"])
    IO.puts(Jason.encode!(Jason.decode!(request), pretty: true))

    banner("the chain")
    for event <- R5e.Log.events(), do: IO.puts("  #{event["seq"]}  #{event["kind"]}  #{event["hash"]}")

    write_summary(summary, %{
      "phase" => "acts",
      "foldKey" => Recurse.Fold.key_id(),
      "nodeKey" => R5e.DSSE.node_key_id(),
      "endorsement" => Recurse.Fold.authority(),
      "bundle" => bundle["specAddress"],
      "source" => bundle["spec"]["sourceRef"]["$ref"],
      "evaluation" => result.denied["policy"]["evaluation"],
      "deniedOutcome" => result.denied["outcome"],
      "allowedOutcome" => result.allowed["outcome"],
      "resolvedAuthority" => length(record["resolvedAuthority"]),
      "bundlePath" => export!(),
      "events" => length(R5e.Log.events())
    })
  end

  def main(["restart", summary]) do
    banner("step 11: this node booted over the existing data dir — the log was replayed")
    IO.puts("  events on the chain: #{length(R5e.Log.events())}")
    IO.puts("  fold key           : #{Recurse.Fold.key_id()}  (read from disk, not regenerated)")
    IO.puts("  endorsement        : #{Recurse.Fold.authority()}  (found, not re-admitted)")

    write_summary(summary, %{
      "phase" => "restart",
      "bundlePath" => export!(),
      "events" => length(R5e.Log.events()),
      "endorsement" => Recurse.Fold.authority()
    })
  end

  defp export! do
    dest =
      Path.join(
        Application.fetch_env!(:r5e, :data_dir),
        "exports/bundle-#{System.system_time(:second)}-#{System.unique_integer([:positive])}"
      )

    {:ok, ^dest, manifest} = R5e.Export.run(dest)
    IO.puts("  exported #{length(manifest["derivedObjects"])} derived object(s) to #{dest}")
    dest
  end

  defp write_summary(path, map), do: File.write!(path, Jason.encode!(map, pretty: true))

  defp banner(text) do
    IO.puts("\n===== #{text} =====")
  end
end

FoldDemoScript.main(System.argv())
