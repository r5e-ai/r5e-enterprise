defmodule Recurse.Gateway.Importers.JsonlSessionImporter do
  @moduledoc false

  alias Recurse.Gateway.Importers.JsonlReader
  alias Recurse.Gateway.Importers.SessionReceiptBuilder
  alias Recurse.Gateway.ProviderRegistry
  alias Recurse.Providers.Impls.PostgresMerkleLedger

  @default_principal "unknown@localhost"

  @type opts :: [
          principal: String.t(),
          tenant_id: String.t(),
          skip_thinking?: boolean()
        ]

  @spec import_session(Path.t(), module(), opts()) ::
          {:ok, %{receipts: non_neg_integer(), session_id: String.t() | nil}} | {:error, term()}
  def import_session(path, classifier, opts \\ []) when is_atom(classifier) do
    opts = normalize_opts(opts)

    with :ok <- validate_path(path),
         {:ok, preflight} <- collect_preflight(path, classifier),
         {:ok, registry} <- fetch_registry(),
         {:ok, result} <- persist_session(path, classifier, opts, preflight, registry) do
      {:ok, result}
    end
  end

  defp normalize_opts(opts) do
    %{
      principal: Keyword.get(opts, :principal, @default_principal),
      tenant_id: Keyword.get(opts, :tenant_id),
      skip_thinking?: Keyword.get(opts, :skip_thinking?, true)
    }
  end

  defp validate_path(path) do
    if File.regular?(path), do: :ok, else: {:error, {:not_found, path}}
  end

  defp collect_preflight(path, classifier) do
    preflight =
      path
      |> JsonlReader.stream(source_label: classifier.source_label())
      |> Enum.reduce(%{entries: 0, session_id: nil, first_timestamp: nil, tool_results: %{}}, fn
        entry, acc ->
          acc
          |> increment_entries()
          |> maybe_set_session_id(classifier.source_session_id(entry))
          |> maybe_set_first_timestamp(classifier.timestamp(entry))
          |> merge_tool_results(classifier.tool_results(entry))
      end)

    {:ok, preflight}
  end

  defp increment_entries(acc), do: %{acc | entries: acc.entries + 1}

  defp maybe_set_session_id(%{session_id: nil} = acc, session_id) when is_binary(session_id),
    do: %{acc | session_id: session_id}

  defp maybe_set_session_id(acc, _session_id), do: acc

  defp maybe_set_first_timestamp(%{first_timestamp: nil} = acc, %DateTime{} = timestamp),
    do: %{acc | first_timestamp: timestamp}

  defp maybe_set_first_timestamp(acc, _timestamp), do: acc

  defp merge_tool_results(acc, tool_results),
    do: %{acc | tool_results: Map.merge(acc.tool_results, tool_results)}

  defp fetch_registry do
    case ProviderRegistry.fetch() do
      {:ok, registry} -> {:ok, registry}
      {:error, :not_installed} -> {:error, :provider_registry_not_installed}
    end
  end

  defp persist_session(_path, _classifier, _opts, %{entries: 0}, _registry) do
    {:ok, %{receipts: 0, session_id: nil}}
  end

  defp persist_session(path, classifier, opts, preflight, registry) do
    source_session_id = preflight.session_id || fallback_source_session_id(path)
    context = build_context(opts, classifier.source_kind(), source_session_id, registry)

    path
    |> JsonlReader.stream(source_label: classifier.source_label())
    |> Enum.reduce_while({:ok, 0, 0}, fn entry, {:ok, count, next_position} ->
      case commit_receipts_for_entry(
             entry,
             classifier,
             opts,
             preflight,
             context,
             registry,
             next_position
           ) do
        {:ok, inserted, next_position} -> {:cont, {:ok, count + inserted, next_position}}
        {:error, reason} -> {:halt, {:error, reason}}
      end
    end)
    |> case do
      {:ok, receipts, _next_position} ->
        {:ok, %{receipts: receipts, session_id: source_session_id}}

      {:error, reason} ->
        {:error, reason}
    end
  end

  defp build_context(opts, source, source_session_id, registry) do
    %{
      tenant_id: opts.tenant_id || registry.tenant_id,
      principal: opts.principal,
      source: source,
      source_session_id: source_session_id,
      signer: registry.signer,
      secrets_provider: registry.secrets
    }
  end

  defp commit_receipts_for_entry(
         entry,
         classifier,
         opts,
         preflight,
         context,
         registry,
         next_position
       ) do
    receipt_opts = [skip_thinking?: opts.skip_thinking?]

    entry
    |> classifier.receipt_specs(preflight.tool_results, receipt_opts)
    |> Enum.reduce_while({:ok, 0, next_position}, fn spec, {:ok, count, position} ->
      spec = Map.put(spec, :session_chain_position, position)

      case commit_receipt(spec, context, registry) do
        {:ok, inserted} -> {:cont, {:ok, count + inserted, position + 1}}
        {:error, reason} -> {:halt, {:error, reason}}
      end
    end)
  end

  defp commit_receipt(spec, context, %{ledger: {PostgresMerkleLedger, _ledger_state}}) do
    spec = scope_natural_key(spec, context.source_session_id)

    with {:ok, commit} <- SessionReceiptBuilder.build_commit(spec, context),
         {:ok, _result} <-
           PostgresMerkleLedger.commit_attestation(commit.envelope, commit.ledger_opts) do
      {:ok, 1}
    else
      {:error, reason} -> handle_commit_error(reason)
    end
  end

  defp commit_receipt(_spec, _context, %{ledger: {mod, _ledger_state}}) do
    {:error, {:unsupported_ledger_provider, mod}}
  end

  defp commit_receipt(_spec, _context, _registry) do
    {:error, :ledger_provider_not_configured}
  end

  defp handle_commit_error(reason) do
    if duplicate_commit_error?(reason) do
      {:ok, 0}
    else
      {:error, reason}
    end
  end

  defp duplicate_commit_error?({step, %Ecto.ConstraintError{} = error})
       when step in [:attestation, :session_epoch, :leaf_node] do
    error.type in [:unique, :primary_key]
  end

  defp duplicate_commit_error?({step, %Postgrex.Error{postgres: %{code: :unique_violation}}})
       when step in [:attestation, :session_epoch, :leaf_node],
       do: true

  defp duplicate_commit_error?(_reason), do: false

  defp scope_natural_key(%{natural_key: natural_key} = spec, source_session_id) do
    %{spec | natural_key: "#{source_session_id}:#{natural_key}"}
  end

  defp fallback_source_session_id(path) do
    "unknown:#{Path.basename(path)}"
  end
end
