defmodule Recurse.Gateway.Importers.JsonlReader do
  @moduledoc false

  require Logger

  @type opts :: [source_label: String.t()]

  @spec stream(Path.t(), opts()) :: term()
  def stream(path, opts \\ []) do
    source_label = Keyword.get(opts, :source_label, "JSONL")

    path
    |> File.stream!([], :line)
    |> Stream.with_index(1)
    |> Stream.flat_map(&decode_line(&1, source_label))
  end

  defp decode_line({line, line_number}, source_label) do
    line = String.trim(line)

    if line == "" do
      []
    else
      case Jason.decode(line) do
        {:ok, %{} = entry} ->
          [entry]

        {:ok, value} ->
          Logger.warning(
            "skipping #{source_label} line #{line_number}: expected object, got #{inspect(value)}"
          )

          []

        {:error, error} ->
          Logger.warning(
            "skipping malformed #{source_label} line #{line_number}: #{Exception.message(error)}"
          )

          []
      end
    end
  end
end
