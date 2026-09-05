unless Code.ensure_loaded?(Recurse.ReleaseSbom) do
  raise """
  Recurse.ReleaseSbom is not loaded.

  Run this script through Mix so the recurse_shared app is on the code path:

      mix run --no-start scripts/generate-release-sbom.exs -- <args>
  """
end

Recurse.ReleaseSbom.main(System.argv())
