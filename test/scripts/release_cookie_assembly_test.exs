# Run with: elixir test/scripts/release_cookie_assembly_test.exs
# No enterprise applications, databases or kernel are started.
Mix.start()
Code.compile_file(Path.expand("../../mix.exs", __DIR__))

[:assemble, remove_cookie, :tar] =
  Recurse.MixProject.project()[:releases][:audit_console][:steps]

root = Path.join(System.tmp_dir!(), "r5e-cookie-assembly-#{System.unique_integer([:positive])}")
File.mkdir_p!(Path.join(root, "releases"))

try do
  cookie = Path.join(root, "releases/COOKIE")
  File.write!(cookie, "test-only-build-cookie")
  release = %{path: root}
  ^release = remove_cookie.(release)
  false = File.exists?(cookie)

  # A missing expected assembly output fails packaging rather than hiding a
  # changed Mix assembly contract. The callback must run after assemble.
  try do
    remove_cookie.(release)
    raise "missing assembled cookie did not fail"
  rescue
    File.Error -> :ok
  end

  template = Path.expand("../../rel/env.sh.eex", __DIR__)
  rendered = EEx.eval_file(template)
  true = String.contains?(rendered, "export RELEASE_COOKIE")
  false = String.contains?(rendered, "test-only-build-cookie")
  IO.puts("PASS: release step removes assembly cookie before tar; env template renders")
after
  File.rm_rf!(root)
end
