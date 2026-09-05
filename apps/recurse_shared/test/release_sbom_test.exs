defmodule Recurse.ReleaseSbomTest do
  use ExUnit.Case, async: false

  setup do
    root = Path.join(System.tmp_dir!(), "r5e-sbom-test-#{System.unique_integer([:positive])}")
    File.mkdir_p!(root)

    on_exit(fn -> File.rm_rf!(root) end)

    {:ok, root: root}
  end

  test "mix components include only deps installed for the release env", %{root: root} do
    File.write!(Path.join(root, "mix.lock"), """
    %{
      "jason" => {:hex, :jason, "1.4.4", "checksum", [:mix], [], "hexpm", "package-hash"},
      "credo" => {:hex, :credo, "1.7.18", "dev-checksum", [:mix], [], "hexpm", "dev-package-hash"}
    }
    """)

    File.mkdir_p!(Path.join(root, "deps/jason"))

    components = Recurse.ReleaseSbom.mix_components(root)

    assert [%{"name" => "jason", "purl" => "pkg:hex/jason@1.4.4"}] = components
    assert [%{"alg" => "SHA-256", "content" => "package-hash"}] = hd(components)["hashes"]
  end

  test "cargo components are parsed from both NIF lockfiles and deduped", %{root: root} do
    cedar_lock = Path.join(root, "native/recurse_cedar/Cargo.lock")
    spiffe_lock = Path.join(root, "native/recurse_spiffe/Cargo.lock")
    File.mkdir_p!(Path.dirname(cedar_lock))
    File.mkdir_p!(Path.dirname(spiffe_lock))

    File.write!(cedar_lock, cargo_lock("recurse_cedar"))
    File.write!(spiffe_lock, cargo_lock("recurse_spiffe"))

    components = Recurse.ReleaseSbom.cargo_components(root)
    refs = Enum.map(components, & &1["bom-ref"])

    assert "pkg:cargo/recurse_cedar@0.1.0" in refs
    assert "pkg:cargo/recurse_spiffe@0.1.0" in refs
    assert Enum.count(refs, &(&1 == "pkg:cargo/serde@1.0.228")) == 1
  end

  test "build_bom includes runtime metadata and bundled OpenSSL file hashes", %{root: root} do
    release_root = Path.join(root, "release")
    openssl_dir = Path.join(release_root, "support/openssl/lib")
    File.mkdir_p!(openssl_dir)
    File.write!(Path.join(openssl_dir, "libssl.so.3"), "fake libssl")
    write_empty_inputs!(root)

    bom =
      Recurse.ReleaseSbom.build_bom(root, release_root, sbom_metadata())

    assert bom["bomFormat"] == "CycloneDX"
    assert bom["specVersion"] == "1.5"

    assert %{"hashes" => [%{"alg" => "SHA-256", "content" => hash}]} =
             Enum.find(
               bom["components"],
               &(&1["bom-ref"] == "file:support/openssl/lib/libssl.so.3")
             )

    assert hash == :crypto.hash(:sha256, "fake libssl") |> Base.encode16(case: :lower)

    decoded = bom |> Recurse.ReleaseSbom.encode_json() |> JSON.decode!()
    assert decoded["metadata"]["component"]["name"] == "audit_console"
  end

  test "serial number is deterministic for fixed inputs", %{root: root} do
    release_root = Path.join(root, "release")
    File.mkdir_p!(release_root)
    write_empty_inputs!(root)

    bom_1 = Recurse.ReleaseSbom.build_bom(root, release_root, sbom_metadata())
    bom_2 = Recurse.ReleaseSbom.build_bom(root, release_root, sbom_metadata())

    assert bom_1["serialNumber"] == bom_2["serialNumber"]

    assert bom_1["serialNumber"] =~
             ~r/^urn:uuid:[0-9a-f]{8}-[0-9a-f]{4}-5[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/
  end

  test "tarball digest is bound into canonical SBOM sidecar metadata", %{root: root} do
    release_root = Path.join(root, "release")
    File.mkdir_p!(release_root)
    write_empty_inputs!(root)

    metadata =
      sbom_metadata(%{
        release_tarball_name: "r5e-enterprise-linux-arm64-release.tar.gz",
        release_tarball_sha256: String.duplicate("a", 64)
      })

    bom = Recurse.ReleaseSbom.build_bom(root, release_root, metadata)

    assert [
             %{
               "type" => "distribution",
               "url" => "file:r5e-enterprise-linux-arm64-release.tar.gz",
               "hashes" => [%{"alg" => "SHA-256", "content" => sha256}]
             }
           ] = bom["externalReferences"]

    assert sha256 == String.duplicate("a", 64)

    changed =
      Recurse.ReleaseSbom.build_bom(
        root,
        release_root,
        %{metadata | release_tarball_sha256: String.duplicate("b", 64)}
      )

    assert changed["serialNumber"] != bom["serialNumber"]
  end

  test "main writes canonical sidecar bound to release tarball digest", %{root: root} do
    release_root = Path.join(root, "release")
    tarball_path = Path.join(root, "release.tar.gz")
    output_path = Path.join(root, "audit_console.sbom.cdx.json")
    File.mkdir_p!(release_root)
    File.write!(tarball_path, "fake release tarball")
    write_empty_inputs!(root)

    File.cd!(root, fn ->
      Recurse.ReleaseSbom.main([
        "--output",
        output_path,
        "--release-root",
        release_root,
        "--release-name",
        "audit_console",
        "--release-version",
        "0.1.0",
        "--release-tag",
        "test-tag",
        "--vcs-ref",
        "abcdef",
        "--build-time",
        "2026-04-27T00:00:00Z",
        "--elixir-version",
        "1.19.5",
        "--otp-version",
        "28.0",
        "--erts-version",
        "16.0",
        "--rust-version",
        "1.92.0",
        "--openssl-version",
        "OpenSSL 3.0.17",
        "--release-tarball-path",
        tarball_path,
        "--release-tarball-name",
        "release.tar.gz"
      ])
    end)

    decoded = output_path |> File.read!() |> JSON.decode!()
    expected_hash = :crypto.hash(:sha256, "fake release tarball") |> Base.encode16(case: :lower)

    assert [%{"hashes" => [%{"content" => ^expected_hash}], "url" => "file:release.tar.gz"}] =
             decoded["externalReferences"]
  end

  defp cargo_lock(local_name) do
    """
    version = 4

    [[package]]
    name = "#{local_name}"
    version = "0.1.0"
    dependencies = [
     "serde",
    ]

    [[package]]
    name = "serde"
    version = "1.0.228"
    source = "registry+https://github.com/rust-lang/crates.io-index"
    checksum = "abc123"
    """
  end

  defp write_empty_inputs!(root) do
    File.write!(Path.join(root, "mix.lock"), "%{}\n")

    for nif <- ["recurse_cedar", "recurse_spiffe"] do
      lock_path = Path.join(root, "native/#{nif}/Cargo.lock")
      File.mkdir_p!(Path.dirname(lock_path))
      File.write!(lock_path, "version = 4\n")
    end
  end

  defp sbom_metadata(overrides \\ %{}) do
    Map.merge(
      %{
        release_name: "audit_console",
        release_version: "0.1.0",
        release_tag: "test-tag",
        vcs_ref: "abcdef",
        build_time: "2026-04-27T00:00:00Z",
        elixir_version: "1.19.5",
        otp_version: "28.0",
        erts_version: "16.0",
        rust_version: "1.92.0",
        openssl_version: "OpenSSL 3.0.17"
      },
      overrides
    )
  end
end
