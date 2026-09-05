defmodule Recurse.Gateway.Observability.ReadyzTest do
  @moduledoc """
  `/readyz`'s `policy` line (spec 012 S5): active hash + last reload
  outcome, sourced from `Active` and `BundleLoader.status/2`.

  `async: false`: `Active` is a VM-global `:persistent_term` and the
  loader under test is registered by the module name `/readyz` looks
  up, so no two of these may run at once.
  """

  use ExUnit.Case, async: false

  setup_all do
    Recurse.Gateway.Test.KernelFixture.boot()
  end

  alias Recurse.Gateway.Observability.Readyz
  alias Recurse.Gateway.Policy.Active
  alias Recurse.Gateway.Policy.BundleLoader

  @entity_schema_path Path.expand("../../priv/cedar/schema.cedarschema.json", __DIR__)
  @permissive_policy "permit(principal, action, resource);\n"
  @malformed_policy "not a cedar policy {{{"

  setup do
    Active.erase()
    :ok
  end

  test "policy line is all-null before any loader has run" do
    assert %{
             "active_hash" => nil,
             "last_reload_at" => nil,
             "last_error" => nil,
             "last_error_at" => nil
           } = Readyz.policy_status()
  end

  @tag :tmp_dir
  test "reports the active hash, then the reload error after a broken push, without flipping the check",
       %{tmp_dir: tmp_dir} do
    bundle_path = Path.join(tmp_dir, "bundle.cedar")
    File.write!(bundle_path, @permissive_policy)

    # Registered under the real name: that is what Readyz.policy_status/0 asks.
    start_supervised!(
      {BundleLoader,
       [bundle_path: bundle_path, entity_schema_path: @entity_schema_path, trap_sighup: false]}
    )

    {:ok, %Active{bundle: %{bundle_id: hash}}} = Active.current()

    assert %{"active_hash" => ^hash, "last_reload_at" => at, "last_error" => nil} =
             Readyz.policy_status()

    assert {:ok, %DateTime{}, 0} = DateTime.from_iso8601(at)

    File.write!(bundle_path, @malformed_policy)
    BundleLoader.reload()
    # reload/1 is a cast; status/2 is a call on the same mailbox, so it
    # observes the reload's outcome.
    {:ok, _} = BundleLoader.status()

    assert %{"active_hash" => ^hash, "last_error" => error, "last_error_at" => err_at} =
             Readyz.policy_status()

    assert error =~ "bundle_parse_failure"
    assert {:ok, %DateTime{}, 0} = DateTime.from_iso8601(err_at)
    assert :ready = Readyz.check_policy_bundle()

    # The whole body carries it as a top-level key, next to `checks`.
    conn = Readyz.call(Plug.Test.conn(:get, "/readyz"), [])
    body = JSON.decode!(conn.resp_body)
    assert body["policy"]["active_hash"] == hash
    assert body["policy"]["last_error"] =~ "bundle_parse_failure"
    assert body["checks"]["policy_bundle"] == "ready"
  end
end
