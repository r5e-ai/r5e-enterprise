defmodule Recurse.Gateway.Policy.PolicyStarterBundleTest do
  @moduledoc """
  `policy-starter/` (spec 012 S5) is the template a user copies into their
  own git repo for the `git-policy` profile. Its bundle must stay
  byte-identical to the compose default, so the first sync from an
  unmodified starter repo is a no-op and the README's claims about "same
  content as the stack's default" hold.
  """

  use ExUnit.Case, async: true

  @root Path.expand("../../../..", __DIR__)
  @default Path.join(@root, "policy/bundle.cedar")
  @starter Path.join(@root, "policy-starter/policy/bundle.cedar")

  test "policy-starter/policy/bundle.cedar is byte-identical to policy/bundle.cedar" do
    assert File.read!(@starter) == File.read!(@default)
  end

  test "the starter bundle parses under the pinned Cedar NIF (what the CI job checks with the CLI)" do
    assert :ok = Recurse.Cedar.validate_policy_syntax(File.read!(@starter))
  end
end
