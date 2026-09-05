defmodule Recurse.Gateway.Test.LegacyChatHandler do
  @moduledoc """
  Internal handler integration coverage for the retired chat-completions path.

  First asserts that the public router refuses this capability. Then, on a
  separate connection, exercises the retained handler directly for its legacy
  provider, receipt, and SIEM contracts. This is not a production routing plug.
  """
  import ExUnit.Assertions
  import Plug.Conn

  alias Recurse.Gateway.Identity.IdentityContextBuilder
  alias Recurse.Gateway.ProviderRegistry
  alias Recurse.Gateway.Router

  def call(conn) do
    public_conn = Plug.Test.conn(:post, "/v1/chat/completions", "{}")
    public_conn = %{public_conn | req_headers: conn.req_headers}
    refused = Router.call(public_conn, Router.init([]))
    assert refused.status == 503
    assert %{"error" => %{"code" => "capability_unavailable"}} = JSON.decode!(refused.resp_body)
    # Plug.Test reports sends to the test mailbox, including this separate refusal.
    assert_receive {ref, {503, _headers, _body}} when is_reference(ref)
    assert_receive {:plug_conn, :sent}

    opts = Application.get_env(:recurse_gateway, :jwt_validator_opts, [])

    {:ok, ctx} =
      IdentityContextBuilder.build(conn.req_headers, ProviderRegistry.tenant_id(), opts)

    conn
    |> Plug.Parsers.call(Plug.Parsers.init(parsers: [:json], json_decoder: JSON))
    |> assign(:identity_ctx, ctx)
    |> put_resp_header("x-recurse-correlation-id", ctx.correlation_id)
    |> Recurse.Gateway.DataPlane.ChatCompletionsHandler.handle()
  end
end
