defmodule RecurseBroker.JWKS.Endpoint do
  @moduledoc """
  Plug handler for `GET /oidc/jwks` (F002 T087).

  Pure module-Plug (NOT `Plug.Router`) — `RecurseBroker.Endpoint`'s
  `get "/oidc/jwks"` route forwards here. Keeping this a plain Plug
  makes the response trivially composable with fresh routing layers
  (e.g., a future Gateway-side proxy) without inheriting a whole
  router's middleware stack.

  Publishes every non-expired signing key held by
  `RecurseBroker.JWT.KeyRing.all_active_keys/0` as a JWKS document
  shaped per `contracts/recurse_broker_api.md` "GET /oidc/jwks":

  ```json
  {"keys": [{"kty":"EC","crv":"P-256","kid":"...","use":"sig","alg":"ES256","x":"...","y":"..."}, ...]}
  ```

  Keys are **public-half only** (`JOSE.JWK.to_public/1`) and sorted
  by `kid` ascending for deterministic diffing during operator
  rotation drills.

  ## Caching

  Emits `cache-control: public, max-age=300` per F002 FR-007 — the
  Gateway caches JWKS for 5 min and refreshes on `kid`-miss. The
  `cache-control` header is authoritative for downstream proxies;
  Gateway-side cache semantics live in `recurse_gateway`.

  ## Failure mode

  If the KeyRing is not yet ready (boot race, or active kid cleared
  during a broken rotate), respond 503 with a JSON body so the
  Gateway can distinguish "broker is up but empty" from "broker is
  down". A 200 with `{"keys": []}` would be legal JWKS but actively
  harmful — the Gateway would cache an empty set for 5 min and
  reject every token. 503 forces a fresh fetch.

  ## Cross-references

    * `specs/002-standalone-gateway-vertical-slice/contracts/recurse_broker_api.md`
      ("GET /oidc/jwks" — response shape + caching)
    * `specs/002-standalone-gateway-vertical-slice/research.md` D2
    * `specs/002-standalone-gateway-vertical-slice/tasks.md` T087
  """

  @behaviour Plug

  import Plug.Conn

  alias RecurseBroker.JWT.KeyRing

  @impl Plug
  def init(opts), do: opts

  @impl Plug
  def call(%Plug.Conn{method: "GET"} = conn, _opts) do
    case KeyRing.all_active_keys() do
      {:ok, keys_map} ->
        body = Jason.encode!(%{"keys" => build_key_list(keys_map)})

        conn
        |> put_resp_content_type("application/json", "utf-8")
        |> put_resp_header("cache-control", "public, max-age=300")
        |> send_resp(200, body)

      {:error, _reason} ->
        body =
          Jason.encode!(%{
            "error" => "temporarily_unavailable",
            "error_description" => "keyring not ready"
          })

        conn
        |> put_resp_content_type("application/json", "utf-8")
        |> send_resp(503, body)
    end
  end

  def call(conn, _opts) do
    body = Jason.encode!(%{"error" => "method_not_allowed"})

    conn
    |> put_resp_content_type("application/json", "utf-8")
    |> put_resp_header("allow", "GET")
    |> send_resp(405, body)
  end

  defp build_key_list(keys_map) do
    keys_map
    |> Enum.map(fn {kid, jwk} -> public_jwk_with_metadata(kid, jwk) end)
    |> Enum.sort_by(& &1["kid"])
  end

  defp public_jwk_with_metadata(kid, %JOSE.JWK{} = jwk) do
    {_, public_fields} =
      jwk
      |> JOSE.JWK.to_public()
      |> JOSE.JWK.to_map()

    public_fields
    |> Map.put("kid", kid)
    |> Map.put("use", "sig")
    |> Map.put("alg", "ES256")
  end
end
