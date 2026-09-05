defmodule Recurse.Gateway.AuditPlane.ErrorEnvelope do
  @moduledoc """
  Single canonical error-envelope builder for every JSON-emitting handler in
  the Audit Plane and Admin Plane.

  ## Why this module exists (Issue #29 / Constitution Principle VII)

  Before this module landed, three different error envelope shapes coexisted
  in the gateway:

    * `Authz.error_body/4` (audit-plane handlers) emitted F001-shaped
      `{"error" => %{"code" => ..., "message" => ..., "correlation_id" => ...,
      "details" => ...}}` (nested).

    * `BrowserSessionPlug.send_unauthorized/2` (admin-plane cookie auth)
      emitted `{"error_code" => ...}` (flat, single-key, different field
      name).

    * `AuthMeHandler.send_unauthorized/2` emitted yet a third variant that
      most-resembled the SPA's expectation but wasn't shared with the other
      sites.

  The SPA's `ApiError` parser at `ui/src/lib/api.ts:19-43` defines the
  de-facto canonical shape — flat, with `error` as a string code,
  `error_description` as the message, plus `correlation_id`, optional
  `attested_run_id`, and `status`. NEITHER backend variant matched it,
  so every backend 401/403/404/500 currently degrades to the SPA's
  fallback rendering ("HTTP 401" inline). That's live bug LB-1 from
  the issue #29 audit-pass survey.

  This module makes the SPA's shape canonical. All 401/403/404/500
  emitters in the gateway delegate to `build/3` + `send_*/3` helpers
  here. Tests that previously expected the F001-nested shape are
  migrated as part of MR #29.

  ## The envelope

      %{
        "error" => "ERR_<UPPER_SNAKE>",        # stable machine-readable code
        "error_description" => "human msg",     # for UI display
        "correlation_id" => "uuid-or-unknown",  # request correlation
        "attested_run_id" => "run_..." | nil    # for forbidden errors that
                                                # produced a denial receipt;
                                                # nil otherwise
      }

  The `status` field on `ApiError` (SPA-side) is set from the HTTP status
  code, NOT the envelope body — so we don't include it server-side.

  ## Why we did NOT preserve the F001 nested shape

    * The SPA is the only known consumer of the audit-plane and admin-plane
      surfaces. Aligning to its expected shape closes the live bug AND the
      drift in one move.

    * Future external integrations (SIEM forwarders, recurse-verify CLI)
      can adapt to the flat shape — it's simpler than nested and has a
      precedent across major web APIs (RFC 7807 problem-details, GitHub
      API, Stripe).

  If a customer integration emerges that DOES need the F001-nested shape,
  add a `Plug` that translates this canonical shape to the legacy one
  per-route — don't fork this module.

  ## Canonical schema

  The wire shape this module emits is pinned by
  `apps/recurse_gateway/priv/schemas/error_envelope.json` (Draft 2020-12,
  `x-version: 1.0.0`, `x-status: stable`). That schema is the canonical
  contract — published via the `/v1/schemas/error_envelope.json` route
  and advertised in `manifest.json`. The placeholder shape that previously
  occupied that file (with `additionalProperties: true`) was retired in
  the same MR that landed Task L (issue #30).

  Tests in `test/audit_plane/error_envelope_test.exs` pin `build/3`'s
  output against the schema's required + optional keys to catch any
  future drift between the builder and the published contract.

  ## Iron Law

  Pure module. No process. Builds maps and pipes them into Plug.Conn
  via the existing handler.
  """

  alias Plug.Conn

  @recurse_correlation_header "x-recurse-correlation-id"

  @typedoc """
  Options for `build/3` + `send_*/3`:

    * `:correlation_id` — overrides the conn-resp-header lookup. Useful in
      tests and in handlers that compute the correlation_id before
      calling `Plug.Conn.put_resp_header/3`.
    * `:attested_run_id` — set when the error is a Cedar denial that
      produced a receipt; the SPA renders a "View attested receipt"
      link in error toasts using this field.
  """
  @type opts :: [
          {:correlation_id, String.t()}
          | {:attested_run_id, String.t() | nil}
        ]

  @doc """
  Build the canonical error envelope as a plain map. Most callers use
  `send_*/3` helpers below — this is the seam for tests and for
  callers that need to compose the body before sending (e.g., a custom
  retry-after header).
  """
  @spec build(code :: String.t(), description :: String.t(), opts()) :: map()
  def build(code, description, opts \\ []) when is_binary(code) and is_binary(description) do
    correlation_id = Keyword.get(opts, :correlation_id, "unknown")
    attested_run_id = Keyword.get(opts, :attested_run_id, nil)

    %{
      "error" => code,
      "error_description" => description,
      "correlation_id" => correlation_id,
      "attested_run_id" => attested_run_id
    }
  end

  @doc """
  Send a 401 Unauthorized with the canonical envelope.
  """
  @spec send_unauthorized(Conn.t(), code :: String.t(), description :: String.t(), opts()) ::
          Conn.t()
  def send_unauthorized(conn, code, description, opts \\ []) do
    send_envelope(conn, 401, code, description, opts)
  end

  @doc """
  Send a 403 Forbidden with the canonical envelope. Pass
  `attested_run_id:` in opts when a denial receipt was emitted so the
  SPA can deep-link to it.
  """
  @spec send_forbidden(Conn.t(), code :: String.t(), description :: String.t(), opts()) ::
          Conn.t()
  def send_forbidden(conn, code, description, opts \\ []) do
    send_envelope(conn, 403, code, description, opts)
  end

  @doc """
  Send a 400 Bad Request with the canonical envelope.
  """
  @spec send_bad_request(Conn.t(), code :: String.t(), description :: String.t(), opts()) ::
          Conn.t()
  def send_bad_request(conn, code, description, opts \\ []) do
    send_envelope(conn, 400, code, description, opts)
  end

  @doc """
  Send a 404 Not Found with the canonical envelope.
  """
  @spec send_not_found(Conn.t(), code :: String.t(), description :: String.t(), opts()) ::
          Conn.t()
  def send_not_found(conn, code, description, opts \\ []) do
    send_envelope(conn, 404, code, description, opts)
  end

  @doc """
  Send a 422 Unprocessable Entity with the canonical envelope. Used when
  the request was understood (auth + format ok) but the targeted resource
  cannot be served by-design — e.g. a payload fetch on a predicate-only
  receipt where the signed_predicate IS the audit content and no separate
  payload bytes were ever stored. Distinguished from 404 (resource is
  missing/unknown) and 400 (request was malformed).
  """
  @spec send_unprocessable_entity(Conn.t(), code :: String.t(), description :: String.t(), opts()) ::
          Conn.t()
  def send_unprocessable_entity(conn, code, description, opts \\ []) do
    send_envelope(conn, 422, code, description, opts)
  end

  @doc """
  Send a 503 Service Unavailable with the canonical envelope.
  """
  @spec send_service_unavailable(Conn.t(), code :: String.t(), description :: String.t(), opts()) ::
          Conn.t()
  def send_service_unavailable(conn, code, description, opts \\ []) do
    send_envelope(conn, 503, code, description, opts)
  end

  @doc """
  Send a 500 Internal Server Error with the canonical envelope.
  Generic — most handlers will use this with `code: "ERR_INTERNAL"`.
  """
  @spec send_internal_error(Conn.t(), code :: String.t(), description :: String.t(), opts()) ::
          Conn.t()
  def send_internal_error(conn, code, description, opts \\ []) do
    send_envelope(conn, 500, code, description, opts)
  end

  @doc """
  Lookup the `x-recurse-correlation-id` from the conn's resp_headers,
  defaulting to `"unknown"` when absent. Centralized so callers don't
  duplicate the lookup and don't disagree on the default.
  """
  @spec correlation_id_from_conn(Conn.t()) :: String.t()
  def correlation_id_from_conn(%Conn{} = conn) do
    case Enum.find(conn.resp_headers, fn {k, _} -> k == @recurse_correlation_header end) do
      {_, v} -> v
      nil -> "unknown"
    end
  end

  defp send_envelope(conn, status, code, description, opts) do
    correlation_id =
      Keyword.get_lazy(opts, :correlation_id, fn -> correlation_id_from_conn(conn) end)

    body =
      build(code, description, Keyword.put(opts, :correlation_id, correlation_id))

    conn
    |> Conn.put_resp_content_type("application/json")
    |> Conn.send_resp(status, JSON.encode!(body))
  end
end
