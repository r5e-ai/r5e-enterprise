defmodule Recurse.Fold do
  @moduledoc """
  The fold's public surface: **admit something, as the fold**.

  Two functions, and everything else in this app is behind them. A caller —
  the demo script, a test, the LLM proxy of spec 012 — says what Kind and
  what spec, and gets back a receipt. What it never has to know is that the
  act is signed, by which key, or under whose authority: those are facts
  about this deployment's record, settled here once.

  ## The fold's key, and where its authority comes from

  At its first boot the fold generates `foldKey` under the kernel's data
  directory (`R5e.Signer.Local.role_keypair/2` — same custody as the node
  key and the retention key, and the private half never leaves this node),
  and the **node key** admits

      Endorsement{subject: foldKey, role: "fold",
                  kinds: <exactly the Kinds the fold admits>, mayIssue: false}

  through `R5e.Bootstrap.endorse_role/3`, exactly as it endorses the
  retention sweeper at event 10 (spec 011 contract §10). Every fold
  admission is then signed by `foldKey` and cites that Endorsement in
  `authority`.

  **The grant is the minimum the role exercises** (contract r4.5 §10):
  `core.r5e.io/v1/KindDefinition`, `core.r5e.io/v1/CasObject`, and the
  nine Kinds of the gateway group — nothing else — and `mayIssue: false`.
  It was `["*"], mayIssue: true`, and that was wrong in a way worth
  stating: root issuance is ungated, so anyone may *claim* anything, but
  `mayIssue: true` under the node key's own root let the fold key hand out
  authority **rooted at the node key** — a thing no reader's pin of the
  node key was consenting to. spec/03's narrowing sentence applies to a
  deployment's own first grant as much as to a delegate's. Widening is a
  new Endorsement, which is an act.

  That is the whole of the change from the fold's first version, and it is
  not cosmetic. Before, the fold admitted under `system:recurse-fold`, a
  string with a placeholder fingerprint beside it: the chain recorded a
  name nobody could check. Now the chain records a **key**, a signature
  over the canonical request, and the endorsement chain that key was acting
  under — all three re-derivable offline by anyone holding the bundle.
  `system:recurse-fold` is deleted rather than aliased; nothing on a new
  chain refers to it.

  **Renewal, and what happens when there is none.** `authority/0` asks for
  the newest *effective* Endorsement for the role
  (`R5e.Bootstrap.role_endorsement/2`, which filters by §5's walk), so an
  operator renewing the grant before its `notAfter` simply admits a new
  one and the next act cites it. A revoked or expired Endorsement is not
  cited merely for being the most recent.

  When **none** is effective, `admit/3` and `put_cas/2` return
  `{:refused, "fold authority not effective: …"}` and submit nothing.
  Role Endorsements are minted **at boot only** (contract r4.5 §10), and
  only when the chain carries **no Endorsement for this role and key at
  all**. The earlier version minted one on demand, which meant revoking
  the fold's Endorsement was undone by the fold's very next act. The
  version after that minted at every boot whenever the lookup came back
  empty — and a revoked Endorsement is exactly an empty lookup, so a
  `systemctl restart`, a pod eviction or an OOM kill restored the
  revoked authority with nobody deciding anything (RC review 2026-09-05,
  K4). A revocation a restart reverses is a suspension. So the boot mint
  is keyed on **presence in history**, not on effectiveness: once an
  Endorsement for (role, subject) has been recorded, restoring the role
  is an operator's act — a new Endorsement admitted under the node key —
  and never a side effect of starting the process. Until then the fold
  refuses every act and `/readyz` says why.

  ## What the two functions return

  Both return `{:ok, receipt}` / `{:denied, receipt}` / `{:refused, reason}`.
  **A denial is a return value, never an exception.** A policy refusing an
  act is the system working, and it produces a receipt that says who
  refused it and under which bundle; raising would throw that receipt away
  and leave the caller with a stack trace instead of evidence.

  `{:refused, reason}` is the third case spec 011 §2 adds and it means
  something different: the request was not an *act* at all — the envelope
  was malformed or the signature did not verify, so nothing was recorded
  and no nonce was spent. On a fold-signed request it should be
  unreachable; it is in the return type because pretending otherwise would
  make a caller treat "nothing happened" as "you were refused".

  ## A worked example

      iex> {:ok, receipt} =
      ...>   Recurse.Fold.admit("gateway.r5e.io/v1alpha1/ToolCall", %{
      ...>     "tool" => "shell",
      ...>     "args" => %{"command" => "ls -la"},
      ...>     "llmCall" => %{"$ref" => call_event_ref},
      ...>     "index" => 1
      ...>   })
      iex> receipt["outcome"]
      "admitted"
      iex> receipt["policy"]["bundle"]
      "sha256:…"                       # the policy that allowed it
      iex> receipt["resolvedAuthority"] |> hd() |> Map.get("chain") |> List.last()
      %{"actor" => "key:ed25519:sha256:…", …}   # the node key, at the root

  and the same act with `rm -rf` comes back `{:denied, receipt}` with
  `receipt["policy"]["evaluation"]` naming the exact bytes Cedar was
  handed.
  """

  alias Recurse.Fold.Policy.Cedar

  @role "fold"

  # The two core Kinds the fold admits beside its own group: its seeds are
  # KindDefinitions, and its detached bytes (the policy text, the reviewed
  # specification, prompts and completions) are CasObjects.
  @core_kinds ["core.r5e.io/v1/CasObject", "core.r5e.io/v1/KindDefinition"]

  @doc """
  The fold's own keypair, generated under the kernel's data directory on
  first use and read from there afterwards.
  """
  @spec key() :: %{public: binary(), private: binary(), algorithm: String.t()}
  def key, do: R5e.Signer.Local.role_keypair(@role)

  @doc "The §0 key id the fold signs under."
  @spec key_id() :: String.t()
  def key_id, do: R5e.Request.key_id(key())

  @doc "The role name the fold's Endorsement carries."
  @spec role() :: String.t()
  def role, do: @role

  @doc """
  The Kinds the fold's Endorsement covers — **exactly** the Kinds it
  admits, and nothing else (contract r4.5 §10).

  Derived from the seed files rather than written down twice: a tenth
  Kind added to `priv/kinds/` widens the grant at the next boot, and a
  grant that named `*` would have hidden that from a reader.
  """
  @spec kinds() :: [String.t()]
  def kinds do
    seeded =
      for path <- Recurse.Fold.Application.kind_paths() do
        spec = path |> File.read!() |> Jason.decode!()
        "#{spec["group"]}/#{spec["version"]}/#{spec["kind"]}"
      end

    Enum.sort(@core_kinds ++ seeded)
  end

  @doc """
  The `event:` ref of the Endorsement every fold admission cites — the
  newest **effective** one for this role and this key, or `nil`.

  It is a **lookup and never a mint**. Minting happens once, on the first
  boot of a chain that has never endorsed this role, in
  `endorse_at_boot/0`; see the moduledoc for why an act may not mint its
  own authority.
  """
  @spec authority() :: String.t() | nil
  def authority, do: R5e.Bootstrap.role_endorsement(@role, key_id())

  @doc """
  Mint the fold's role Endorsement **only if the chain has never carried
  one** for this role and this key. Called once, from
  `Recurse.Fold.Application.start/2`, and from nowhere else — contract
  r4.5 §10: role Endorsements are minted at boot only.

  Returns `{:ok, ref}` with the Endorsement to cite, or
  `{:refused, reason}` when one was recorded and is no longer effective —
  revoked, expired, or otherwise refused by §5's walk. **A refusal is not
  a mint.** The fold then boots without authority, seeds nothing, refuses
  every act, and `/readyz` reports the standing (`role_standing/0`); an
  operator restores it by admitting a new Endorsement under the node key,
  which is an act on the chain rather than a restart.

  Still raises in one case: the node key's own Endorsement of the fold key
  is *denied* by the kernel on a chain that has never endorsed this role.
  That is a broken deployment, not an operator's decision — booting on
  would put a half-authorised extension on the chain.
  """
  @spec endorse_at_boot() :: {:ok, String.t()} | {:refused, String.t()}
  def endorse_at_boot do
    case {authority(), newest_endorsement()} do
      {ref, _} when is_binary(ref) ->
        {:ok, ref}

      {nil, {_ref, _walk}} ->
        refuse("fold authority not effective: " <> why_not_effective())

      {nil, nil} ->
        mint_first_endorsement()
    end
  end

  defp mint_first_endorsement do
    case R5e.Bootstrap.endorse_role(key().public, @role, kinds: kinds(), may_issue: false) do
      {:ok, receipt} ->
        {:ok, receipt["eventRef"]}

      {:denied, receipt} ->
        raise """
        recurse_fold could not obtain its own authority: the kernel denied
        the node key's Endorsement of the fold key.

          reason: #{receipt["reason"]}

        Nothing the fold does is admissible without it, so booting on
        would put a half-authorised extension on the chain.
        """
    end
  end

  @doc """
  The standing of the fold's role Endorsement, asked of the chain now.

  One of:

    * `"effective"` — an Endorsement for this role and key resolves;
    * `"role revoked; explicit re-endorsement required"` — one was
      recorded and a Revocation ended it;
    * `"role Endorsement not effective (…); explicit re-endorsement
      required"` — one was recorded and §5's walk refuses it for another
      reason (out of term, a broken parent, an ineffective root);
    * `"never endorsed"` — nothing for this (role, subject) is on the
      chain, which is the state a first boot mints from.

  The revoked wording is a reading of the walk's own reason, and the walk's
  full reason travels beside it in `status/0`'s `last_refusal`, so nothing
  is hidden behind the shorter phrase.
  """
  @spec role_standing() :: String.t()
  def role_standing do
    case {authority(), newest_endorsement()} do
      {ref, _} when is_binary(ref) -> "effective"
      {nil, nil} -> "never endorsed"
      {nil, {_ref, walk}} -> ineffective_standing(walk)
    end
  end

  defp ineffective_standing(walk) do
    if String.contains?(walk.reason || "", "revoked"),
      do: "role revoked; explicit re-endorsement required",
      else: "role Endorsement not effective (#{walk.reason}); explicit re-endorsement required"
  end

  @doc """
  Read-only standing of the fold, for `/readyz` (spec 012 S9a):

      %{"enabled" => boolean, "kernel" => "running" | "stopped",
        "authority_effective" => boolean,
        "role_standing" => String.t(),
        "last_refusal" => %{"reason" => String.t(), "at" => String.t()} | nil}

  `authority_effective` is `authority/0` asked right now — a Revocation of
  the fold's Endorsement shows here as `false` at the next probe, and every
  `admit/3` after it as `{:refused, …}`. `role_standing` says what a
  restart would and would not fix: a revoked role reads `"role revoked;
  explicit re-endorsement required"` and stays that way across reboots,
  because boot mints only for a (role, subject) the chain has never
  endorsed (§10, RC review K4). `last_refusal` is the most recent
  `{:refused, reason}` either function returned since boot, so a refusal
  the caller did not log is still visible to the operator. Never raises:
  a fold whose kernel is down reports that rather than crashing the probe.
  """
  @spec status() :: map()
  def status do
    enabled = Recurse.Fold.Application.enabled?()
    kernel_up = Process.whereis(R5e.Supervisor) != nil

    effective =
      if enabled and kernel_up do
        safely_ask(fn -> is_binary(authority()) end, false)
      else
        false
      end

    standing =
      cond do
        effective ->
          "effective"

        enabled and kernel_up ->
          safely_ask(&role_standing/0, "unknown (the chain was unreadable)")

        true ->
          "unknown (the fold's kernel is not running)"
      end

    %{
      "enabled" => enabled,
      "kernel" => if(kernel_up, do: "running", else: "stopped"),
      "authority_effective" => effective,
      "role_standing" => standing,
      "last_refusal" => Application.get_env(:recurse_fold, :last_refusal)
    }
  end

  # A readiness probe reports; it never crashes because the thing it is
  # reporting on is broken.
  defp safely_ask(fun, fallback) do
    fun.()
  rescue
    _ -> fallback
  catch
    :exit, _ -> fallback
  end

  # §10: outside boot there is no minting. A revoked or expired role
  # Endorsement is a refusal the caller sees in the return type — nothing
  # is submitted, so nothing is recorded, because a request the fold knows
  # it cannot authorise is not worth spending a nonce on.
  #
  # A fold that is loaded but not enabled (spec 012 S9a) has no kernel to
  # ask, and says so in the same arm: the call is not dropped, and the
  # reason names the switch.
  defp with_authority(fun) do
    cond do
      not Recurse.Fold.Application.enabled?() ->
        refuse("the fold is disabled (R5E_FOLD_ENABLED is not true); nothing is recorded")

      Process.whereis(R5e.Supervisor) == nil ->
        refuse("the fold's kernel is not running; nothing is recorded")

      true ->
        case authority() do
          ref when is_binary(ref) ->
            fun.(ref)

          nil ->
            refuse("fold authority not effective: " <> why_not_effective())
        end
    end
  end

  # Every `{:refused, …}` passes through here so `status/0` can show the
  # last one. Application env rather than a process: the fold supervises
  # nothing, and this is a note for the operator, not state the chain
  # depends on.
  defp refuse(reason) do
    Application.put_env(:recurse_fold, :last_refusal, %{
      "reason" => reason,
      "at" => DateTime.utc_now() |> DateTime.truncate(:second) |> DateTime.to_iso8601()
    })

    {:refused, reason}
  end

  # The reason, from the chain rather than guessed: the newest Endorsement
  # for this role and key, and what §5's walk says about it.
  defp why_not_effective do
    case newest_endorsement() do
      nil ->
        "no Endorsement for role #{inspect(@role)} and subject #{key_id()} is on this chain; " <>
          "the next boot mints the first one"

      {ref, walk} ->
        "#{ref} is #{walk.reason}; role Endorsements are minted at boot only and only for a " <>
          "role this chain has never endorsed, so neither the fold nor a restart can restore " <>
          "it — an operator admits a new Endorsement under the node key"
    end
  end

  defp newest_endorsement do
    s = R5e.Succession.next_seq()
    ts = R5e.Clock.ts()

    found =
      for event <- R5e.Log.read_events(),
          event["kind"] == "admission.granted",
          {:ok, payload} <- [R5e.Log.payload(event)],
          R5e.Admission.target_path(payload) == "core.r5e.io/v1/Endorsement",
          payload["spec"]["role"] == @role,
          payload["spec"]["subject"] == key_id(),
          ref = R5e.Admission.event_ref(event) do
        {ref, R5e.Authority.effective(ref, s, ts)}
      end

    List.last(found)
  end

  @doc """
  Admit `spec` as an instance of `kind` (a `group/version/Kind` path),
  signed by the fold key and citing the fold's Endorsement.

  Options:

    * `:name` — the instance name, for the naming modes that take one
      (`caller`, `literal`, `derived`, and a `server` replace). Omit it and
      the kernel assigns one where the mode says it does.
    * `:derived_from` — a `bytes:sha256:…` address of the natural-language
      document this spec was derived from. An **envelope** field: it is
      recorded beside the spec and never inside it, so the authored file is
      the admitted bytes.
    * `:transition` — declares this admission a **same-identity
      transition** (§10): a `path`-named definition whose bytes changed,
      superseding the one on the chain rather than colliding with it. Only
      the actor of record on the existing definition (or the node key) may
      perform one, and the reason is recorded on the payload. Use
      `R5e.Bootstrap.transition_reason/0` rather than a literal.
  """
  @spec admit(String.t(), map(), keyword()) ::
          {:ok, map()} | {:denied, map()} | {:refused, String.t()}
  def admit(kind, spec, opts \\ []) when is_binary(kind) and is_map(spec) do
    with {:ok, group, version, k} <- split(kind) do
      name = Keyword.get(opts, :name)
      target = %{"group" => group, "version" => version, "kind" => k, "name" => name}

      with_authority(fn ref ->
        envelope =
          R5e.Request.sign(
            %{
              target: target,
              spec: spec,
              derived_from: Keyword.get(opts, :derived_from),
              authority: [ref]
            },
            [key()]
          )

        outcome(
          R5e.Admission.admit(%{
            envelope: envelope,
            group: group,
            version: version,
            kind: k,
            name: name,
            spec: spec,
            transition: Keyword.get(opts, :transition)
          })
        )
      end)
    end
  end

  # A malformed Kind path is the caller's mistake and not an act: nothing
  # is submitted, so it comes back in the `{:refused, …}` arm the type
  # already has rather than as a MatchError. The surface is frozen for
  # spec 012, so it cannot grow a fourth return shape for this.
  defp split(kind) do
    case String.split(kind, "/") do
      [group, version, k] when group != "" and version != "" and k != "" ->
        {:ok, group, version, k}

      _ ->
        refuse(
          "#{inspect(kind)} is not a group/version/Kind path, so there is no target to admit to"
        )
    end
  end

  @doc """
  Put raw bytes on the record — the `PUT /cas` path, signed by the fold key.

  Returns `{:ok, receipt, address}` where `address` is the
  `bytes:sha256:…` a later spec cites. The bytes are written **only** as
  the `admit` step of a granted admission: a refusal leaves nothing behind.

    * `:media_type` — the label recorded on the `CasObject` spec, from the
      `content-type` a caller would have sent. Omitted when absent, because
      "no label" and "an empty label" are different claims.
  """
  @spec put_cas(binary(), keyword()) ::
          {:ok, map(), String.t()} | {:denied, map()} | {:refused, String.t()}
  def put_cas(bytes, opts \\ []) when is_binary(bytes) do
    media_type = Keyword.get(opts, :media_type)
    spec = R5e.CAS.object_spec(bytes, media_type)

    with_authority(fn ref ->
      envelope =
        R5e.Request.sign(
          %{
            target: %{
              "group" => "core.r5e.io",
              "version" => "v1",
              "kind" => "CasObject",
              "name" => nil
            },
            spec: spec,
            authority: [ref]
          },
          [key()]
        )

      case R5e.CAS.admit(envelope, bytes, media_type) do
        {:ok, receipt, address, _size} ->
          {:ok, receipt, address}

        {:denied, receipt} ->
          outcome({:denied, receipt})

        # `R5e.CAS.admit/3` is documented as returning those two. A third
        # shape is a kernel this fold was not built against, and saying so
        # is better than a FunctionClauseError from a frozen surface.
        other ->
          {:refused, "the kernel returned #{inspect(other, limit: 3)} from PUT /cas"}
      end
    end)
  end

  @doc "The coordinates of the policy bundle in force, for a caller that wants to read it."
  defdelegate bundle_coordinates(), to: Cedar

  # §2/§12: an unattributable request is not an act, and the receipt says so
  # (`recorded: false`). Told apart here rather than left for every caller to
  # notice, because "your act was refused" and "your request was not an act"
  # are the distinction the whole stage list exists to draw.
  defp outcome({:ok, receipt}), do: {:ok, receipt}

  defp outcome({:denied, %{"recorded" => false, "reason" => reason}}), do: refuse(reason)

  defp outcome({:denied, receipt}), do: {:denied, receipt}
end
