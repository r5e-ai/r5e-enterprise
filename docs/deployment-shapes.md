# Deployment shapes

For the person working out which of three situations they are in before reading any instructions.

The gateway is the same program in all three. What differs is who runs it, where the client's traffic is routed from, and what the surrounding setup declares about the client's other network paths. Each section below states what the gateway sees in that situation.

## Local demo on your own machine

This is what the compose stack in this repository is: Postgres, the gateway, and optionally a policy-sync sidecar and a log shipper, running under Docker on one machine, with Claude Code on the same machine pointed at the gateway's loopback port.

The demo exists to show how the system works and that it works. It is not a deployment, and its setup says so:

| Part | In the demo |
|---|---|
| Principal | one fixed local identity, not a person authenticated by an identity provider |
| Sign-in to the console | a dev login the compose file enables |
| Transport to the gateway | cleartext HTTP on loopback and the compose network |
| Signing key | generated on first boot into a volume on the same disk as the ledger |
| Tenant | one |

Under the local demo's setup, every model call Claude Code makes passes through the gateway and produces a receipt. Claude Code's token refresh for a claude.ai login, its calls for account features such as connector listings, and its telemetry go directly to Anthropic and to a telemetry host, not through the gateway; they are not model calls and produce no receipts.

## Managed employee laptop

This is Claude Code on a company-managed device, with the gateway on a company host.

Claude Code reads its base URL from managed settings, so the platform team sets `ANTHROPIC_BASE_URL` and `NO_PROXY` there and the employee does not touch them. The desktop application's Code tab reads the same settings.

The operator owns the following, and the compose stack in this repository provides none of them:

| Operator owns | What it means |
|---|---|
| The endpoint | a hostname every managed laptop can reach, published in managed settings |
| TLS in front of it | the gateway listens on plain HTTP; a terminating proxy or load balancer carries the certificate the laptops trust |
| Identity | on a managed device the OS login is the identity the organization already trusts. The TLS terminator in front of the gateway can request the device certificate issued by MDM (Entra, Jamf, Kandji) |
| The policy repository | the git repository the sidecar syncs from; its merge rights are the right to change what the gateway enforces |
| Key custody | the signing key the receipts are made with, in a key management service rather than a file in a volume |

Today's demo records `principal_source: client_metadata`, the account id Claude Code asserts in its request; a certificate-bound source, `mtls_svid`, is reserved in the gateway and not produced. The field is in the receipt's predicate body, `predicate/<run_id>.json` in an evidence export.

Under this setup, every model call from a laptop whose managed settings point at the gateway passes through it and produces a receipt. The laptop's token refresh, account calls, and telemetry go directly to Anthropic and produce no receipts. A laptop whose settings do not point at the gateway produces no receipts; the operator's statement that managed settings cover the fleet is the statement under which the receipts are read.

## Autonomous agent in a container or pod

This is an agent running headless, in CI or in a pod, with no person at a keyboard.

The agent container runs without root and with network egress only to the gateway's proxy port: a compose network marked internal that it shares with the gateway alone, or a pod network policy that says the same thing. The repository it works on is mounted in; its credential arrives as an environment variable, as an API key rather than a claude.ai login so that there is no token refresh to route. The gateway container in turn runs without root, with a read-only filesystem, all capabilities dropped, and egress only to the upstream.

The compose file, the Dockerfile, and any pod policy are the containment declaration. They are the bytes that state no root and egress only to the gateway, they are content-addressed, and a deployment record can cite them by hash. Claims about this shape are made under that declared containment: under it, the agent has no route to Anthropic except through the gateway.

Under this setup, every model call the agent makes passes through the gateway and produces a receipt, because there is no other route out. The client's direct calls for account features and telemetry have no route out of the container; they are not model calls and produce no receipts.
