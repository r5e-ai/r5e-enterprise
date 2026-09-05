# Codex and other clients

For someone who uses Codex, or a client other than Claude Code, and wants to know whether the gateway applies to it.

## Why Claude Code needs one environment variable

Claude Code documents a gateway setting. `ANTHROPIC_BASE_URL` sends every model call to the address given, the credential travels with the request, and a plain `http://` address is accepted, so the gateway needs no DNS change and no certificate on the client.

## Why Codex needs more

Codex signed in with a ChatGPT account talks to its ChatGPT-login backend, and there is no documented gateway setting for that backend. The client also does not know it is being proxied, so the gateway has to be where the client thinks the backend is, and it has to present a certificate the client trusts.

That is a man-in-the-middle, and it takes three pieces:

| Piece | What it does |
|---|---|
| Hosts override | sends the client's `chatgpt.com` to loopback, where a port bridge hands port 443 to the gateway's proxy port |
| A local certificate authority | a two-tier CA whose leaf the gateway serves for `chatgpt.com`; the client trusts it through its own certificate environment variable, because Codex carries its own root store and ignores the system keychain |
| Bypass DNS in the gateway | the gateway resolves `chatgpt.com` against public DNS so it still reaches OpenAI despite the override on the same machine |

There is a second reason Codex is harder to govern. Its tool-call shape has taken three forms across releases: the item type and the key that carries the arguments have both moved. The gateway's parser and the shipped policy cover the shapes confirmed so far, and the parser logs any shape it does not recognise so a change is visible rather than silent.

## Status of the Codex path

The MITM runbook was last validated on Codex 0.149, in a separate workspace, before this compose stack existed. It is not part of the supported quickstart. It needs root for the hosts override and is written for macOS.

What the operator does, in order. Sign in to Codex (`codex login`) before touching `/etc/hosts`, so the OAuth flow runs against the real backend and not through the interception. Start the gateway with its LLM-proxy listener serving a two-tier certificate for `chatgpt.com`: a single self-signed certificate marked `CA:TRUE` is accepted by curl but rejected by Codex's Rust TLS stack (`CaUsedAsEndEntity`), after which Codex parks in "waiting for network". Add `/etc/hosts` entries that send `chatgpt.com` and the other hosts the client reaches to `127.0.0.1`, flush the DNS cache, and run a port bridge (for example `socat`) from 443 to the gateway's proxy port; the repository does not ship a script for the hosts change, so make it by hand and revert it when the session is over. Export `CODEX_CA_CERTIFICATE` pointing at the CA file, not the served leaf, and start Codex in that shell; setting `SSL_CERT_FILE` to the bare CA file would replace the trust store rather than extend it, so if that route is used it needs a bundle of the system roots plus the CA. When finished, remove the hosts entries and stop the bridge.

Unverified: the Codex 0.149 binary carries a `chatgpt_base_url` configuration key and a matching environment variable. If the client honours it for the ChatGPT-login backend, a configured base URL would replace the hosts override and the TLS interception, leaving Codex with the same one-setting shape as Claude Code.

## Other clients

A client with a base-URL setting for the Anthropic Messages or OpenAI Responses formats can be pointed at the gateway the same way Claude Code is. A client that does not is in Codex's situation and needs the MITM. In both cases the receipts cover the model calls that reach the gateway, and the parser's unrecognised-event log names any shape the gateway did not extract a tool call from.
