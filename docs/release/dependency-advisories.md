# Dependency advisory response

This release updates HTTP server/client and database dependencies after reviewing their published advisory metadata. A clean container build used newer Hex tooling than the host and reported additional affected packages. The lockfile records the selected versions and their resolved transitive dependencies.

## Selected versions

| Package | Previous lock | New lock | Why this version |
| --- | --- | --- | --- |
| Bandit | 1.10.4 (enterprise), 1.12.0 (kernel) | 1.12.5 | 1.12.5 is the first release outside the affected ranges for the two most recent Bandit advisories, including the high-severity HTTP/2 connection-window denial of service. Earlier fixes in 1.11.x and 1.12.1 are also included. See the [Bandit advisory index](https://hex.pm/packages/bandit/advisories). |
| Plug | 1.19.1 (enterprise), 1.20.3 (kernel) | 1.20.3 | 1.19.1 is affected by four multipart, query-decoding, cookie, and resource-exhaustion advisories. The fixes finish at 1.19.5; 1.20.3 is the current stable patch and matches the kernel's existing secure lock. See the [Plug advisory index](https://hex.pm/packages/plug/advisories). |
| Req | 0.5.17 | 0.6.3 | The multipart-header fix begins at 0.6.0 and the decompression-bomb fix at 0.6.1. 0.6.3 stays on the smallest fixed minor series and avoids the broader 0.7 migration. See the [Req advisory index](https://hex.pm/packages/req/advisories), [GHSA-px9f-whj3-246m](https://github.com/wojtekmach/req/security/advisories/GHSA-px9f-whj3-246m), and [GHSA-655f-mp8p-96gv](https://github.com/wojtekmach/req/security/advisories/GHSA-655f-mp8p-96gv). |
| Mint | 1.7.1 | 1.10.0 | Fixes accumulated HTTP/1 and HTTP/2 parsing, buffering, smuggling, and denial-of-service issues. The advisories published on 2026-09-04 affect every earlier version, so 1.10.0 is the minimum fully fixed version. See the [Mint advisory index](https://hex.pm/packages/mint/advisories) and [Mint changelog](https://github.com/elixir-mint/mint/blob/main/CHANGELOG.md). |
| Finch | 0.21.0 | 0.23.0 | Required to admit Mint 1.10.0: Finch 0.21 constrains Mint to the 1.6/1.7 lines, while Finch 0.23 admits the fixed Mint line. Finch is upgraded only for that compatibility requirement. See [Finch 0.23.0 on Hex](https://hex.pm/packages/finch/0.23.0). |
| Thousand Island | 1.4.3 | 1.5.0 | Required by Bandit 1.12.5. This is a transitive lockfile update rather than a new direct constraint. See [Thousand Island 1.5.0 on Hex](https://hex.pm/packages/thousand_island/1.5.0). |
| Cowboy | 2.14.2 | 2.18.0 | The package version index marks earlier versions vulnerable. See [Cowboy versions](https://hex.pm/packages/cowboy/versions). |
| Cowlib | 2.16.0 | 2.19.0 | Updated with Cowboy after the clean-build advisory warnings. See [Cowlib 2.19.0](https://hex.pm/packages/cowlib/2.19.0). |
| Decimal | 2.3.0 | 3.1.1 | The maintainer's advisory names 3.0.0 as the fixed major series; 2.4.1 remains in the affected range despite partial mitigations. See [Decimal advisory](https://github.com/ericmj/decimal/security/advisories/GHSA-rhv4-8758-jx7v). |
| HPAX | 1.0.3 | 1.0.4 | Updated in both enterprise and kernel locks. See [HPAX 1.0.4](https://hex.pm/packages/hpax/1.0.4). |
| Plug Cowboy | 2.8.0 | 2.9.0 | Updated after the clean-build advisory warnings. See [Plug Cowboy 2.9.0](https://hex.pm/packages/plug_cowboy/2.9.0). |
| Postgrex | 0.22.0 | 0.22.4 | The package version index marks earlier 0.22 releases vulnerable. See [Postgrex versions](https://hex.pm/packages/postgrex/versions) and its [changelog](https://github.com/elixir-ecto/postgrex/blob/master/CHANGELOG.md). |

The direct HTTP constraints are `bandit ~> 1.12.5`, `plug ~> 1.20.3`, `req ~> 0.6.3`, and `finch ~> 0.23.0`. The second resolution also advanced DBConnection, Jason, Plug Crypto, Ranch, and Telemetry within their accepted version ranges. Ecto and Ecto SQL advance to their 3.14 series to support Decimal 3. Mint, Thousand Island, Cowboy, Cowlib, Decimal, and HPAX remain transitive.

Cowlib 2.19.0 remains listed for three encoder advisories without a fixed
Hex release range ([CVE-2026-43971](https://cna.erlef.org/cves/CVE-2026-43971.html),
Link directive injection; [CVE-2026-43966](https://cna.erlef.org/cves/CVE-2026-43966.html),
structured-field response splitting; [CVE-2026-43969](https://cna.erlef.org/cves/CVE-2026-43969.html),
request-cookie injection). A static review of the 2.19.0 source on
2026-09-04 found the affected encoders present (`cow_link:link/1`,
`cow_http_struct_hd`'s string escaping and its `cow_http_hd` wrappers,
`cow_cookie:cookie/1`) and found no caller of any of them in application
code or in any other dependency; gateway login cookies go through
`Plug.Conn.put_resp_cookie`, which is the distinct response-cookie path.
That is reachability evidence for this source and configuration, not a
proof covering future plugins, dynamic code or operator changes.

The only production path that pulled Cowlib in was the unused full
Prometheus exporter (`telemetry_metrics_prometheus → plug_cowboy → cowboy →
cowlib`); the gateway already runs the core scraper under Bandit, so the
exporter was removed. The production dependency tree now excludes Plug
Cowboy, Cowboy, Cowboy Telemetry, Cowlib, and Ranch; test-server
dependencies still include them. The final image inventory must confirm
this boundary — a dependency tree is not a substitute for inspecting the
packaged release. See the [Cowlib advisory index](https://hex.pm/packages/cowlib/advisories).

## Verification status

The enterprise suite and the kernel suite pass with these locks, and enterprise compilation with warnings as errors passes; both are CI gates (`.gitlab-ci.yml`, `.github/workflows/ci.yml`).

`mix hex.audit` reported no retired packages, but that command checks Hex retirement metadata rather than this CVE inventory; it does not replace the advisory review above.
