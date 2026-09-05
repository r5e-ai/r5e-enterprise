# License

Copyright (c) 2026 r5e Inc.

r5e-enterprise is licensed `AGPL-3.0-only`: the GNU Affero General Public
License, version 3, whose full text is in [LICENSE](LICENSE). Not "or any
later version" — a later AGPL covers this code only when the copyright
holder says so.

The asymmetry is the design (ADR-0004). The protocol surface in r5e-core —
the charter, the specs, the conformance kit and the reference verifier — is
Apache-2.0, so a second implementation can be written, run and sold without
asking. This repository is the reference deployment, and it is AGPL.

Two directories inside this repository carry a different license, stated in
a `LICENSE` file beside them:

| Path | License | Why |
|---|---|---|
| `policy-starter/` | MIT-0 | Its first instruction is to copy it into a repository of your own. |
| `specs/010-gateway-api-group/kinds/` | Apache-2.0 | Machine-readable protocol surface: the shape a second implementation must match. |

Third-party components and their licenses are listed in
[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
