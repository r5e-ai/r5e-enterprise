# Reporting a vulnerability

Report privately, as a **confidential issue** on the canonical project:
<https://gitlab.com/r5e-group/r5e-enterprise/-/issues/new> with the
*This issue is confidential* box ticked. Do not open a public issue, and do
not open a merge request that contains the exploit. If you cannot use GitLab,
email <thomas@runr5e.ai> instead.

Include, as far as you have it: the commit or release the finding is against,
the configuration it needs, the steps that reproduce it, and what an attacker
gets. A proof-of-concept against your own deployment is worth more than a
description.

The steward acknowledges a report within 5 working days. That is the
intention, not a contractual term; there is no support agreement behind it
and there is no bounty programme.

Supported for fixes: the tip of the default branch. There is no maintained
release branch yet; when there is, this file will name it.

Public disclosure is coordinated with the reporter. The finding, the fix and
the date are recorded in the repository afterwards.
