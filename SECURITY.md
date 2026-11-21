# Security policy

## Report a vulnerability privately

Use GitHub's private report form:
<https://github.com/oneshot2001/onvif-mcp/security/advisories/new>. Please don't open a
public issue, pull request, or discussion about a security problem.

If the form isn't available to you, open a public issue that says only that you need a
private contact, with no details about the problem, and the maintainer will reach out.

Include what you found, the steps to reproduce it, and the commit you tested. Use test keys
and synthetic data in anything you attach. Leave out real signing keys, credentials, and
live camera images or data.

## Scope

The code in this repository: the MCP server, its policy checks, rate limits, receipts, and
commissioning tools. A way to get an agent past the policy is exactly what we want to hear
about, for example:

- a `ptz_move` accepted even though its pan, tilt, or zoom exceeds the agent's configured
  per-call limit
- a call the policy should deny that goes through anyway
- a denial that can be worked around
- a forged receipt, or a change to signed receipt content, that still verifies under the
  original public key without its signing key

## Rules for testing

This invitation covers the repository code. It doesn't authorize testing any live device,
service, or network.

- The test suite (`bun test`) runs without any camera. Start there.
- `cameras.json` ships with the maintainer's private lab addresses. Replace it with your own
  inventory before you start the server, or it will try to reach whatever answers at those
  addresses on your network.
- Test live only against cameras and systems you own, or whose owner has authorized the
  specific tests.
- Don't test against the maintainer's lab, cameras, or network.
- Resource-exhaustion testing is fine in an isolated environment you control. No
  denial-of-service against shared or third-party systems, and no social engineering.

## What to expect

One person maintains this project, so there are no guaranteed response or fix times. Each
confirmed report is assessed on its own, and fixes, mitigations, and disclosure timing are
worked out privately with the reporter.

There's no bug bounty. If an advisory is published and you want credit, you'll be credited.
