# Security Policy

## Reporting a vulnerability

**Please report privately, not as a public issue.**

Use GitHub's private vulnerability reporting:
[**Report a vulnerability**](https://github.com/richlegrand/bitbang-server/security/advisories/new).
It is private to the maintainers, and it gives us a place to develop and review a fix with
you before anything is public.

If you cannot use GitHub, email **security@bitba.ng**.

Useful to include, though a partial report is far better than none:

- What an attacker gains, and what they need to already have
- Affected version or commit, or the date you fetched a served asset such as
  `bootstrap.js` or `sw.js`
- Steps to reproduce, or a proof of concept
- Any suggested fix

## What to expect

BitBang is maintained by a very small team, so an honest statement rather than a service
level agreement: we aim to acknowledge a report within a few days and to keep you updated
as we work through it. Complex issues take longer, and we will say so rather than go quiet.

We are glad to coordinate disclosure, agree an embargo date, and credit you in the
advisory. If you would rather not be credited, say so.

## Scope

This repository is the signaling server and the browser runtime it serves. Two properties
matter most here.

The server brokers connections **without being able to read them or insert itself into
them**. Anything that gives the server, or someone who has breached it, the ability to read
session traffic, impersonate a device, or defeat the endpoint key verification is a serious
finding.

The browser runtime is **served code**, which makes its integrity and its origin boundary
critical. The installed clients run no served code and therefore have a stronger guarantee;
that distinction is documented in the
[security claims](https://github.com/richlegrand/bitbang) writeup.

**In scope**

- Any path by which the server, a relay, or a network attacker can read, modify, or inject
  into session traffic
- Defeating the verification that prevents a man-in-the-middle, or impersonating a device
- Disclosure of an access code or PIN, including through browser storage, the Cache API,
  the URL fragment, logs, or referrer headers
- Cross-site scripting, or any way for content in a device frame or a proxied application
  to reach the parent page's origin, storage, or credentials
- Content injection into served runtime assets, or anything weakening their integrity in
  delivery
- Session fixation, session confusion between users, or one session reaching another's data
- Authentication or authorization flaws in the server's own APIs
- Resource exhaustion where a bounded input causes unbounded allocation or work

**Out of scope**

- The server observing connection metadata such as timing, size, or which identifiers are
  connecting. This is a documented property of the design, not a defect.
- Anyone holding a valid access link having the access that link grants. Links are
  capabilities. Ways to obtain a link you were never given are in scope.
- The operator being able to serve different browser code. This is the known and documented
  limit of the browser tier, and the reason the installed clients exist. A way for someone
  *other* than the operator to affect served code is very much in scope.
- Volumetric denial of service. Bugs where a small input causes disproportionate resource
  use are in scope, as above.
- Missing hardening headers or similar findings with no demonstrated impact
- Automated scanner output with no working proof of concept

For issues in the command-line client or the device-side listener, please report against
[bitbang-cli](https://github.com/richlegrand/bitbang-cli) instead.

## Supported versions

BitBang is pre-1.0 and moves quickly. Fixes land on `main` and are deployed to the hosted
service; there is no supported older deployment. Please confirm against current production
or current `main` before reporting.

## Safe harbor

We will not pursue or support legal action against anyone who makes a good-faith effort to
follow this policy: research on your own devices and accounts, no access to or modification
of other people's data, no degradation of service for others, and a reasonable window to
fix before public disclosure. If you are unsure whether something is in bounds, ask first.

Please do not test against the hosted service in ways that affect other users. Running your
own server, or testing against your own sessions, is always in bounds.
