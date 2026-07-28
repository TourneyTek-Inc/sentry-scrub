# Changelog

All notable changes to this project are documented here. This project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## 1.0.0

Stable release. **No functional change from the previous version** — this
promotes the package out of `0.x` to declare the public API settled and
supported under Semantic Versioning.

The `0.x` range signalled that the API might still shift. It won't: this
package is consumed in production by the Poker Hawk platform and its surface
has been stable since extraction. Breaking changes from here require a major
bump.

### Changed

- Release workflow no longer sets `registry-url` on `actions/setup-node`,
  which was suppressing OIDC trusted publishing. Publishes again carry a
  provenance attestation.

## 0.1.0

Initial release. Extracted from the Poker Hawk platform, where it scrubs
Sentry events across web, mobile, desktop and TV surfaces.

### Added

- `scrubSentryEvent` — drop-in `beforeSend` scrubber: redacts messages,
  exceptions, breadcrumbs, headers, URLs and contexts; drops cookies and
  request bodies; narrows `user` to its id.
- `redactString` — single-pass sweep over free text.
- `createScrubber` — configurable key patterns, rules, depth and
  truncation limits.
- `keyValueRule` — build domain-specific `key=value` rules with loose key
  spelling and a minimum value length.
