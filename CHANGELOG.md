# Changelog

All notable changes to this project are documented here. This project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
