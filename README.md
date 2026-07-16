# @pokerhawk/sentry-scrub

[![CI](https://github.com/TourneyTek-Inc/sentry-scrub/actions/workflows/ci.yml/badge.svg)](https://github.com/TourneyTek-Inc/sentry-scrub/actions/workflows/ci.yml)
[![npm](https://img.shields.io/npm/v/@pokerhawk/sentry-scrub.svg)](https://www.npmjs.com/package/@pokerhawk/sentry-scrub)
[![types](https://img.shields.io/badge/types-included-3178C6.svg)](https://www.typescriptlang.org/)
[![license](https://img.shields.io/badge/license-MIT-blue.svg)](./LICENSE)

Strip PII and secrets out of Sentry events **before they leave the process**.

Zero dependencies. No Sentry SDK dependency — works with `@sentry/nextjs`, `@sentry/react-native`, `@sentry/electron`, `@sentry/node`, or anything else with a `beforeSend` hook.

```bash
npm install @pokerhawk/sentry-scrub
```

```ts
import * as Sentry from '@sentry/nextjs';
import { scrubSentryEvent } from '@pokerhawk/sentry-scrub';

Sentry.init({
  dsn: process.env.SENTRY_DSN,
  beforeSend(event) {
    try {
      return scrubSentryEvent(event);
    } catch {
      return null; // never let a scrubber failure ship an unscrubbed event
    }
  },
});
```

That's the whole integration. It redacts emails, JWTs, bearer tokens, provider API keys and webhook signing secrets out of messages, stack frames, URLs, breadcrumbs, headers and contexts; drops cookies and request bodies; and narrows `user` down to the id you set on purpose.

## Why not just hash the identifiers?

A common approach is to hash PII so the same user can still be correlated across events. This library **redacts instead**, deliberately.

A truncated hash of an email is brute-forceable against a candidate list — if you suspect an address is in your user base, you can confirm it with a single hash. Your error tracker is a third party, so nothing reversible goes over the wire. Correlate users with Sentry's own `setUser({ id })`, which is an explicit, auditable choice rather than a side effect of whatever happened to land in a string.

If you want hashing for *local* log files, that's a reasonable tradeoff — it just isn't this library's job.

## The design decisions that matter

**One regex, one pass — not a chain of `.replace()` calls.** Both alternatives are broken, and the tests here exist because both were shipped first:

1. *Sequential replaces rescan their own output.* `[token:redacted]` got re-matched by the `key=value` rule and mangled into `[token=[redacted]`.
2. *Neither ordering is safe.* Running `key=value` first turns `Authorization: Bearer abc123` into `Authorization=[redacted] abc123` — the value pattern stops at the space, so **the token itself survives**. Running the token patterns first hits problem 1.

A single pass consumes each match exactly once and never rescans, so rule order only decides which rule wins on overlap — never correctness.

**Redact first, truncate second.** The reverse order leaks. A secret straddling the truncation boundary gets sliced into a fragment that no longer matches its pattern and sails through in the clear. Truncating a 1960-character string followed by a JWT left a real, decodable header and claims in the payload.

**Redact on the key before looking at the value.** An auth header's value is opaque bytes — there is no pattern to match. If the key says `Authorization`, the value is gone regardless of what it looks like.

**Free text needs its own rules.** Key-based redaction only sees *structured* keys (`{ uid: '…' }`). A live probe against a real Sentry project caught `uid=FIREBASEUID12345` interpolated into an error message shipping in the clear — hence the `key=value` sweeps over message and stack strings too.

**Never throws.** A scrubber that throws inside `beforeSend` drops the event and blinds your triage — the exact failure it exists to prevent. Errors and Dates are unwrapped explicitly (their fields are non-enumerable, so the naive object walk reduces a whole `Error` to `{}`), invalid Dates are guarded, and depth is capped.

**Booleans are never redacted.** `/email/i` is a substring match, so `emailVerified: true` became `'[email:redacted]'` — destroying a debugging signal while implying an address had been scrubbed. A boolean carries no PII no matter what the key is called.

## Request bodies are dropped, not scrubbed

```ts
scrubSentryEvent({ request: { data: { customer: 'cus_123' } } });
// → request.data === '[body-dropped]'
```

Webhook routes verify signatures against the **raw** request body, so those bodies are attacker-visible signing payloads containing full customer objects. There is no scrubber worth trusting to catch every field of a provider payload you don't control. Opt out with `dropRequestBody: false` if your bodies are yours.

## Adding your own rules

The defaults are deliberately generic. Anything specific to your domain — a join code, a player id, an internal ticket format — is yours to add:

```ts
import { createScrubber, defaultRules, keyValueRule } from '@pokerhawk/sentry-scrub';

const scrubber = createScrubber({
  // Key patterns, matched against STRUCTURED object keys.
  keys: {
    identifier: /(?:\buid\b|player[_-]?id|host[_-]?uid)/i,
  },
  // Value patterns, swept through free text. Order is most-specific-first.
  rules: [
    ...defaultRules,
    keyValueRule({
      name: 'joinCodes',
      keys: ['join_code', 'tournament_code'],
      placeholder: '[code:redacted]',
      minValueLength: 4,
    }),
  ],
});

scrubber.redactString('join_code=9F2K1 expired');
// → 'join_code=[code:redacted] expired'
```

`keyValueRule` matches key spellings loosely — `api_key`, `api-key`, `api key` and `apikey` all hit. `minValueLength` guards against shredding ordinary prose: `uid=abc` is left alone because a three-character value isn't an identifier.

Rules are combined with **named** capture groups, so adding one can't silently shift another rule's arguments. Invalid or duplicate rule names throw at construction rather than producing a quietly broken regex.

## What's redacted by default

| Input | Output |
| --- | --- |
| `someone@example.com` | `[email:redacted]` |
| `eyJhbGci….eyJzdWIi….SflKxw…` (JWT) | `[token:redacted]` |
| `Bearer abc123.def-456` | `Bearer [token:redacted]` |
| `sk_live_…`, `pk_…`, `rk_…`, `whsec_…` | `[key:redacted]` |
| `auth_token=abc123xyz` | `auth_token=[redacted]` |
| `uid=FIREBASEUID12345` | `uid=[user:redacted]` |
| `invite_code=AB12CD` | `invite_code=[code:redacted]` |

Structured keys matching `token`, `secret`, `password`, `authorization`, `api_key`, `signature` or `cookie` are redacted by key. Identifier keys (`uid`, `user_id`, `account_id`, `customer_id`, `member_id`) become `[user:redacted]`; `email` keys become `[email:redacted]`.

## API

| Export | Purpose |
| --- | --- |
| `scrubSentryEvent(event)` | Scrub an event in place with the defaults. Drop-in for `beforeSend`. |
| `redactString(text)` | Sweep a single string. |
| `createScrubber(options)` | Build a configured scrubber — `{ redactString, scrubSentryEvent, scrubValue }`. |
| `keyValueRule(config)` | Build a `key=value` sweep rule. |
| `defaultRules`, `defaultKeys` | The built-in rule set and key patterns, for composing. |

Options: `keys`, `rules`, `maxDepth` (default 8), `maxStringLength` (default 2000), `dropRequestBody` (default true).

## Caveats

This is defense in depth, not a compliance guarantee. It catches the shapes it knows about — it cannot know that `{ note: 'call Bob on 555-0123' }` is personal data. Keep `sendDefaultPii` off, keep secrets out of error messages, and treat this as the backstop rather than the strategy.

## License

MIT © [TourneyTek, Inc.](https://www.pokerhawk.io)
