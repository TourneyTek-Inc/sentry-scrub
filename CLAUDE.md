# Claude Code Instructions — @tourneytek/sentry-scrub

Redacts PII and secrets from Sentry events before they leave the process.
Zero dependencies, no Sentry SDK dependency, ESM + CJS + types.

## How this repo relates to Poker Hawk

This code was extracted FROM the private `TourneyTek-Inc/pokerhawk-monorepo`,
which consumes it from npm like any third-party dependency. **This repo is the
source of truth.** The monorepo keeps only a thin re-export shim at the old
import path — there is no copy of this logic there to edit, and no sync of any
kind between them.

## Releasing — never `npm publish` by hand

```bash
npm version <patch|minor|major>   # updates package.json + tags
git push --follow-tags            # the tag triggers .github/workflows/release.yml
```

The workflow publishes over **OIDC trusted publishing**: no token, no 2FA
prompt, and npm attaches a provenance attestation proving the tarball was built
by that workflow from that commit. A manual `npm publish` gets NO provenance,
and will fail anyway — npm now hard-requires 2FA to publish.

`release.yml` refuses to publish if the git tag and `package.json` disagree.
That guard matters: **a published npm version is immutable.** You cannot
overwrite or re-use it, only deprecate it and burn the number.

## Publishing does NOT update Poker Hawk

The monorepo pins an exact version in its lockfile, so a release here reaches
nothing until someone bumps it there. That gap is deliberate — it stops an
upstream change silently altering a live tournament app. After publishing:

1. bump the version in the monorepo's `package.json` (see its `CLAUDE.md`)
2. `pnpm install`
3. the monorepo's `pnpm check:oss-drift` / `/cut-release` will otherwise flag it

## Rules

- **No `Co-Authored-By: Claude` lines in commit messages.**
- **Keep the dependency count at zero.** It is a headline feature of these
  packages and the reason they are safe to drop into any runtime. Do not add a
  runtime dependency without a very good reason; devDependencies are fine.
- **Public API changes are breaking.** Pre-1.0, breaking changes go in a MINOR
  bump. Update `CHANGELOG.md` in the same commit.
- **Nothing Poker Hawk-specific belongs here.** No pricing, no entitlements, no
  product schema, no customer data. If a stranger building tournament software
  wouldn't want it, it goes in the monorepo instead.
- Every exported symbol needs a test. `npm test` must be green before you tag.

## Traps specific to this package

**NEVER refactor the single-pass regex into a chain of `.replace()` calls.**
Both obvious alternatives are broken, and the tests exist because both shipped:

1. Sequential replaces rescan their own output — `[token:redacted]` got
   re-matched by the key=value rule and mangled into `[token=[redacted]`.
2. Neither ordering is safe. key=value first turns `Authorization: Bearer abc`
   into `Authorization=[redacted] abc` — the value pattern stops at the space,
   so **the token survives**. Token-patterns first hits problem 1.

One pass consumes each match exactly once and never rescans, so rule order only
decides overlap winners, never correctness.

**Redact FIRST, truncate second.** The reverse leaks: a secret straddling the
truncation boundary is sliced into a fragment that no longer matches its
pattern and ships in the clear.

**Redact, do not hash.** A truncated hash of an email is brute-forceable against
a candidate list, and the error tracker is a third party. (Poker Hawk's desktop
MAIN process hashes for LOCAL log files — different threat model, don't copy it.)

**It must never throw.** A scrubber that throws inside `beforeSend` drops the
event and blinds the triage — the exact failure it exists to prevent.

**Booleans are never redacted** regardless of key name. `emailVerified: true`
is not an email; redacting it destroys a debug signal and implies an address was
scrubbed.

**Defaults stay GENERIC.** Domain-specific shapes (Poker Hawk's `join_code`,
`player_id`, `host_uid`, `tournament_code`) do NOT belong in `defaultRules`
— they are configured by the consumer via `createScrubber({ keys, rules })`.
Poker Hawk does this in `packages/core/src/observability/scrub.ts`. A new
Poker Hawk key shape goes THERE, not here.

**Rules use NAMED capture groups.** The positional version worked but each
rule's group index depended on how many groups earlier rules declared, so
adding one silently shifted another's arguments. Keep it named.
