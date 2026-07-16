/**
 * PII/secret scrubbing for Sentry events.
 *
 * Redacts rather than hashes. A truncated hash of an email is
 * brute-forceable against a candidate list, and your error tracker is a
 * third party — so nothing reversible goes over the wire. Correlate users
 * via Sentry's own `setUser({ id })`, which is an explicit, auditable
 * choice, rather than as a side effect of whatever happened to land in a
 * string.
 *
 * Contract:
 *   - **Never throws.** A scrubber that throws inside `beforeSend` drops
 *     the event and blinds your triage — the exact failure it exists to
 *     prevent.
 *   - Redact on the KEY when the key names a secret, before ever looking
 *     at the value (an auth header's value is opaque bytes).
 *   - Then sweep the VALUE for anything that leaked in from a message or
 *     a stack string.
 */

import { buildSweepRegex, defaultRules, type SweepRule } from './rules.js';

/** Key-name patterns. Matched as substrings against the key. */
export interface KeyPatterns {
  /** Keys whose values are secrets outright — never send any form of them. */
  secret: RegExp;
  /** Keys carrying a user identifier — pseudonymous, but not yours to ship. */
  identifier: RegExp;
  /** Keys naming a shareable code. */
  code: RegExp;
  /** Keys naming an email address. */
  email: RegExp;
}

export const defaultKeys: KeyPatterns = {
  secret: /(?:token|secret|password|authorization|api[_-]?key|auth[_-]?token|signature|cookie)/i,
  identifier: /(?:\buid\b|user[_-]?id|account[_-]?id|customer[_-]?id|member[_-]?id)/i,
  code: /(?:invite|invite[_-]?code|access[_-]?code|referral[_-]?code)/i,
  email: /email/i,
};

export interface ScrubOptions {
  /**
   * Key-name patterns. Provide any subset; unspecified keys fall back to
   * {@link defaultKeys}.
   */
  keys?: Partial<KeyPatterns>;
  /**
   * Value-sweep rules, replacing {@link defaultRules} entirely. To extend
   * rather than replace, spread them: `rules: [...defaultRules, myRule]`.
   * Order is most-specific-first.
   */
  rules?: SweepRule[];
  /** Max object nesting before bailing out. @default 8 */
  maxDepth?: number;
  /** Max string length before truncation. @default 2000 */
  maxStringLength?: number;
  /**
   * Drop `request.data` wholesale instead of scrubbing it. Webhook routes
   * verify signatures against the RAW body, so those bodies are
   * attacker-visible signing payloads containing full customer objects —
   * and no scrubber can be trusted to catch every field of a provider
   * payload you don't control.
   * @default true
   */
  dropRequestBody?: boolean;
}

/**
 * Minimal structural view of the Sentry event fields this touches. Typed
 * locally rather than importing `@sentry/core`, so this stays usable from
 * every runtime without taking an SDK dependency (the Next, RN and
 * Electron SDKs ship different, incompatible copies of those types).
 *
 * NO index signatures here, deliberately. A type that HAS one can't
 * accept a type that lacks one, and Sentry's own `ErrorEvent` /
 * `RequestEventData` have none — adding `[k: string]: unknown` for
 * convenience makes every SDK event fail to typecheck against this.
 */
export interface ScrubbableEvent {
  message?: unknown;
  request?: {
    url?: unknown;
    headers?: unknown;
    cookies?: unknown;
    query_string?: unknown;
    data?: unknown;
  };
  exception?: { values?: Array<{ value?: unknown }> };
  breadcrumbs?: Array<{ message?: unknown; data?: unknown }>;
  extra?: unknown;
  contexts?: unknown;
  user?: Record<string, unknown>;
}

export interface Scrubber {
  /** Sweep a free-text string (a message, a stack frame, a URL) for leaks. */
  redactString: (value: string) => string;
  /** Scrub a Sentry event in place and return it. Safe for `beforeSend`. */
  scrubSentryEvent: <T extends ScrubbableEvent>(event: T) => T;
  /** Scrub an arbitrary value, using `key` as the first and strongest signal. */
  scrubValue: (value: unknown, key?: string) => unknown;
}

export function createScrubber(options: ScrubOptions = {}): Scrubber {
  const keys: KeyPatterns = { ...defaultKeys, ...options.keys };
  const rules = options.rules ?? defaultRules;
  const maxDepth = options.maxDepth ?? 8;
  const maxString = options.maxStringLength ?? 2000;
  const dropRequestBody = options.dropRequestBody ?? true;

  const sweepRe = buildSweepRegex(rules);
  const byName = new Map(rules.map((r) => [r.name, r]));

  /**
   * Redact FIRST, truncate second. The reverse order leaks: a secret
   * straddling the truncation boundary gets sliced into a fragment that
   * no longer matches its pattern and sails through. Truncating a
   * 1960-char string + a JWT left a real header and claims in the clear.
   */
  function redactString(value: string): string {
    // The regex is stateful (`g`); reset so a previous call can't cause
    // this one to start mid-string.
    sweepRe.lastIndex = 0;

    const swept = value.replace(sweepRe, (...args: unknown[]) => {
      const match = args[0] as string;
      const groups = args[args.length - 1] as Record<string, string | undefined> | undefined;
      if (!groups) return match;

      for (const [name, text] of Object.entries(groups)) {
        if (text === undefined) continue;
        const rule = byName.get(name);
        if (!rule) continue; // a `{name}Key` sub-group, not a rule itself
        return rule.replace(text, groups[`${name}Key`]);
      }
      return match;
    });

    return swept.length > maxString ? `${swept.slice(0, maxString)}…[truncated]` : swept;
  }

  function scrubValue(value: unknown, key = '', depth = 0): unknown {
    if (value === null || value === undefined) return value;
    if (depth > maxDepth) return '[depth-limit]';

    // Booleans carry no PII no matter what the key is called, and
    // redacting them destroys a debugging signal while implying an
    // address was scrubbed. `emailVerified: true` is not an email.
    if (typeof value === 'boolean') return value;

    if (keys.secret.test(key)) return '[redacted]';
    if (keys.identifier.test(key)) return '[user:redacted]';
    if (keys.code.test(key)) return '[code:redacted]';
    if (keys.email.test(key)) return '[email:redacted]';

    if (typeof value === 'string') return redactString(value);
    if (typeof value === 'number') return value;

    // `instanceof` alone is unreliable across realms (RN bridges,
    // Electron contexts, vm), so check the internal tag too — a missed
    // Error silently becomes `{}`.
    const tag = Object.prototype.toString.call(value);

    // Errors must be unwrapped explicitly: `message` and `stack` are
    // NON-ENUMERABLE, so the generic object branch below would run
    // Object.entries() over them, get [], and reduce the whole error to
    // `{}` — discarding the root cause the triage exists to surface.
    if (tag === '[object Error]' || value instanceof Error) {
      const err = value as Error;
      return {
        name: err.name,
        message: redactString(err.message ?? ''),
        stack: redactString(err.stack ?? ''),
      };
    }

    // Dates are likewise entry-less. toISOString() throws RangeError on
    // an invalid date, so guard rather than let beforeSend blow up.
    if (tag === '[object Date]') {
      const t = (value as Date).getTime();
      return Number.isNaN(t) ? '[invalid-date]' : (value as Date).toISOString();
    }

    if (Array.isArray(value)) {
      return value.map((item) => scrubValue(item, key, depth + 1));
    }

    if (typeof value === 'object') {
      const out: Record<string, unknown> = {};
      for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
        out[k] = scrubValue(v, k, depth + 1);
      }
      return out;
    }

    // Functions, symbols, bigints — not serializable telemetry.
    return undefined;
  }

  function scrubSentryEvent<T extends ScrubbableEvent>(event: T): T {
    if (typeof event.message === 'string') {
      event.message = redactString(event.message);
    }

    if (event.request) {
      const req = event.request;
      if (typeof req.url === 'string') req.url = redactString(req.url);
      if (typeof req.query_string === 'string') req.query_string = redactString(req.query_string);
      else if (req.query_string) req.query_string = scrubValue(req.query_string, 'query_string');
      if (req.headers) req.headers = scrubValue(req.headers, 'headers');
      if (req.cookies) req.cookies = '[redacted]';
      if ('data' in req && req.data !== undefined) {
        req.data = dropRequestBody ? '[body-dropped]' : scrubValue(req.data, 'data');
      }
    }

    if (event.exception?.values) {
      for (const ex of event.exception.values) {
        if (typeof ex.value === 'string') ex.value = redactString(ex.value);
      }
    }

    if (event.breadcrumbs) {
      for (const crumb of event.breadcrumbs) {
        if (typeof crumb.message === 'string') crumb.message = redactString(crumb.message);
        if (crumb.data) crumb.data = scrubValue(crumb.data, 'data');
      }
    }

    if (event.extra) event.extra = scrubValue(event.extra, 'extra');

    // Anything attached via Sentry.setContext(). The SDK's own auto
    // contexts (os/runtime/trace) pass through untouched — no key matches
    // and hex ids don't trip the sweep — but a hand-set context is
    // arbitrary app data and gets the same treatment as `extra`.
    if (event.contexts) event.contexts = scrubValue(event.contexts, 'contexts');

    // `user` is kept, but narrowed to the pseudonymous id you set on
    // purpose. Sentry auto-attaches ip_address/email when sendDefaultPii
    // is on; this is the backstop if that ever flips.
    if (event.user) {
      const id = event.user.id;
      event.user = typeof id === 'string' || typeof id === 'number' ? { id } : {};
    }

    return event;
  }

  return {
    redactString,
    scrubSentryEvent,
    scrubValue: (value: unknown, key = '') => scrubValue(value, key, 0),
  };
}

const defaultScrubber = createScrubber();

/** Sweep a free-text string using the default configuration. */
export const redactString = defaultScrubber.redactString;
/** Scrub a Sentry event using the default configuration. */
export const scrubSentryEvent = defaultScrubber.scrubSentryEvent;
