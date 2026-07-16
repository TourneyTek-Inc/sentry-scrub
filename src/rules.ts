/**
 * Value-level sweep rules.
 *
 * Every rule is compiled into ONE combined regex applied in a SINGLE
 * pass — never a chain of `.replace()` calls. Two reasons, both of which
 * were found the hard way:
 *
 *   1. Sequential replaces rescan their own output. `[token:redacted]`
 *      got re-matched by the key=value rule and mangled into
 *      `[token=[redacted]`.
 *   2. Neither ordering is safe. Running key=value first turns
 *      `Authorization: Bearer abc123` into `Authorization=[redacted]
 *      abc123` — the value pattern stops at the space, so the token
 *      itself survives. Running the token patterns first hits problem 1.
 *
 * A single pass consumes each match exactly once and never rescans, so
 * rule order only decides which rule wins on overlap, never correctness.
 * Order is most-specific-first: the key=value branches lead because they
 * must swallow an optional `Bearer ` prefix along with the value.
 *
 * Rules are combined with NAMED capture groups rather than positional
 * ones. The positional version worked, but the group index of each rule
 * depended on how many groups every earlier rule declared — so adding a
 * rule silently shifted the callback's arguments. Named groups make a
 * user-supplied rule impossible to get wrong that way.
 */

export interface SweepRule {
  /**
   * Unique identifier, and the capture-group name. Must be a valid JS
   * identifier: letters and digits only, starting with a letter.
   */
  name: string;
  /**
   * Regex source. Use `(?<{name}Key>…)` for the key portion of a
   * key=value rule and it will be passed to `replace` — see
   * {@link keyValueRule}, which builds this for you.
   *
   * Prefer non-capturing groups `(?:…)` for everything else.
   */
  pattern: string;
  /** Returns the replacement text. `key` is the `{name}Key` group, if any. */
  replace: (match: string, key?: string) => string;
}

/** Escape a literal for embedding in a regex. */
const escape = (literal: string) => literal.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

/**
 * Build a `key=value` / `key: value` rule from a list of key names.
 *
 * Key names may contain `_`, which is matched loosely — `api_key`,
 * `api-key`, `api key` and `apikey` all hit.
 */
export function keyValueRule(config: {
  name: string;
  /** Key names to match, e.g. `['user_id', 'uid']`. */
  keys: string[];
  /** Placeholder to emit, e.g. `'[user:redacted]'`. */
  placeholder: string;
  /**
   * Minimum value length to treat as sensitive. Guards against shredding
   * ordinary prose — `uid=abc` is not an identifier.
   * @default 8
   */
  minValueLength?: number;
  /**
   * Value character class. Defaults to identifier-ish characters. Secret
   * rules want something greedier.
   * @default '[A-Za-z0-9_-]'
   */
  valueChars?: string;
}): SweepRule {
  const { name, keys, placeholder, minValueLength = 8, valueChars = '[A-Za-z0-9_-]' } = config;
  const keyAlternation = keys
    .map((k) => escape(k).replace(/_/g, '[_\\s-]?'))
    .sort((a, b) => b.length - a.length) // longest first so `user_id` beats `id`
    .join('|');

  return {
    name,
    pattern: String.raw`\b(?<${name}Key>${keyAlternation})\s*[:=]\s*${valueChars}{${minValueLength},}`,
    replace: (_match, key) => `${key}=${placeholder}`,
  };
}

/**
 * The default sweep rules — deliberately generic. Anything specific to
 * your domain (a join code, a player id, an internal ticket format)
 * belongs in `rules` at construction time; see {@link keyValueRule}.
 */
export const defaultRules: SweepRule[] = [
  // Secret key=value, including a `Bearer `-prefixed value. The value
  // class is greedy — secrets are opaque bytes and may contain anything
  // that isn't a delimiter.
  {
    name: 'secretKeyValue',
    pattern: String.raw`\b(?<secretKeyValueKey>token|access[_\s-]?token|auth[_\s-]?token|authorization|api[_\s-]?key|password|secret)\s*[:=]\s*(?:Bearer\s+)?[^\s,;&"']+`,
    replace: (_m, key) => `${key}=[redacted]`,
  },

  // Identifier key=value. Key-based redaction only sees STRUCTURED keys
  // (`{uid: '…'}`) — an identifier interpolated into a message string
  // needs this free-text rule. A live probe caught exactly that:
  // `uid=FIREBASEUID12345` inside an error message shipped in the clear.
  keyValueRule({
    name: 'identifierKeyValue',
    keys: ['uid', 'user_id', 'account_id', 'customer_id', 'member_id'],
    placeholder: '[user:redacted]',
    minValueLength: 8,
  }),

  // Shareable codes — low sensitivity, but still user data.
  keyValueRule({
    name: 'codeKeyValue',
    keys: ['invite_code', 'access_code', 'referral_code'],
    placeholder: '[code:redacted]',
    minValueLength: 4,
  }),

  {
    name: 'email',
    pattern: String.raw`\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b`,
    replace: () => '[email:redacted]',
  },

  {
    name: 'jwt',
    pattern: String.raw`\beyJ[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}\b`,
    replace: () => '[token:redacted]',
  },

  {
    name: 'bearerToken',
    pattern: String.raw`\bBearer\s+[A-Za-z0-9\-._~+/]+=*\b`,
    replace: () => 'Bearer [token:redacted]',
  },

  // Stripe-style publishable/secret/restricted keys and webhook signing
  // secrets. Several providers copy this prefix convention.
  {
    name: 'providerKey',
    pattern: String.raw`\b(?:sk|rk|pk|whsec)_[A-Za-z0-9_]{8,}\b`,
    replace: () => '[key:redacted]',
  },
];

const VALID_NAME = /^[A-Za-z][A-Za-z0-9]*$/;

/** Compile rules into one case-insensitive, global, single-pass regex. */
export function buildSweepRegex(rules: SweepRule[]): RegExp {
  const seen = new Set<string>();
  for (const rule of rules) {
    if (!VALID_NAME.test(rule.name)) {
      throw new Error(
        `Invalid sweep rule name "${rule.name}": must be a valid capture-group name ` +
          `(letters and digits, starting with a letter).`,
      );
    }
    if (seen.has(rule.name)) {
      throw new Error(`Duplicate sweep rule name "${rule.name}": names must be unique.`);
    }
    seen.add(rule.name);
  }

  return new RegExp(rules.map((r) => `(?<${r.name}>${r.pattern})`).join('|'), 'gi');
}
