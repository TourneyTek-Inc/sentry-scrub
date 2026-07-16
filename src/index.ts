export {
  createScrubber,
  redactString,
  scrubSentryEvent,
  defaultKeys,
  type KeyPatterns,
  type ScrubbableEvent,
  type ScrubOptions,
  type Scrubber,
} from './scrubber.js';

export {
  buildSweepRegex,
  defaultRules,
  keyValueRule,
  type SweepRule,
} from './rules.js';
