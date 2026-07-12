/*!
 * highlight.js language definition for the Chai policy language (chai_dsl).
 *
 * Usage:
 *   import hljs from 'highlight.js/lib/core';
 *   import chai from './chai.js';
 *   hljs.registerLanguage('chai', chai);
 *   hljs.highlightAll();
 *
 * Then wrap a policy in <pre><code class="language-chai"> ... </code></pre>.
 */
export default function (hljs) {
  const ROOTS =
    'principal action resource subject object context args ' +
    'dlp_facts safety_facts grounding_facts schema_facts tooltrace risk_facts thresholds';

  return {
    name: 'Chai',
    case_insensitive: false,
    keywords: {
      keyword: 'permit forbid deny redact defer downgrade require_human ' +
        'when from to action any obligations mode',
      built_in: 'first_match deny_override ip decimal size len containsAll containsAny',
      operator: 'and or not in has contains like is',
      literal: 'true false',
      variable: ROOTS,
    },
    contains: [
      hljs.HASH_COMMENT_MODE,
      hljs.QUOTE_STRING_MODE,
      hljs.C_NUMBER_MODE,
      { className: 'meta', begin: /@[A-Za-z_]\w*/ },
      { className: 'type', begin: /\b[A-Za-z_]\w*(?:::[A-Za-z_]\w*)*::(?=")/ },
      { className: 'symbol', begin: /\?[A-Za-z_]\w*/ },
    ],
  };
}
