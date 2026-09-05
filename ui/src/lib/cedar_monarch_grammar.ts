// Monaco/Monarch language definition for Cedar policy syntax (T093 — Phase 5
// US3).
//
// Per `contracts/frontend_architecture.md` §"Folder layout" + research D1 +
// the prompt brief: the Phase-1 MVP only needs a *basic* Cedar tokenizer —
// keywords, identifiers, strings, comments, and operators — so the editor is
// readable. Full Cedar syntax-grammar fidelity (entity-UID parsing, namespace
// scoping, set/record literals) is reserved for a future polish task.
//
// Spec reference: https://docs.cedarpolicy.com/policies/syntax-grammar.html
//
// This module is framework-free: it returns plain JSON suitable for handing to
// Monaco's `monaco.languages.setMonarchTokensProvider(...)`. The CedarEditor
// component registers it lazily when Monaco mounts (so we don't pull Monaco
// into the main bundle).
//
// We deliberately avoid importing `monaco-editor` here. Typing each export as
// `unknown` keeps the bundle small and lets the consumer cast at the
// registration site (`monaco.languages.setMonarchTokensProvider("cedar", ...)`)
// where Monaco's types are already in scope.

/** Language ID used in `setMonarchTokensProvider("cedar", ...)`. */
export const CEDAR_LANGUAGE_ID = "cedar" as const;

/** Cedar reserved keywords (per the syntax grammar). */
export const CEDAR_KEYWORDS = [
  "permit",
  "forbid",
  "when",
  "unless",
  "principal",
  "action",
  "resource",
  "context",
  "true",
  "false",
  "if",
  "then",
  "else",
] as const;

/** Cedar binary/unary operators that we want highlighted as `operator`. */
export const CEDAR_OPERATORS = [
  "==",
  "!=",
  "<=",
  ">=",
  "<",
  ">",
  "&&",
  "||",
  "!",
  "+",
  "-",
  "*",
  "/",
  "%",
  "::",
] as const;

/** Reserved word-style operators (`like`, `in`, `has`). */
export const CEDAR_WORD_OPERATORS = ["like", "in", "has"] as const;

/**
 * Monarch language definition. Cast to `monaco.languages.IMonarchLanguage` at
 * the registration site; we leave the type loose here so Monaco doesn't have
 * to be imported eagerly.
 */
export const cedarMonarchLanguage = {
  defaultToken: "",
  tokenPostfix: ".cedar",

  keywords: CEDAR_KEYWORDS,
  wordOperators: CEDAR_WORD_OPERATORS,
  operators: CEDAR_OPERATORS,

  symbols: /[=><!~?:&|+\-*/^%]+/,

  tokenizer: {
    root: [
      // Identifiers + keywords + word-operators.
      [
        /[a-zA-Z_][a-zA-Z0-9_]*/,
        {
          cases: {
            "@keywords": "keyword",
            "@wordOperators": "operator",
            "@default": "identifier",
          },
        },
      ],

      // Whitespace
      { include: "@whitespace" },

      // Strings — Cedar string literals are double-quoted.
      [/"([^"\\]|\\.)*$/, "string.invalid"],
      [/"/, { token: "string.quote", bracket: "@open", next: "@string" }],

      // Numbers (decimal only — Cedar has no float literals in F004 scope).
      [/\d+/, "number"],

      // Punctuation
      [/[{}()[\]]/, "@brackets"],
      [/[,;.]/, "delimiter"],

      // Operators
      [
        /@symbols/,
        {
          cases: {
            "@operators": "operator",
            "@default": "",
          },
        },
      ],
    ],

    string: [
      [/[^\\"]+/, "string"],
      [/\\./, "string.escape.invalid"],
      [/"/, { token: "string.quote", bracket: "@close", next: "@pop" }],
    ],

    whitespace: [
      [/[ \t\r\n]+/, ""],
      [/\/\*/, "comment", "@comment"],
      [/\/\/.*$/, "comment"],
    ],

    comment: [
      [/[^/*]+/, "comment"],
      [/\*\//, "comment", "@pop"],
      [/[/*]/, "comment"],
    ],
  },
};

/**
 * Sensible defaults for `monaco.languages.setLanguageConfiguration("cedar", ...)`.
 * Sets bracket pairs + comment toggles so Cmd-/ works in the editor.
 */
export const cedarLanguageConfiguration = {
  comments: {
    lineComment: "//",
    blockComment: ["/*", "*/"] as [string, string],
  },
  brackets: [
    ["{", "}"],
    ["[", "]"],
    ["(", ")"],
  ] as Array<[string, string]>,
  autoClosingPairs: [
    { open: "{", close: "}" },
    { open: "[", close: "]" },
    { open: "(", close: ")" },
    { open: '"', close: '"' },
  ],
  surroundingPairs: [
    { open: "{", close: "}" },
    { open: "[", close: "]" },
    { open: "(", close: ")" },
    { open: '"', close: '"' },
  ],
};
