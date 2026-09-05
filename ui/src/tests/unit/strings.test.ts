// Vitest unit tests for `~/lib/strings` — slug() + truncate().
//
// These helpers were extracted per Constitution Principle VII after the
// MR !93 fix-pass-2 GAN review flagged inline duplications. The tests pin
// the behavior of all three pre-extraction call sites so any future
// regression on consumers (Sidebar / ChatThread suggestion cards / ChatPage
// history dropdown / TagsSection chips) gets caught here.

import { describe, expect, it } from "vitest";

import { slug, truncate } from "~/lib/strings";

describe("slug()", () => {
  it("lowercases, replaces non-alphanumerics with '-', strips leading/trailing '-'", () => {
    expect(slug("Why was Alice's last bash_exec denied?")).toBe(
      "why-was-alice-s-last-bash-exec-denied",
    );
  });

  it("collapses runs of non-alphanumerics to a single '-'", () => {
    expect(slug("Foo!!! Bar??? Baz")).toBe("foo-bar-baz");
  });

  it("returns an empty string for all-non-alphanumeric input", () => {
    expect(slug("???!!!")).toBe("");
  });

  it("is un-capped by default (mirrors Sidebar behavior)", () => {
    const longLabel = "a".repeat(80);
    expect(slug(longLabel)).toBe(longLabel);
  });

  it("caps at maxLength when provided (mirrors ChatThread behavior)", () => {
    const long = "Why was Alice's last bash_exec denied yesterday afternoon?";
    // Pre-cap slug = "why-was-alice-s-last-bash-exec-denied-yesterday-afternoon"
    // Slice to 40 → "why-was-alice-s-last-bash-exec-denied-ye"
    expect(slug(long, 40)).toBe("why-was-alice-s-last-bash-exec-denied-ye");
  });

  it("trims a trailing '-' that lands at the cap boundary", () => {
    // The pre-cap output is "show-me-all-denials-in-the-last-hour" (36 chars),
    // so slicing to 20 mid-run gives "show-me-all-denials-" (trailing dash).
    expect(slug("Show me all denials in the last hour.", 20)).toBe(
      "show-me-all-denials",
    );
  });
});

describe("truncate()", () => {
  it("returns the input unchanged when shorter than max", () => {
    expect(truncate("short", 10)).toBe("short");
  });

  it("returns the input unchanged when exactly max", () => {
    expect(truncate("12345", 5)).toBe("12345");
  });

  it("truncates with an ellipsis when over max", () => {
    expect(truncate("hello world", 5)).toBe("hell…");
  });

  it("trims trailing whitespace before the ellipsis", () => {
    expect(truncate("hello world", 7)).toBe("hello…");
  });

  it("uses a default max of 60 (mirrors ChatPage history-row behavior)", () => {
    const text = "Why was Alice's";
    expect(truncate(text)).toBe(text);
  });

  it("works against the TagsSection chip width (max ≈ 40)", () => {
    const value = "policy.simulator.suggestions.live_tail.tag";
    expect(truncate(value, 20)).toBe("policy.simulator.su…");
  });
});
