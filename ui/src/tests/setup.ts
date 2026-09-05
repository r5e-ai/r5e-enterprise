// F004 — Vitest setup: jest-dom matchers + test-environment polyfills.
import "@testing-library/jest-dom/vitest";

if (typeof window !== "undefined") {
  let needsPolyfill = false;
  try {
    needsPolyfill = typeof window.localStorage?.clear !== "function";
  } catch {
    needsPolyfill = true;
  }

  if (needsPolyfill) {
    const store = new Map<string, string>();
    const storage: Storage = {
      get length() {
        return store.size;
      },
      clear() {
        store.clear();
      },
      getItem(key: string) {
        return store.get(key) ?? null;
      },
      key(index: number) {
        return Array.from(store.keys())[index] ?? null;
      },
      removeItem(key: string) {
        store.delete(key);
      },
      setItem(key: string, value: string) {
        store.set(key, value);
      },
    };

    Object.defineProperty(window, "localStorage", {
      configurable: true,
      value: storage,
    });
  }
}
