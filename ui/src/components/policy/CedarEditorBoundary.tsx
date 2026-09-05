// CedarEditorBoundary — defense-in-depth fallback when Monaco fails to
// initialize (issue #61 follow-up).
//
// Background: Monaco's AMD bundle is shipped same-origin under
// /admin/vs/* (see ui/src/lib/configureMonacoLoader.ts and the
// `pnpm copy:monaco` build step). When that path is wired correctly,
// the editor renders instantly. When it is NOT — eg the Plug.Static
// `:only` allowlist regression that produced issue #61, a CSP bump
// that newly blocks the WebWorker bootstrap, or a bundle-hash mismatch
// after a rolling deploy — `@monaco-editor/loader`'s `init()` Promise
// rejects (or, worse, hangs forever).
//
// Without this boundary, the user sees the SPA's `<EditorSkeleton />`
// pulse forever and has no way to recover except a full page reload —
// the exact symptom users hit on audit-dev when this trapdoor reopens.
//
// With this boundary in place, two failure modes are handled:
//
//   1. **Synchronous render error from MonacoEditor.** Caught by the
//      class-component error boundary's `componentDidCatch` /
//      `getDerivedStateFromError`. The user sees a card with the
//      error text and a "Use plain-text editor" button that swaps in
//      a `<textarea>` with the same `value` / `onChange` contract.
//
//   2. **Loader timeout.** Monaco does not throw if the AMD bootstrap
//      never resolves; it just stays in its "Loading..." state forever.
//      We surface a SECOND escape hatch — a 10-second timeout that
//      flips into the same fallback state. The timeout is generous
//      (Monaco normally renders <500ms even on a cold cache); only
//      fires when something is truly wrong.
//
// The fallback `<textarea>` is intentionally minimal: it wires `value`
// and `onChange` so the parent's save / validate logic continues to
// work; it has no syntax highlighting and no inline parse-error
// markers. The user can keep authoring policy and re-load the page
// after deploy to recover the rich editor.
//
// **Why a class component and not a hook?** React's error boundary
// API is class-only. There is no `useErrorBoundary` in stable React
// 18. We keep the class component small and locally-scoped so the
// rest of the codebase stays functional-only.

import {
  Component,
  type ErrorInfo,
  type ReactNode,
  useEffect,
  useState,
} from "react";

interface BoundaryProps {
  /** Current Cedar source — passed through to the fallback `<textarea>`. */
  value: string;
  /** Change handler — passed through to the fallback `<textarea>`. */
  onChange: (next: string) => void;
  /**
   * Children must be the wrapped `<CedarEditor />` (or a `<Suspense>`
   * containing it). The boundary catches errors thrown during render
   * and surfaces a textarea fallback in their place.
   */
  children: ReactNode;
  /**
   * Timeout (ms) after which we assume Monaco failed to initialize even
   * though no error was thrown — defaults to 10s. Tests pass a much
   * smaller value (e.g. 50ms) to assert the timeout-driven fallback
   * without slow tests.
   */
  loaderTimeoutMs?: number;
  /**
   * Test seam: when true, skip the timeout-driven fallback path so a
   * test that exercises ONLY the throw-driven path can hold the
   * timeout open without flake. Defaults to false.
   */
  disableTimeout?: boolean;
  /**
   * Test seam: when true, treat the timeout as having ALREADY fired
   * (skipping the wall-clock wait entirely). Used by the unit test
   * to assert the timeout-driven fallback renders the textarea.
   */
  forceTimeout?: boolean;
}

interface BoundaryState {
  failed: boolean;
  errorMessage: string | null;
}

/**
 * Outer class component — catches synchronous render errors thrown by
 * children and flips into fallback mode.
 */
export default class CedarEditorBoundary extends Component<
  BoundaryProps,
  BoundaryState
> {
  state: BoundaryState = {
    failed: false,
    errorMessage: null,
  };

  static getDerivedStateFromError(error: Error): BoundaryState {
    return {
      failed: true,
      errorMessage: error.message ?? String(error),
    };
  }

  componentDidCatch(error: Error, info: ErrorInfo): void {
    // Surface to console so a developer can grep — production users
    // see the fallback UI; production telemetry is out of scope here.
    console.error(
      "[CedarEditorBoundary] Monaco initialization failed:",
      error,
      info.componentStack,
    );
  }

  reset = (): void => {
    this.setState({ failed: false, errorMessage: null });
  };

  render(): ReactNode {
    const { value, onChange, children, loaderTimeoutMs, disableTimeout, forceTimeout } =
      this.props;

    if (this.state.failed) {
      return (
        <CedarEditorFallback
          value={value}
          onChange={onChange}
          errorMessage={this.state.errorMessage}
          onRetry={this.reset}
        />
      );
    }

    // Inner functional component watches the timeout. We render it
    // alongside `children` so the timeout fires regardless of whether
    // children throw — but only the timeout's failure path renders.
    return (
      <CedarEditorTimeoutGuard
        loaderTimeoutMs={loaderTimeoutMs}
        disableTimeout={disableTimeout}
        forceTimeout={forceTimeout}
        value={value}
        onChange={onChange}
      >
        {children}
      </CedarEditorTimeoutGuard>
    );
  }
}

// ----------------------------------------------------------------------------
// Inner timeout guard — separate component so it can use hooks.
// ----------------------------------------------------------------------------

interface TimeoutGuardProps {
  value: string;
  onChange: (next: string) => void;
  children: ReactNode;
  loaderTimeoutMs?: number;
  disableTimeout?: boolean;
  forceTimeout?: boolean;
}

function CedarEditorTimeoutGuard({
  value,
  onChange,
  children,
  loaderTimeoutMs = 10_000,
  disableTimeout = false,
  forceTimeout = false,
}: TimeoutGuardProps): ReactNode {
  // The timeout's only purpose is to detect Monaco's "loader hangs
  // forever" failure mode. CedarEditor signals success by dispatching
  // a one-shot 'cedar-editor-mounted' event on `window` from its
  // `onMount` callback. That signal cancels the timeout.
  const [timedOut, setTimedOut] = useState<boolean>(false);

  useEffect(() => {
    if (disableTimeout) return;
    if (forceTimeout) {
      setTimedOut(true);
      return;
    }

    let cancelled = false;
    const handle = window.setTimeout(() => {
      if (!cancelled) setTimedOut(true);
    }, loaderTimeoutMs);

    function onMount(): void {
      cancelled = true;
      window.clearTimeout(handle);
    }

    window.addEventListener("cedar-editor-mounted", onMount, { once: true });

    return () => {
      cancelled = true;
      window.clearTimeout(handle);
      window.removeEventListener("cedar-editor-mounted", onMount);
    };
  }, [loaderTimeoutMs, disableTimeout, forceTimeout]);

  if (timedOut) {
    return (
      <CedarEditorFallback
        value={value}
        onChange={onChange}
        errorMessage={
          "The Cedar editor did not finish loading within " +
          `${Math.round(loaderTimeoutMs / 1000)}s. ` +
          "This usually means a static asset failed to load — " +
          "check the browser console for a 404 on /admin/vs/loader.js."
        }
        onRetry={() => setTimedOut(false)}
      />
    );
  }

  return <>{children}</>;
}

// ----------------------------------------------------------------------------
// Fallback UI — minimal textarea + retry button.
// ----------------------------------------------------------------------------

interface FallbackProps {
  value: string;
  onChange: (next: string) => void;
  errorMessage: string | null;
  onRetry: () => void;
}

function CedarEditorFallback({
  value,
  onChange,
  errorMessage,
  onRetry,
}: FallbackProps): ReactNode {
  return (
    <div
      data-testid="cedar-editor-fallback"
      className="flex h-full min-h-[280px] flex-col gap-2 rounded border border-r5e-border bg-r5e-bg p-3"
    >
      <div
        role="alert"
        className="flex flex-col gap-1 text-xs text-r5e-text"
      >
        <strong className="text-r5e-accent">
          Cedar editor failed to initialize
        </strong>
        <span data-testid="cedar-editor-fallback-message">
          {errorMessage ??
            "Monaco could not be loaded. You can keep editing as plain text below."}
        </span>
        <button
          type="button"
          onClick={onRetry}
          data-testid="cedar-editor-fallback-retry"
          className="self-start rounded border border-r5e-border px-2 py-1 text-r5e-text hover:bg-r5e-surface"
        >
          Retry rich editor
        </button>
      </div>
      <textarea
        data-testid="cedar-editor-fallback-textarea"
        value={value}
        onChange={(e) => onChange(e.target.value)}
        spellCheck={false}
        className="min-h-[240px] flex-1 resize-none rounded border border-r5e-border bg-r5e-surface p-2 font-mono text-[12px] leading-relaxed text-r5e-text focus:border-r5e-accent focus:outline-none"
      />
    </div>
  );
}
