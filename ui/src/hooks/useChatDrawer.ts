// useChatDrawer — URL-driven open/close state for the persistent
// Audit Agent chat drawer (T117, Phase 6 US4).
//
// Per spec FR-036: the chat surface is reachable from any other surface.
// We park the open/closed bit in the URL search param `?chat=open` so the
// state survives page reloads and is shareable across users (e.g., a
// link with the drawer pre-opened on a specific conversation).
//
// The direct route `/admin/chat` implicitly opens the drawer too — that
// path doubles as the "page" surface for direct deep-links from external
// systems.

import { useCallback, useMemo } from "react";
import { useLocation, useSearchParams } from "react-router-dom";

export interface ChatDrawerControls {
  isOpen: boolean;
  open: () => void;
  close: () => void;
  toggle: () => void;
}

export function useChatDrawer(): ChatDrawerControls {
  const [searchParams, setSearchParams] = useSearchParams();
  const location = useLocation();

  const isOpen = useMemo(() => {
    if (searchParams.get("chat") === "open") return true;
    return location.pathname === "/chat" || location.pathname === "/chat/";
  }, [searchParams, location.pathname]);

  const open = useCallback(() => {
    setSearchParams(
      (prev) => {
        const next = new URLSearchParams(prev);
        next.set("chat", "open");
        return next;
      },
      { replace: false },
    );
  }, [setSearchParams]);

  const close = useCallback(() => {
    setSearchParams(
      (prev) => {
        const next = new URLSearchParams(prev);
        next.delete("chat");
        return next;
      },
      { replace: false },
    );
  }, [setSearchParams]);

  const toggle = useCallback(() => {
    if (isOpen) close();
    else open();
  }, [isOpen, open, close]);

  return { isOpen, open, close, toggle };
}
