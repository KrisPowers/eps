import { useEffect, type RefObject } from "react";

// useDismiss closes a popup, such as a menu, on a click outside every one of
// `boxes` or on Escape, while it is open.
export function useDismiss(open: boolean, close: () => void, ...boxes: RefObject<HTMLElement | null>[]) {
  useEffect(() => {
    if (!open) return;
    const away = (e: MouseEvent) => {
      if (!boxes.some((b) => b.current?.contains(e.target as Node))) close();
    };
    const esc = (e: KeyboardEvent) => {
      if (e.key === "Escape") close();
    };
    document.addEventListener("mousedown", away);
    document.addEventListener("keydown", esc);
    return () => {
      document.removeEventListener("mousedown", away);
      document.removeEventListener("keydown", esc);
    };
    // The boxes are refs, which keep their identity.
  }, [open, close]);
}
