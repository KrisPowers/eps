import { useState, type ReactNode } from "react";
import { Icon } from "./Icon";

// usePaged splits a long list into pages of `size`, so no list runs on: the
// page shown, and the bar that steps through the pages, which is nothing
// when the list fits on one.
export function usePaged<T>(list: T[], size: number) {
  const [page, setPage] = useState(0);
  const pages = Math.max(1, Math.ceil(list.length / size));
  const at = Math.min(page, pages - 1);
  const from = at * size;
  const pager = list.length > size && (
    <div className="pager-bar">
      <span className="muted">{from + 1}-{Math.min(from + size, list.length)} of {list.length}</span>
      <button type="button" className="icon-btn" aria-label="Previous page" disabled={at === 0} onClick={() => setPage(at - 1)}>
        <Icon name="chevron_left" />
      </button>
      <button type="button" className="icon-btn" aria-label="Next page" disabled={at === pages - 1} onClick={() => setPage(at + 1)}>
        <Icon name="chevron_right" />
      </button>
    </div>
  );
  return { shown: list.slice(from, from + size), pager };
}

// Fold is a row whose detail stays hidden until it's opened.
export function Fold({ head, children }: { head: ReactNode; children: ReactNode }) {
  const [open, setOpen] = useState(false);
  return (
    <div className={"fold" + (open ? " open" : "")}>
      <button type="button" className="fold-head" aria-expanded={open} onClick={() => setOpen((o) => !o)}>
        {head}
        <Icon name="chevron_right" size={20} className="fold-caret" />
      </button>
      {open && <div className="fold-body">{children}</div>}
    </div>
  );
}
