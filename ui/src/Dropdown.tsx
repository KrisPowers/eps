import { useCallback, useLayoutEffect, useRef, useState, type KeyboardEvent } from "react";
import { createPortal } from "react-dom";
import { useDismiss } from "./dismiss";
import { Icon, type IconName } from "./Icon";

export interface Option<T> {
  value: T;
  label: string;
  // A line under the label, saying what the choice does.
  hint?: string;
  icon?: IconName;
}

// Dropdown picks one of `options`: a field showing the choice that opens a
// list of them. The list is drawn over the page, under the field, so no
// card or scroll area cuts it off; it closes on a click outside, Escape, or
// the page scrolling. Arrow keys move through it and Enter picks.
export function Dropdown<T extends string | number>({ label, value, options, onChange }: {
  label: string;
  value: T;
  options: Option<T>[];
  onChange: (value: T) => void;
}) {
  const [open, setOpen] = useState(false);
  const [active, setActive] = useState(0);
  const [at, setAt] = useState({ left: 0, top: 0, width: 0, up: false });
  const field = useRef<HTMLButtonElement>(null);
  const list = useRef<HTMLUListElement>(null);
  const close = useCallback(() => setOpen(false), []);
  useDismiss(open, close, field, list);
  const current = options.find((o) => o.value === value) ?? options[0];

  // Place the list under the field, or over it when there's no room below.
  useLayoutEffect(() => {
    if (!open || !field.current) return;
    const r = field.current.getBoundingClientRect();
    const tall = Math.min(options.length * 56 + 16, 360);
    const up = r.bottom + tall + 8 > innerHeight && r.top > tall + 8;
    setAt({ left: r.left, top: up ? r.top - tall - 4 : r.bottom + 4, width: Math.max(r.width, 220), up });
    const shut = () => setOpen(false);
    addEventListener("scroll", shut, true);
    addEventListener("resize", shut);
    return () => {
      removeEventListener("scroll", shut, true);
      removeEventListener("resize", shut);
    };
  }, [open, options.length]);

  const pick = (v: T) => {
    onChange(v);
    setOpen(false);
    field.current?.focus();
  };

  const onKey = (e: KeyboardEvent) => {
    if (e.key === "ArrowDown" || e.key === "ArrowUp") {
      e.preventDefault();
      if (!open) {
        setActive(Math.max(0, options.indexOf(current)));
        return setOpen(true);
      }
      const step = e.key === "ArrowDown" ? 1 : -1;
      setActive((a) => (a + step + options.length) % options.length);
    } else if ((e.key === "Enter" || e.key === " ") && open) {
      e.preventDefault();
      pick(options[active].value);
    }
  };

  return (
    <>
      <button ref={field} type="button" className={"dropdown" + (open ? " open" : "")} aria-haspopup="listbox" aria-expanded={open} aria-label={label}
        onKeyDown={onKey}
        onClick={() => {
          setActive(Math.max(0, options.indexOf(current)));
          setOpen((o) => !o);
        }}>
        {current?.icon && <Icon name={current.icon} size={18} />}
        <span className="dropdown-value">{current?.label ?? String(value)}</span>
        <svg className="dropdown-caret" width="18" height="18" viewBox="0 0 24 24" aria-hidden="true"><path d="M7 10l5 5 5-5z" /></svg>
      </button>
      {open && createPortal(
        <ul ref={list} className={"dropdown-list" + (at.up ? " up" : "")} role="listbox" aria-label={label}
          style={{ left: at.left, top: at.top, minWidth: at.width }}>
          {options.map((o, i) => (
            <li key={String(o.value)} role="option" aria-selected={o.value === value}
              className={"dropdown-option" + (i === active ? " active" : "")}
              onMouseEnter={() => setActive(i)} onMouseDown={(e) => e.preventDefault()} onClick={() => pick(o.value)}>
              <span className="dropdown-check">{o.value === value && <Icon name="check" size={18} />}</span>
              {o.icon && <Icon name={o.icon} size={20} className="dropdown-icon" />}
              <span className="dropdown-text">
                <span>{o.label}</span>
                {o.hint && <small>{o.hint}</small>}
              </span>
            </li>
          ))}
        </ul>,
        document.body,
      )}
    </>
  );
}
