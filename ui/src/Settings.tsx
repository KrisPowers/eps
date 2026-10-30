import { useEffect, useState } from "react";
import { Icon, type IconName } from "./Icon";
import { Card } from "./ScanView";

type Theme = "system" | "light" | "dark";
const THEMES: [Theme, string, IconName][] = [["system", "System", "brightness_auto"], ["light", "Light", "light_mode"], ["dark", "Dark", "dark_mode"]];

// Settings is the dashboard's own preferences, kept in this browser. The
// theme is light, dark, or whatever the system is set to; index.html applies
// it before the page draws.
export function Settings() {
  const [theme, setTheme] = useState<Theme>(() => {
    try {
      const t = localStorage.getItem("theme");
      return t === "light" || t === "dark" ? t : "system";
    } catch {
      return "system";
    }
  });

  useEffect(() => {
    const root = document.documentElement;
    if (theme === "system") delete root.dataset.theme;
    else root.dataset.theme = theme;
    try {
      if (theme === "system") localStorage.removeItem("theme");
      else localStorage.setItem("theme", theme);
    } catch {
      // Not kept, still applied.
    }
  }, [theme]);

  return (
    <>
      <div className="page-head">
        <div className="page-head-main"><h1>Settings</h1></div>
      </div>
      <Card title="Theme" sub="Kept in this browser">
        <div className="choices" role="radiogroup" aria-label="Theme">
          {THEMES.map(([key, label, icon]) => (
            <button key={key} type="button" role="radio" aria-checked={theme === key} className="choice" onClick={() => setTheme(key)}>
              <Icon name={icon} size={28} />
              <span>{label}</span>
            </button>
          ))}
        </div>
      </Card>
    </>
  );
}
