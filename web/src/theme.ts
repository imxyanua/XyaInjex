export type Theme = "light" | "dark";

const KEY = "xyainjex-theme";

export const initialTheme: Theme = (() => {
  const saved = localStorage.getItem(KEY);
  if (saved === "light" || saved === "dark") return saved;
  const prefersLight =
    window.matchMedia && window.matchMedia("(prefers-color-scheme: light)").matches;
  return prefersLight ? "light" : "dark";
})();

export function applyTheme(theme: Theme): void {
  document.documentElement.setAttribute("data-theme", theme);
  localStorage.setItem(KEY, theme);
}
