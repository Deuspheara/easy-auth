"use strict";
const preference = matchMedia("(prefers-color-scheme: dark)");
const root = document.documentElement;
const control = document.getElementById("theme");
function synchronize() {
  const dark = root.dataset.theme === "dark" || (!root.dataset.theme && preference.matches);
  root.classList.toggle("dark", dark);
  const label = dark ? "Use light theme" : "Use dark theme";
  control?.setAttribute("aria-label", label);
  if (control) control.title = label;
  return dark;
}
control?.addEventListener("click", () => {
  root.dataset.theme = synchronize() ? "light" : "dark";
  synchronize();
});
preference.addEventListener("change", synchronize);
synchronize();
