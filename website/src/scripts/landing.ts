export {};

const menu = document.querySelector<HTMLButtonElement>(".menu-toggle");
const navigation = document.querySelector<HTMLElement>("#site-navigation");
function closeMenu() {
  menu?.setAttribute("aria-expanded", "false");
  if (navigation) navigation.dataset.open = "false";
}
menu?.addEventListener("click", () => {
  const expanded = menu.getAttribute("aria-expanded") !== "true";
  menu.setAttribute("aria-expanded", String(expanded));
  if (navigation) navigation.dataset.open = String(expanded);
});
navigation
  ?.querySelectorAll("a")
  .forEach((link) => link.addEventListener("click", closeMenu));
document.addEventListener("keydown", (event) => {
  if (
    event.key === "Escape" &&
    menu?.getAttribute("aria-expanded") === "true"
  ) {
    closeMenu();
    menu.focus();
  }
});
document.querySelector(".theme-toggle")?.addEventListener("click", () => {
  const theme =
    document.documentElement.dataset.theme === "dark" ? "light" : "dark";
  document.documentElement.dataset.theme = theme;
  try {
    localStorage.setItem("starlight-theme", theme);
  } catch {
    /* Session-only theme still works. */
  }
});

for (const group of document.querySelectorAll<HTMLElement>(
  "[data-code-tabs]",
)) {
  const tabs = [...group.querySelectorAll<HTMLButtonElement>('[role="tab"]')];
  function select(index: number, focus = false) {
    tabs.forEach((tab, i) => {
      tab.setAttribute("aria-selected", String(i === index));
      tab.tabIndex = i === index ? 0 : -1;
      const panel = document.getElementById(
        tab.getAttribute("aria-controls") ?? "",
      );
      if (panel) panel.hidden = i !== index;
    });
    if (focus) tabs[index]?.focus();
  }
  tabs.forEach((tab, i) => {
    tab.addEventListener("click", () => select(i));
    tab.addEventListener("keydown", (event) => {
      const index =
        event.key === "ArrowRight"
          ? (i + 1) % tabs.length
          : event.key === "ArrowLeft"
            ? (i + tabs.length - 1) % tabs.length
            : event.key === "Home"
              ? 0
              : event.key === "End"
                ? tabs.length - 1
                : -1;
      if (index >= 0) {
        event.preventDefault();
        select(index, true);
      }
    });
  });
  const copy = group.querySelector<HTMLButtonElement>(".copy-button");
  copy?.addEventListener("click", async () => {
    const code = group.querySelector<HTMLElement>(
      '[role="tabpanel"]:not([hidden]) code',
    );
    const status = copy.querySelector<HTMLElement>("[aria-live]");
    try {
      await navigator.clipboard.writeText(code?.textContent ?? "");
      if (status) status.textContent = "Copied";
      copy.dataset.copied = "true";
    } catch {
      if (status)
        status.textContent = "Copy unavailable. Select the code to copy it.";
    }
    setTimeout(() => {
      delete copy.dataset.copied;
      if (status) status.textContent = "";
    }, 2500);
  });
}
