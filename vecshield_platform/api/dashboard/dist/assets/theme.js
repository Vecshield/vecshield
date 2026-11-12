// Applies the theme before the stylesheet paints, so the console never flashes
// the wrong one. A classic synchronous script because the CSP forbids inline
// code: a stored choice wins, otherwise the system preference.
(function () {
  try {
    var theme = null;
    try { theme = window.localStorage.getItem("vecshield_theme"); } catch (e) { /* blocked */ }
    if (theme !== "light" && theme !== "dark") {
      theme = window.matchMedia && window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light";
    }
    document.documentElement.setAttribute("data-theme", theme);
  } catch (e) { /* keep the page's default */ }
})();
