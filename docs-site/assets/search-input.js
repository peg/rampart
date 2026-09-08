(() => {
  "use strict";

  // Material 9.7 observes search changes on keyup and focus, but not input.
  // Forward input-only edits (including mobile input and committed composition)
  // until the theme observes input itself. Its value filters deduplicate keyup.
  const refreshSearch = (event) => {
    const input = event.target;
    if (!(input instanceof HTMLInputElement) ||
        !input.matches('[data-md-component="search-query"]') ||
        event.isComposing) return;

    // Keep this local to the query observer, away from global keyboard shortcuts.
    input.dispatchEvent(new Event("keyup"));
  };

  document.addEventListener("input", refreshSearch);
  document.addEventListener("compositionend", refreshSearch);
})();
