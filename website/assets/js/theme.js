// Runs in <head>, before the first paint, so the page never flashes the other chart.
(function () {
  try {
    var t = localStorage.getItem("theme");
    if (t === "day" || t === "night") document.documentElement.dataset.theme = t;
  } catch (e) {}
})();
