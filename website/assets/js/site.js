(function () {
  var root = document.documentElement;
  var btn = document.querySelector("[data-theme-toggle]");
  if (btn) btn.addEventListener("click", function () {
    var now = root.dataset.theme || (matchMedia("(prefers-color-scheme: light)").matches ? "day" : "night");
    var next = now === "day" ? "night" : "day";
    root.dataset.theme = next;
    try { localStorage.setItem("theme", next); } catch (e) {}
  });

  var menu = document.querySelector("[data-menu]");
  if (menu) menu.addEventListener("click", function () {
    var open = document.body.classList.toggle("nav-open");
    menu.setAttribute("aria-expanded", open);
  });

  document.querySelectorAll(".code .copy").forEach(function (b) {
    b.addEventListener("click", function () {
      var pre = b.closest(".code").querySelector("pre");
      var lines = Array.from(pre.querySelectorAll(".line")).map(function (l) {
        return l.textContent.replace(/^\$ /, "").replace(/\s+#.*$/, "").replace(/\n$/, "");
      }).filter(function (l) { return l.trim() !== ""; });
      navigator.clipboard.writeText(lines.join("\n")).then(function () {
        var was = b.textContent; b.textContent = b.dataset.done;
        setTimeout(function () { b.textContent = was; }, 1400);
      });
    });
  });

  // A footnote link opens the closed notes before the browser scrolls to them.
  function openNote(hash) {
    var li = hash && document.getElementById(decodeURIComponent(hash.slice(1)));
    var d = li && li.closest("details");
    if (d && !d.open) { d.open = true; return li; }
  }
  var noted = openNote(location.hash);
  if (noted) noted.scrollIntoView();
  document.querySelectorAll(".matrix sup a").forEach(function (a) {
    a.addEventListener("click", function () { openNote(a.hash); });
  });

  var links = Array.from(document.querySelectorAll(".toc a"));
  if (links.length && "IntersectionObserver" in window) {
    var byId = {};
    links.forEach(function (a) { byId[decodeURIComponent(a.hash.slice(1))] = a; });
    var obs = new IntersectionObserver(function (es) {
      es.forEach(function (e) {
        if (e.isIntersecting) {
          links.forEach(function (a) { a.classList.remove("on"); });
          var a = byId[e.target.id]; if (a) a.classList.add("on");
        }
      });
    }, { rootMargin: "-70px 0px -70% 0px" });
    document.querySelectorAll(".prose h2[id]").forEach(function (h) { obs.observe(h); });
  }
})();
