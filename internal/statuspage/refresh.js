// Fetches the page again every 15 s while it is shown, and swaps its content.
(function () {
	var every = 15000;
	function refresh() {
		if (document.visibilityState !== "visible") return;
		fetch(location.href, { cache: "no-store", credentials: "omit" })
			.then(function (r) { return r.text(); })
			.then(function (html) {
				var next = new DOMParser().parseFromString(html, "text/html");
				["main", ".bar .note"].forEach(function (sel) {
					var a = document.querySelector(sel), b = next.querySelector(sel);
					if (a && b) a.replaceWith(b);
				});
			})
			.catch(function () {});
	}
	setInterval(refresh, every);
	document.addEventListener("visibilitychange", refresh);
})();
