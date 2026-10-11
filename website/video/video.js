// The tour: every frame is a function of t alone, so that the renderer can
// seek to any frame; nothing here may animate by itself.
"use strict";

const clamp = (x, a = 0, b = 1) => Math.min(b, Math.max(a, x));
const ramp = (t, t0, t1) => clamp((t - t0) / (t1 - t0));
const ease = (t, t0, t1) => { const x = ramp(t, t0, t1); return x * x * (3 - 2 * x); };
// fade is 1 between in and out, ramping over d at either end.
const fade = (t, tin, tout, d = 0.4) => Math.min(ease(t, tin, tin + d), 1 - ease(t, tout - d, tout));
const $ = (s) => document.querySelector(s);
const esc = (s) => s.replace(/[&<>]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;" })[c]);

// ---- intro: devices that need no server in the middle ----

const SVG = "http://www.w3.org/2000/svg";
function el(name, attrs, parent) {
  const e = document.createElementNS(SVG, name);
  for (const k in attrs) e.setAttribute(k, attrs[k]);
  if (parent) parent.appendChild(e);
  return e;
}

const intro = {
  devices: [
    { name: "phone", x: 960, y: 330 },
    { name: "laptop", x: 560, y: 790 },
    { name: "nas", x: 1360, y: 790 },
  ],
  server: { x: 960, y: 640 },

  build() {
    const svg = $("#intro");
    const s = this.server;
    this.spokes = this.devices.map((d) => el("line", { x1: s.x, y1: s.y, x2: d.x, y2: d.y, stroke: "#7d9192", "stroke-width": 3, "stroke-dasharray": "10 10" }, svg));
    this.links = [];
    for (let i = 0; i < 3; i++) {
      const a = this.devices[i], b = this.devices[(i + 1) % 3];
      const len = Math.hypot(b.x - a.x, b.y - a.y);
      this.links.push({ a, b, len, line: el("line", { x1: a.x, y1: a.y, x2: b.x, y2: b.y, stroke: "#46d1bf", "stroke-width": 5, "stroke-linecap": "round", "stroke-dasharray": len }, svg) });
    }
    this.serverBox = el("g", {}, svg);
    el("rect", { x: s.x - 130, y: s.y - 48, width: 260, height: 96, rx: 18, fill: "#0a1317", stroke: "#7d9192", "stroke-width": 3, "stroke-dasharray": "10 8" }, this.serverBox);
    el("text", { x: s.x, y: s.y + 11, "text-anchor": "middle", "font-size": 32, fill: "#7d9192" }, this.serverBox).textContent = "server";
    this.strike = el("line", { x1: s.x - 150, y1: s.y + 60, x2: s.x + 150, y2: s.y - 60, stroke: "#f0644f", "stroke-width": 8, "stroke-linecap": "round", "stroke-dasharray": 340 }, svg);
    this.packets = this.links.map(() => [0, 1].map(() => el("circle", { r: 9, fill: "#e8c98e" }, svg)));
    this.boxes = this.devices.map((d) => {
      const g = el("g", {}, svg);
      el("rect", { x: d.x - 130, y: d.y - 48, width: 260, height: 96, rx: 18, fill: "#102127", stroke: "#2b4a52", "stroke-width": 3 }, g);
      el("circle", { cx: d.x - 84, cy: d.y, r: 10, fill: "#46d1bf" }, g);
      el("text", { x: d.x + 14, y: d.y + 12, "text-anchor": "middle", "font-size": 36, fill: "#e4dccb" }, g).textContent = d.name;
      return g;
    });
  },

  // seek draws the intro at its own time t.
  seek(t) {
    this.boxes.forEach((g, i) => {
      const p = ease(t, 0.2 + i * 0.15, 0.8 + i * 0.15);
      g.setAttribute("opacity", p);
      g.setAttribute("transform", `translate(0 ${(1 - p) * 30})`);
    });
    const serverIn = ease(t, 0.6, 1.2), serverOut = ease(t, 3.0, 3.6);
    this.serverBox.setAttribute("opacity", serverIn * (1 - serverOut));
    this.spokes.forEach((l) => l.setAttribute("opacity", serverIn * (1 - serverOut) * 0.8));
    this.strike.setAttribute("stroke-dashoffset", 340 * (1 - ease(t, 2.2, 2.6)));
    this.strike.setAttribute("opacity", 1 - serverOut);
    this.links.forEach((k, i) => {
      k.line.setAttribute("stroke-dashoffset", k.len * (1 - ease(t, 3.4 + i * 0.2, 4.2 + i * 0.2)));
      this.packets[i].forEach((c, j) => {
        const u = (t - 4.6 - j * 0.9 - i * 0.3) / 1.4;
        const on = u > 0 && t < 7.6;
        const f = ((u % 1) + 1) % 1;
        const [a, b] = j ? [k.b, k.a] : [k.a, k.b];
        c.setAttribute("cx", a.x + (b.x - a.x) * f);
        c.setAttribute("cy", a.y + (b.y - a.y) * f);
        c.setAttribute("opacity", on ? Math.sin(Math.PI * f) : 0);
      });
    });
  },
};

// ---- terminal scene: a lab recording, two devices side by side ----

const QUADS = { "▀": "qt", "▄": "qb", "█": "qf" };
const WORDS = /(?<![\w-])[a-z]+-[a-z]+-[a-z]+-[a-z]+(?![\w-])/;
const DIRECT = /(?<=^laptop +\S+ +)direct\b/;

function renderPane(screen, from, to, rows, hl, prompt) {
  // hl, where set, is a pattern whose first match on each row is highlighted.
  let html = "";
  for (let r = rows[0]; r < rows[1]; r++) {
    const cells = screen.cells[r].slice(from, to);
    const text = cells.map((c) => c.ch).join("");
    const m = hl ? hl.exec(text) : null;
    let line = "", cur = null, buf = "";
    const flush = () => { if (buf) line += cur ? `<span class="${cur}">${esc(buf)}</span>` : esc(buf); buf = ""; };
    cells.forEach((c, i) => {
      if (QUADS[c.ch]) { flush(); line += `<span class="q ${QUADS[c.ch]}"></span>`; return; }
      let cls = c.style ? `b${c.style & 4 ? 4 : c.style & 1 ? 1 : 2}` : "";
      if (m && i >= m.index && i < m.index + m[0].length) cls = "hl";
      if (prompt && i < prompt.length && text.startsWith(prompt)) cls = "p";
      if (cls !== (cur || "")) { flush(); cur = cls || null; }
      buf += c.ch;
    });
    flush();
    html += `<div>${line}</div>`;
  }
  return html;
}

// A clip plays a cast through a piecewise map from scene time to cast time:
// each hold freezes the cast at a cast time for some seconds.
class Clip {
  constructor(cast, holds) {
    this.cast = cast;
    this.holds = holds.slice().sort((a, b) => a.at - b.at);
    this.duration = cast.duration + this.holds.reduce((s, h) => s + h.for, 0);
  }

  castTime(t) {
    let shift = 0;
    for (const h of this.holds) {
      if (t - shift < h.at) break;
      if (t - shift < h.at + h.for) return h.at;
      shift += h.for;
    }
    return Math.min(this.cast.duration, t - shift);
  }

  // sceneTime is the inverse of castTime: the scene time a cast time first shows.
  sceneTime(c) {
    let shift = 0;
    for (const h of this.holds) if (h.at < c) shift += h.for;
    return c + shift;
  }
}

const term = {
  build(cast, titles) {
    const words = cast.when(/same\? \[y\/N\]/);
    const invited = cast.when(/# same LAN/);
    const pinged = cast.when(/packet loss/);
    const direct = cast.when(/laptop +\S+ +direct/);
    this.clip = new Clip(cast, [
      { at: invited, for: 1.5 },
      { at: words, for: 3.0 },
      { at: pinged, for: 1.0 },
    ]);
    const s = (c) => this.clip.sceneTime(c);
    this.words = [s(words), s(words) + 4.2];
    this.direct = s(direct);
    this.captions = [
      { from: 0, to: s(cast.when(/juist invite/)), h: "Create a network", p: "One command. No account, no server to run." },
      { from: s(cast.when(/juist invite/)), to: s(words), h: "Invite a device", p: "A code for the LAN, a link or QR code for anywhere." },
      { from: s(words), to: s(words) + 4.6, h: "Compare four words", p: "The same on both screens? Then the device is in." },
      { from: s(words) + 4.6, to: this.clip.duration + 3, h: "Connected", p: "WireGuard, directly from device to device." },
    ];
    $("#win-l .bar span").textContent = titles[0];
    $("#win-r .bar span").textContent = titles[1];
  },

  seek(t) {
    const screen = this.clip.cast.at(this.clip.castTime(t));
    const hl = t >= this.words[0] && t < this.words[1] ? WORDS : t >= this.direct + 0.3 ? DIRECT : null;
    $("#win-l .screen").innerHTML = renderPane(screen, 0, 79, [1, screen.rows], hl, "laptop#");
    $("#win-r .screen").innerHTML = renderPane(screen, 81, 160, [1, screen.rows], hl, "nas#");
  },
};

// ---- phone: the Android app joining the same network ----

const phone = {
  // when each screen slides in, in seconds into the scene
  screens: [0, 2.8, 5.8],
  len: 9.6,

  seek(t) {
    const pos = this.screens.slice(1).reduce((p, s) => p + ease(t, s, s + 0.4), 0);
    document.querySelectorAll("#phone .glass img").forEach((img, i) => {
      img.style.transform = `translateX(${(i - pos) * 100}%)`;
    });
    // a tap on "Scan QR code", at its place in the welcome screen
    const tap = $("#phone .tap");
    const u = ramp(t, 1.9, 2.6);
    tap.style.left = "50%";
    tap.style.top = "78.4%";
    tap.style.opacity = u > 0 && u < 1 ? 0.9 * (1 - u) : 0;
    tap.style.transform = `scale(${0.6 + u * 1.4})`;
  },
};

// ---- the timeline ----

let timeline = [];
let duration = 0;

function caption(h, p, o) {
  const c = $("#caption");
  if ($("#caption h1").textContent !== h) $("#caption h1").textContent = h;
  if ($("#caption p").textContent !== p) $("#caption p").textContent = p;
  c.style.opacity = o;
  c.style.transform = `translateY(${(1 - o) * 12}px)`;
}

async function load() {
  const cast = new Cast(await (await fetch("casts/demo.cast")).text());
  intro.build();
  term.build(cast, ["laptop · Debian 12", "nas · FreeBSD 14"]);
  $("#outro .mark").innerHTML = (await (await fetch("wordmark.svg")).text()).replace(/<!--.*?-->\s*/s, "");
  $("#outro .tag").textContent = "A mesh VPN with no coordination server";
  $("#outro .url").textContent = "github.com/nning/juist";

  const introLen = 8.0, termLen = term.clip.duration + 2.5, phoneLen = phone.len, outroLen = 4.5;
  timeline = [
    { el: $("#intro"), start: 0, len: introLen, seek: (t) => intro.seek(t), captions: [
      { from: 0.4, to: 3.3, h: "No server in the middle", p: "" },
      { from: 3.5, to: 7.6, h: "Your devices are the network", p: "They find each other and connect directly." },
    ] },
    { el: $("#term"), start: introLen, len: termLen, seek: (t) => term.seek(t), captions: term.captions },
    { el: $("#phone"), start: introLen + termLen, len: phoneLen, seek: (t) => phone.seek(t), captions: [
      { from: 0, to: phone.screens[2], h: "Phones join too", p: "The Android app scans the QR code and compares the same four words." },
      { from: phone.screens[2], to: phoneLen, h: "Every device in reach", p: "Directly where the network allows, through a relay of yours where not." },
    ] },
    { el: $("#outro"), start: introLen + termLen + phoneLen, len: outroLen, seek: (t) => outro(t), captions: [] },
  ];
  duration = introLen + termLen + phoneLen + outroLen;
  await document.fonts.ready;
  seek(0);
}

function outro(t) {
  const link = $("#outro .link");
  const p = ease(t, 0.5, 1.1);
  link.style.opacity = p;
  link.style.transform = `translateY(${(1 - p) * -200}px)`;
  $("#outro .tag").style.opacity = ease(t, 1.0, 1.5);
  $("#outro .url").style.opacity = ease(t, 1.4, 1.9);
}

// seek draws the frame at t seconds; it resolves once the frame is painted.
function seek(t) {
  let shown = null;
  for (const [i, s] of timeline.entries()) {
    const last = i === timeline.length - 1;
    const o = fade(t, i ? s.start : -1, last ? duration + 1 : s.start + s.len, 0.35);
    s.el.style.opacity = o;
    if (o > 0) {
      s.seek(t - s.start);
      for (const c of s.captions) {
        const lt = t - s.start;
        if (lt >= c.from && lt < c.to) shown = { ...c, o: fade(lt, c.from, c.to, 0.35) * Math.min(1, o * 1.5) };
      }
    }
  }
  if (shown) caption(shown.h, shown.p, shown.o);
  else caption("", "", 0);
  return new Promise((r) => requestAnimationFrame(() => requestAnimationFrame(r)));
}

window.seek = seek;
window.videoReady = load().then(() => ({ duration }));
