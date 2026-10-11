// A screen for asciinema casts: enough of a VT100 for what the lab's recorder
// writes (cursor moves, erases, SGR), replayable to any point in time.
"use strict";

class Screen {
  constructor(cols, rows) {
    this.cols = cols;
    this.rows = rows;
    this.reset();
  }

  reset() {
    this.cells = [];
    for (let r = 0; r < this.rows; r++) this.cells.push(this.blankRow());
    this.x = 0;
    this.y = 0;
    this.style = 0;
    this.fg = null;
  }

  blankRow() {
    const row = [];
    for (let c = 0; c < this.cols; c++) row.push({ ch: " ", style: 0, fg: null });
    return row;
  }

  // style bits: 1 bold, 2 dim, 4 reverse
  sgr(params) {
    if (params.length === 0) params = [0];
    for (const p of params) {
      if (p === 0) { this.style = 0; this.fg = null; }
      else if (p === 1) this.style |= 1;
      else if (p === 2) this.style |= 2;
      else if (p === 7) this.style |= 4;
      else if (p === 22) this.style &= ~3;
      else if (p === 27) this.style &= ~4;
      else if (p >= 30 && p <= 37) this.fg = p - 30;
      else if (p >= 90 && p <= 97) this.fg = p - 90 + 8;
      else if (p === 39) this.fg = null;
    }
  }

  csi(params, final) {
    const n = (i, d) => (params[i] === undefined || isNaN(params[i]) ? d : params[i]);
    switch (final) {
      case "H": case "f":
        this.y = Math.min(this.rows - 1, n(0, 1) - 1);
        this.x = Math.min(this.cols - 1, n(1, 1) - 1);
        break;
      case "J":
        if (n(0, 0) === 2) for (let r = 0; r < this.rows; r++) this.cells[r] = this.blankRow();
        break;
      case "K":
        for (let c = this.x; c < this.cols; c++) this.cells[this.y][c] = { ch: " ", style: 0, fg: null };
        break;
      case "m":
        this.sgr(params.map(Number));
        break;
    }
  }

  write(s) {
    for (let i = 0; i < s.length; i++) {
      const ch = s[i];
      if (ch === "\x1b") {
        const m = /^\x1b\[([?]?)([0-9;]*)([A-Za-z])/.exec(s.slice(i, i + 32));
        if (m) {
          if (!m[1]) this.csi(m[2] === "" ? [] : m[2].split(";").map(Number), m[3]);
          i += m[0].length - 1;
        }
        continue;
      }
      if (ch === "\n") { this.y = Math.min(this.rows - 1, this.y + 1); this.x = 0; continue; }
      if (ch === "\r") { this.x = 0; continue; }
      if (this.x < this.cols) {
        this.cells[this.y][this.x] = { ch, style: this.style, fg: this.fg };
        this.x++;
      }
    }
  }

  text(row, from = 0, to = this.cols) {
    return this.cells[row].slice(from, to).map((c) => c.ch).join("");
  }
}

// A Cast replays a cast's output events onto a Screen up to time t.
class Cast {
  constructor(text) {
    const lines = text.trim().split("\n");
    const head = JSON.parse(lines[0]);
    this.cols = head.width;
    this.rows = head.height;
    this.events = lines.slice(1).map((l) => JSON.parse(l)).filter((e) => e[1] === "o");
    this.duration = this.events.length ? this.events[this.events.length - 1][0] : 0;
    this.screen = new Screen(this.cols, this.rows);
    this.next = 0;
  }

  at(t) {
    if (this.next > 0 && this.events[this.next - 1][0] > t) {
      this.screen.reset();
      this.next = 0;
    }
    while (this.next < this.events.length && this.events[this.next][0] <= t) {
      this.screen.write(this.events[this.next][2]);
      this.next++;
    }
    return this.screen;
  }

  // when returns the time of the first event after which some row matches re.
  when(re) {
    const s = new Screen(this.cols, this.rows);
    for (const e of this.events) {
      s.write(e[2]);
      for (let r = 0; r < s.rows; r++) if (re.test(s.text(r))) return e[0];
    }
    return null;
  }
}

if (typeof module !== "undefined") module.exports = { Screen, Cast };
