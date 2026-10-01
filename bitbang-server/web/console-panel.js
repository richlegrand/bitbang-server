/*
 * The device console, as a component rather than a page.
 *
 * The same treatment settings-panel.js had, for the same reasons -- see the top
 * of that file. Mounted into a shadow root on an element the caller supplies, so
 * one implementation renders two ways: `/*console` standalone, and inside a
 * sketch's own layout through `data-bitbang-page="console"` on a div.
 *
 * Opens /__bitbang/console, which bootstrap turns into a SWSP stream of type
 * console. Every DAT frame is one tag byte then bytes: 0x00 history, 0x01 live,
 * 0x02 a JSON control such as {"dropped":4096}.
 *
 * History and live are rendered identically on purpose. An earlier version drew
 * a rule between them, and it misled twice over: the boundary is a byte offset
 * so it lands mid-line, and "live" is not true of anything you are reading --
 * it is all output from the past, some of it from slightly further back. The
 * tag stays on the wire because it costs a byte and a later viewer may want it.
 *
 * What does not need solving, as with settings: the session. Embedded, the page
 * is a device page and ws-shim is already in it; standalone, the service worker
 * puts ws-shim into the meta-page. Either way `new WebSocket(...)` here becomes
 * a stream to the right device with nothing passed in.
 *
 * Temporary, with console.html: both move out when the server has plugins.
 */

import { foldable, FOLD_CSS } from './panel-fold.js';
import { control, absorb, THEME_CSS, CONTROL_CSS } from './setting-control.js';

const STYLE = `
  /* :host, not :root, for the reason settings-panel.js gives: these land on
     the host element, and the variables are the override point a sketch has. */
  :host {
    display: flex;
    flex-direction: column;
    min-height: 0;
    color-scheme: light dark;
    --font: ui-monospace, SFMono-Regular, Menlo, Consolas, "Liberation Mono", monospace;
    /* The colors are setting-control.js's THEME_CSS, shared with settings. */
    font: 13px/1.5 var(--font);
  }
  /* Embedded, the log needs a height to scroll inside, and a div in a sketch's
     layout has none unless the sketch gives it one. This is the default; a
     height the page sets on the element wins, since a page's own rule on the
     host outranks :host. */
  :host([data-bb-embedded]) {
    /* border-box, so a height the page gives the element is its outer height
       rather than that plus anything inside. */
    box-sizing: border-box;
    height: 18rem;
  }
  header { display:flex; align-items:center; gap:1rem; flex-wrap:wrap;
           padding:.6rem 1rem; border-bottom:1px solid var(--line); }
  /* What folds away. A flex child of its own, so the log inside it still fills
     whatever height the host has. */
  #fold-wrap { flex:1; min-height:0; display:flex; flex-direction:column; }

  /* Embedded, the toolbar sits above a bordered log rather than inside one
     border with it -- the settings panel's arrangement, a row of buttons over
     the content. That is what keeps the toggle still: it is at the panel's
     left edge open and folded, so folding moves it down and nothing else.
     Inside a border it sat a padding's width further in when open, and
     jumped sideways every time it was pressed. */
  :host([data-bb-embedded]) header { padding:0 0 .4rem; border-bottom:none; }
  :host([data-bb-embedded]) #fold-wrap { border:1px solid var(--line);
                                         border-radius:6px; }

  /* Folded, the panel is its toggle and nothing else -- a button in the corner
     of the page, as the settings toggle is. The height goes to the button's,
     which is what the page above takes back. A page that sets its own height
     on the element says what folded is worth, as the camera page does for
     settings' width: #con[data-bb-collapsed]{height:auto}. */
  :host([data-bb-collapsed]) { height:auto; }
  :host([data-bb-collapsed]) header { padding:0; border-bottom:none; }
  :host([data-bb-collapsed]) header > :not(#fold) { display:none; }
  h1 { font-size:.75rem; font-weight:600; letter-spacing:.08em;
       text-transform:uppercase; color:var(--dim); margin:0; }
  #state { font-size:.75rem; color:var(--dim); }
  #state.err { color:var(--bad); }
  label { font-size:.75rem; color:var(--dim); display:inline-flex;
          align-items:center; gap:.3rem; }
  button { font:inherit; font-size:.75rem; color:inherit; background:none;
           border:1px solid var(--line); border-radius:5px;
           padding:.2rem .6rem; cursor:pointer; }
  button:hover { border-color:var(--accent); }
  /* The device's own controls, laid out as toolbar items like follow beside
     them rather than as a group of their own. */
  #ctl { display:contents; }
  /* The shared rows, sized for a toolbar: one line each, no label column, no
     line reserved for the device's answer, and type the size of follow's. */
  #ctl .row { display:inline-flex; flex-wrap:nowrap; align-items:center;
              column-gap:.4rem; padding:0; font-size:.75rem; }
  #ctl .label { flex:none; min-width:0; }
  #ctl .ctl, #ctl .ctl.narrow, #ctl .ctl.wide { flex:none; min-width:0; gap:.3rem; }
  #ctl .state { min-height:0; }
  #ctl select { padding:.1rem .3rem; }

  #log { flex:1; min-height:0; overflow:auto; margin:0; padding:.6rem 1rem;
         white-space:pre-wrap; word-break:break-word; }
  :host([data-bb-embedded]) #log { padding:.4rem .75rem; }
  .drop { color:var(--bad); }
  /* Matching what idf.py monitor shows: green info, yellow warn, red error.
     Applied from the level letter on each line, and from ANSI escapes when a
     build or an application actually sends them. */
  .c31 { color:#e5484d; }   /* red */
  .c32 { color:#30a46c; }   /* green */
  .c33 { color:#e2a336; }   /* yellow */
  .c34 { color:#3b82f6; }   /* blue */
  .c35 { color:#c678dd; }   /* magenta */
  .c36 { color:#56b6c2; }   /* cyan */
`;

const TAIL = 65536;

/* Color comes from the level letter, not from escape codes.
 *
 * idf.py monitor colors its output on the host -- that is where the green and
 * yellow in a terminal come from. The device itself sends plain text unless
 * CONFIG_LOG_COLORS is on, which costs 11 bytes of ring and wire per line to
 * transmit what the receiver can work out for itself from "I (123) tag:".
 *
 * So lines are matched here and colored to match what the monitor shows. Any
 * escapes that do arrive -- from CONFIG_LOG_COLORS, or from application output
 * that emits its own -- still win, which is why the parser below stays.
 */
const LEVEL = { E: 'c31', W: 'c33', I: 'c32', D: 'c36', V: 'c35' };

function levelClass(line) {
  /* IDF's exact shape, so arbitrary text that happens to start with a capital
     letter is left alone. */
  const m = /^([EWIDV]) \(\d+\)/.exec(line);
  return m ? LEVEL[m[1]] : null;
}

function classForSGR(params, current) {
  /* Last colour wins, which is what a terminal does: "0;32" is reset then
     green. Bold (1) is dropped rather than approximated. */
  let cls = current;
  for (const p of params.split(';')) {
    const n = parseInt(p || '0', 10);
    if (n === 0) cls = null;
    else if (n >= 30 && n <= 37) cls = 'c' + n;
    else if (n >= 90 && n <= 97) cls = 'c' + (n - 60);
  }
  return cls;
}

/*
 * opts.title        the "Console" heading. Default true; the embedded mount
 *                   passes false, because the page supplies its own label.
 * opts.collapsible  a toggle that folds the console down to just that toggle.
 *                   Default false. Folds vertically -- a console is a row along
 *                   the bottom of a page, not a column -- with the same
 *                   mechanism as the settings panel (panel-fold.js).
 *
 * Everything below lives in this function rather than at module scope, so two
 * consoles on one page keep their own socket, position and line buffer.
 */
export function mount(host, opts = {}) {
  const title = opts.title !== false;
  const collapsible = opts.collapsible === true;
  if (!title) host.setAttribute('data-bb-embedded', '');

  const root = host.attachShadow({ mode: 'open' });
  const style = document.createElement('style');
  /* The shared pieces first, so this panel's own rules can refine them. */
  style.textContent = THEME_CSS + CONTROL_CSS + STYLE + FOLD_CSS;
  root.appendChild(style);

  /* The toggle first in the toolbar, which is the one part that does not
     fold -- so folded, it is the button left in the corner. */
  const frag = document.createElement('div');
  frag.innerHTML = `
    <header>
      ${collapsible ? '<button id="fold" aria-expanded="true">Hide</button>' : ''}
      ${title ? '<h1>Console</h1>' : ''}
      <span id="state">connecting</span>
      <label><input type="checkbox" id="follow" checked> follow</label>
      <span id="ctl"></span>
      <button id="clear">Clear</button>
    </header>
    <div id="fold-wrap"><pre id="log"></pre></div>`;
  while (frag.firstChild) root.appendChild(frag.firstChild);

  const logEl = root.getElementById('log');
  const stateEl = root.getElementById('state');
  const followEl = root.getElementById('follow');

  const say = (t, bad) => { stateEl.textContent = t; stateEl.className = bad ? 'err' : ''; };

  /* -- getting text onto the page without stalling it ------------------------

     This shares a thread with the video. It used to add each line to the log
     the moment it arrived, reading the log's scroll position before and setting
     it after -- two forced layouts per line, of one block of text that only
     ever grew. Measured on 2026-10-01: a 1 KB chunk took 3.9 ms against a
     300-line log and 125.6 ms against 7,300 lines, which is twelve minutes of
     this camera's output. That was the video stuttering whenever the console
     printed, worse the longer the page was open; and nothing was ever let go.

     So: lines wait for the next frame and go in together; whether the view is
     at the bottom is learned from its own scroll events rather than measured
     per line; and the log keeps the last MAX_PIECES and lets the rest go. */
  const MAX_PIECES = 4000;
  let queued = document.createDocumentFragment();
  let frameAsked = false;

  /* At the bottom, so new lines should keep it there. Updated when the log
     scrolls -- by a person, or by flush() below -- so appending never has to
     measure anything. */
  let atBottom = true;
  logEl.addEventListener('scroll', () => {
    atBottom = logEl.scrollHeight - logEl.scrollTop - logEl.clientHeight < 40;
  }, { passive: true });

  function flush() {
    frameAsked = false;
    logEl.appendChild(queued);              /* moves the nodes; queued is empty after */
    for (let extra = logEl.childElementCount - MAX_PIECES; extra > 0; extra--) {
      logEl.firstChild.remove();
    }
    if (followEl.checked && atBottom) logEl.scrollTop = logEl.scrollHeight;
  }

  /* Untrusted by construction: device output is bytes, and the only safe way to
     put bytes on a page is as text. Everything here appends text nodes. */
  function append(text, cls) {
    if (!text) return;
    const node = document.createElement('span');
    if (cls) node.className = cls;
    node.textContent = text;
    queued.appendChild(node);
    /* A hidden tab runs no frames, so the queue is capped too: a device that
       logged for an hour behind another tab would otherwise all land at once. */
    for (let extra = queued.childElementCount - MAX_PIECES; extra > 0; extra--) {
      queued.firstChild.remove();
    }
    if (!frameAsked) {
      frameAsked = true;
      requestAnimationFrame(flush);
    }
  }

  /* The level color is decided per line, so text is held until its newline
     arrives -- a chunk boundary lands mid-line constantly at 1024 bytes.
     Held as pieces, each with the escape color it arrived under. It used to be
     one string colored at the newline with whatever was in force by then, so
     text an application colored and reset before the end of the line lost its
     color. The level color fills in only where no escape set one. The cap is
     for a device that writes without newlines at all: better to show it than
     to hold it forever. */
  let pieces = [], held = 0;

  function flushLine() {
    const level = levelClass(pieces.map(p => p[0]).join(''));
    for (const [t, c] of pieces) append(t, c || level);
    pieces = [];
    held = 0;
  }

  function emit(text, cls) {
    let start = 0, nl;
    while ((nl = text.indexOf('\n', start)) >= 0) {
      pieces.push([text.slice(start, nl + 1), cls]);
      flushLine();
      start = nl + 1;
    }
    if (start < text.length) {
      pieces.push([text.slice(start), cls]);
      held += text.length - start;
    }
    if (held > 4096) flushLine();
  }

  /* ANSI, for the cases where escapes really are in the stream.
   *
   * Only SGR (ESC[...m) is handled; a viewer that tried to implement cursor
   * movement in a scrollback pane would be inventing a terminal it cannot honor.
   *
   * Two pieces of state have to survive across frames, and both would be bugs if
   * they did not: a 1024-byte chunk can split an escape sequence down the
   * middle, and a color set at the start of a line is still in force when the
   * next chunk continues it. */
  let ansiPending = '';   // a partial escape held back for the next chunk
  let ansiClass = null;   // color currently in force

  function writeAnsi(text) {
    const s = ansiPending + text;
    ansiPending = '';
    let i = 0;
    while (i < s.length) {
      const esc = s.indexOf('\x1b', i);
      if (esc < 0) { emit(s.slice(i), ansiClass); return; }
      emit(s.slice(i, esc), ansiClass);

      const m = /^\x1b\[([0-9;]*)m/.exec(s.slice(esc));
      if (m) {
        ansiClass = classForSGR(m[1], ansiClass);
        i = esc + m[0].length;
        continue;
      }
      /* No match: either the sequence is still arriving, or it is not an SGR.
         A real one is short, so a long unmatched tail is junk rather than a
         fragment -- dropping the ESC and moving on stops it eating the log. */
      if (s.length - esc < 16) { ansiPending = s.slice(esc); return; }
      i = esc + 1;
    }
  }

  root.getElementById('clear').onclick = () => {
    logEl.textContent = '';
    queued = document.createDocumentFragment();
  };

  /* -- the device's console settings ---------------------------------------- */

  /* Settings the device declares for this panel -- "p": "console" -- shown in
     the toolbar. Log level today. Built by setting-control.js, the same code
     the settings panel's rows are: writing, showing the device's answer,
     greying when the device says why, and staying put when a refresh finds
     nothing structural changed. This panel decides only where they go.

     Fetched when the console opens and when the window comes back, not polled:
     a change made from another browser shows up then. Polling one row every
     four seconds is not worth link the video is competing for.

     A device without the settings module answers 404, and there is simply
     nothing to show. */
  const SETTINGS = '/__bitbang/settings';
  const ctlEl = root.getElementById('ctl');
  const ctx = {
    root, base: SETTINGS, inflight: new Map(), pending: new Map(),
    /* The device asked for a refetch after a write: this panel's only
       declarations are its own, so that is all it refetches. */
    onReload: () => loadControls(),
  };
  let onScreen = [];

  async function loadControls() {
    try {
      const r = await fetch(SETTINGS);
      if (!r.ok) return;
      const next = ((await r.json()).settings || []).filter(s => s.p === 'console');
      /* Values only when nothing structural moved -- which is what keeps a
         refresh on window focus from replacing a dropdown somebody has just
         opened. */
      if (absorb(onScreen, next)) {
        for (const el of ctlEl.children) el._sync?.();
        return;
      }
      onScreen = next;
      ctlEl.textContent = '';
      for (const s of onScreen) ctlEl.appendChild(control(s, ctx));
    } catch (e) { /* nothing to show */ }
  }

  const dec = new TextDecoder();
  let retry = 0;

  /* Where this viewer has read to, so a reconnect resumes instead of replaying.
     Without it every dropped connection re-sent the whole ring and the page
     showed the same output twice. Counted here rather than reported by the
     device: every byte is accounted for, so from + received is exact. */
  let seq = null;

  /* The socket in use, and the retry waiting to replace it. Folding closes the
     one and cancels the other, and every handler below checks it still belongs
     to the current socket: a frame or a close arriving from one that folding
     shut must neither count toward seq -- the resume would then skip it -- nor
     schedule a reconnect behind the fold's back. */
  let ws = null, retryTimer = null;

  function connect() {
    retryTimer = null;
    /* Same URL shape a device page would use. bootstrap turns the path into a
       SWSP SYN of {"type":"console",...}; nothing in the browser below this
       knows what a console is. */
    const q = seq === null ? `tail=${TAIL}` : `since=${seq}`;
    const base = (location.protocol === 'https:' ? 'wss://' : 'ws://') + location.host;
    const sock = new WebSocket(`${base}/__bitbang/console?${q}`);
    ws = sock;
    sock.binaryType = 'arraybuffer';

    sock.onopen = () => { if (sock !== ws) return; retry = 0; say('connected'); };

    sock.onmessage = (ev) => {
      if (sock !== ws) return;
      if (typeof ev.data === 'string') {
        /* The device's SYN reply: what it is about to send and what it could
           not. Shown only when it means something was lost. */
        try {
          const m = JSON.parse(ev.data);
          if (m.from !== undefined) {
            seq = m.from;
            if (m.first_seq > m.from) {
              append(`[${m.first_seq - m.from} bytes older than the buffer are gone]\n`, 'drop');
              seq = m.first_seq;
            }
          }
        } catch (e) {}
        return;
      }
      const b = new Uint8Array(ev.data);
      if (b.length < 1) return;
      const body = b.subarray(1);
      if (b[0] === 0x02) {
        try {
          const m = JSON.parse(dec.decode(body));
          if (m.dropped) {
            append(`\n[${m.dropped} bytes dropped -- viewer fell behind]\n`, 'drop');
            if (seq !== null) seq += m.dropped;
          }
        } catch (e) {}
        return;
      }
      /* History and live render the same; see the note at the top. */
      if (seq !== null) seq += body.length;
      /* stream:true so a multi-byte character split across frames is held
         rather than turned into a replacement character. */
      writeAnsi(dec.decode(body, { stream: true }));
    };

    sock.onclose = () => {
      if (sock !== ws) return;
      ws = null;
      /* Backoff, because a device that is rebooting will refuse for a few
         seconds and hammering it helps nobody. */
      const wait = Math.min(1000 * 2 ** retry++, 15000);
      say(`disconnected -- retrying in ${Math.round(wait / 1000)}s`, true);
      retryTimer = setTimeout(connect, wait);
    };

    sock.onerror = () => { if (sock === ws) say('connection failed', true); };
  }

  /* Folded, nobody is reading, and the stream would only compete with the
     video for the link. Opening resumes from seq, so what was logged in the
     meantime arrives then -- as far back as the device's ring reaches. */
  function disconnect() {
    clearTimeout(retryTimer);
    retryTimer = null;
    const sock = ws;
    ws = null;
    sock?.close();
  }

  let fold = null;
  if (collapsible) {
    fold = foldable({
      host, axis: 'height', name: 'Console',
      fold: root.getElementById('fold'),
      wrap: root.getElementById('fold-wrap'),
      onChange: (folded) => {
        if (folded) { disconnect(); return; }
        retry = 0;
        say('connecting');
        connect();
        loadControls();
      },
    });
  }

  /* Coming back to the window is when another browser's change would show. */
  addEventListener('focus', () => { if (!fold?.isFolded()) loadControls(); });

  if (!fold?.isFolded()) { connect(); loadControls(); }
}

/*
 * Mount into every element that asked, when this module is loaded. A sketch's
 * page asks with one attribute, and bitbang.js loads this file for it:
 *
 *     <div data-bitbang-page="console"></div>
 *     <script src="/__bitbang__/bitbang.js"></script>
 *
 * Give the element a height to set the size of the log; without one it gets
 * the default in STYLE. No title: the page has labelled the area already.
 * data-bitbang-collapsible asks for the fold toggle, opt-in for the reason
 * settings-panel.js gives: whether folding makes sense is a fact about the
 * page's layout, which only the page knows.
 */
function mountDeclared() {
  for (const el of document.querySelectorAll('[data-bitbang-page="console"]')) {
    if (el.shadowRoot) continue;          /* already mounted */
    mount(el, {
      title:       false,
      collapsible: el.hasAttribute('data-bitbang-collapsible'),
    });
  }
}

/* A module script is deferred, so the document is normally parsed by the time
   this runs -- but a page can also import it dynamically, early. */
if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', mountDeclared);
} else {
  mountDeclared();
}
