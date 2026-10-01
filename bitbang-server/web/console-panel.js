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

const STYLE = `
  /* :host, not :root, for the reason settings-panel.js gives: these land on
     the host element, and the variables are the override point a sketch has. */
  :host {
    display: flex;
    flex-direction: column;
    min-height: 0;
    color-scheme: light dark;
    --font: ui-monospace, SFMono-Regular, Menlo, Consolas, "Liberation Mono", monospace;
    --dim: #8a8a8e;
    --line: #8884;
    --bad: #e5484d;
    --accent: #3b82f6;
    font: 13px/1.5 var(--font);
  }
  /* Embedded, the log needs a height to scroll inside, and a div in a sketch's
     layout has none unless the sketch gives it one. This is the default; a
     height the page sets on the element wins, since a page's own rule on the
     host outranks :host. The border marks where the scrolling region is. */
  :host([data-bb-embedded]) {
    /* border-box, so a height the page gives the element is its outer height
       rather than that plus the border. */
    box-sizing: border-box;
    height: 18rem;
    border: 1px solid var(--line);
    border-radius: 6px;
  }
  header { display:flex; align-items:center; gap:1rem; flex-wrap:wrap;
           padding:.6rem 1rem; border-bottom:1px solid var(--line); }
  :host([data-bb-embedded]) header { padding:.35rem .75rem; }
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
 * opts.title   the "Console" heading. Default true; the embedded mount passes
 *              false, because the page supplies its own label.
 *
 * Everything below lives in this function rather than at module scope, so two
 * consoles on one page keep their own socket, position and line buffer.
 */
export function mount(host, opts = {}) {
  const title = opts.title !== false;
  if (!title) host.setAttribute('data-bb-embedded', '');

  const root = host.attachShadow({ mode: 'open' });
  const style = document.createElement('style');
  style.textContent = STYLE;
  root.appendChild(style);

  const frag = document.createElement('div');
  frag.innerHTML = `
    <header>
      ${title ? '<h1>Console</h1>' : ''}
      <span id="state">connecting</span>
      <label><input type="checkbox" id="follow" checked> follow</label>
      <button id="clear">Clear</button>
    </header>
    <pre id="log"></pre>`;
  while (frag.firstChild) root.appendChild(frag.firstChild);

  const logEl = root.getElementById('log');
  const stateEl = root.getElementById('state');
  const followEl = root.getElementById('follow');

  const say = (t, bad) => { stateEl.textContent = t; stateEl.className = bad ? 'err' : ''; };

  /* Untrusted by construction: device output is bytes, and the only safe way to
     put bytes on a page is as text. Everything here appends text nodes. */
  function append(text, cls) {
    if (!text) return;
    const atBottom = logEl.scrollHeight - logEl.scrollTop - logEl.clientHeight < 40;
    const node = document.createElement('span');
    if (cls) node.className = cls;
    node.textContent = text;
    logEl.appendChild(node);
    if (followEl.checked && atBottom) logEl.scrollTop = logEl.scrollHeight;
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

  root.getElementById('clear').onclick = () => { logEl.textContent = ''; };

  const dec = new TextDecoder();
  let retry = 0;

  /* Where this viewer has read to, so a reconnect resumes instead of replaying.
     Without it every dropped connection re-sent the whole ring and the page
     showed the same output twice. Counted here rather than reported by the
     device: every byte is accounted for, so from + received is exact. */
  let seq = null;

  function connect() {
    /* Same URL shape a device page would use. bootstrap turns the path into a
       SWSP SYN of {"type":"console",...}; nothing in the browser below this
       knows what a console is. */
    const q = seq === null ? `tail=${TAIL}` : `since=${seq}`;
    const base = (location.protocol === 'https:' ? 'wss://' : 'ws://') + location.host;
    const ws = new WebSocket(`${base}/__bitbang/console?${q}`);
    ws.binaryType = 'arraybuffer';

    ws.onopen = () => { retry = 0; say('connected'); };

    ws.onmessage = (ev) => {
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

    ws.onclose = () => {
      /* Backoff, because a device that is rebooting will refuse for a few
         seconds and hammering it helps nobody. */
      const wait = Math.min(1000 * 2 ** retry++, 15000);
      say(`disconnected -- retrying in ${Math.round(wait / 1000)}s`, true);
      setTimeout(connect, wait);
    };

    ws.onerror = () => say('connection failed', true);
  }

  connect();
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
 */
function mountDeclared() {
  for (const el of document.querySelectorAll('[data-bitbang-page="console"]')) {
    if (el.shadowRoot) continue;          /* already mounted */
    mount(el, { title: false });
  }
}

/* A module script is deferred, so the document is normally parsed by the time
   this runs -- but a page can also import it dynamically, early. */
if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', mountDeclared);
} else {
  mountDeclared();
}
