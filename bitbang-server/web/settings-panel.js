/*
 * The settings panel, as a component rather than a page.
 *
 * Mounted into a shadow root on an element the caller supplies, so it renders
 * two ways from one implementation: `/*settings` standalone, and inside a
 * sketch's own layout through `data-bitbang-page="settings"` on a div.
 *
 * A shadow root and not an iframe. The iframe was the obvious way and its costs
 * were all real: a nested browsing context to size (the box-sizing and
 * height:100% trouble was exactly that), a second scrollbar, and a separate
 * document for something that is one column of rows. A shadow root gives the
 * style isolation that was the only reason to want the iframe, in the host's own
 * layout, with no sizing to negotiate.
 *
 * Not plain injection into a div either. This carries forty lines of CSS keyed on
 * elements a sketch also styles -- input, select, and a host of its own -- and
 * the collisions run both ways. The camera example had a `select{width:110px}`
 * rule until the afternoon its controls became settings. Uncontrolled leakage is
 * a different thing from the deliberate override the variables allow.
 *
 * What does not need solving: the session. A fetch from here resolves against
 * the requesting client's URL, and embedded the client *is* the device page at
 * /__device__/<sid>/..., so `fetch('/__bitbang/settings')` reaches the right
 * device with nothing injected. That is the same reason the settings page worked
 * before ws-shim existed -- see the note in sw.js.
 *
 * Temporary, with settings.html: both move out when the server has plugins.
 */

const STYLE = `
  /* :host, not :root. Inside a shadow root these declarations have to land on
     the host element, and that is also what makes the variables below an
     override point: custom properties pierce a shadow boundary, so a sketch
     setting --accent on the container -- or anywhere above it -- reaches in,
     while every structural rule here stays untouchable. Appearance is the
     sketch's, structure is ours, enforced by the platform rather than by
     agreement. */
  :host {
    display: block;
    color-scheme: light dark;
    /* Conventional stack. system-ui resolves to Cantarell or DejaVu on Linux,
       which is what made this look unlike a settings page. */
    --font: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto,
            "Helvetica Neue", Arial, sans-serif;
    --accent: #3b82f6;
    --dim: #8a8a8e;
    --line: #8884;
    --bad: #e5484d;
    --ok: #30a46c;
    accent-color: var(--accent);
  }
  /* 1.45 rather than 1.6, and half the padding. A settings page is a dense
     list read by someone looking for one row, not prose. The narrow padding
     is what lets this work in a 300px column beside a video. */
  /* On :host too, since there is no body in here. The standalone page sets its
     own background and the host stretches to it; embedded, the sketch decides
     the width and this fills it. */
  :host { font:15px/1.45 var(--font); padding:1.25rem 1rem; max-width:42rem; }
  /* Embedded in a sketch's own layout: it chose the column, so the padding and
     the reading-width cap are its business rather than ours. */
  :host([data-bb-embedded]) { padding:0; max-width:none; }
  h1 { font-size:.8rem; font-weight:600; letter-spacing:.08em; text-transform:uppercase;
       color:var(--dim); margin:0 0 .5rem; }

  #tabs { display:flex; gap:1rem; flex-wrap:wrap; margin-bottom:.9rem; }
  #tabs button { font:inherit; background:none; border:0; padding:0 0 .4rem; cursor:pointer;
                 color:var(--dim); border-bottom:2px solid transparent; }
  #tabs button[aria-selected=true] { color:inherit; border-bottom-color:var(--accent); }
  #tabs button:hover { color:inherit; }

  /* No rules between rows -- spacing separates them, and a settings page that
     is merely calm reads as deliberate. */
  /* A wrapping line, not a grid with a breakpoint.
     
     Each control takes a second line only when it does not fit on the first, and
     the ones that do fit all start at the same x because the label's basis is
     fixed -- so a column of checkboxes and selects lines up while the sliders
     beside them wrap. A breakpoint cannot do that: it moves every row at once,
     at a width somebody guessed.
     
     em and not rem throughout. rem is the document's font size, which a host
     page sets and this cannot see: the camera page picks 12px for the panel, and
     an 11rem label column stayed 176px of a 280px column -- 63% of it, leaving
     about 100px for the control. em tracks whatever size the host chose. */
  .row { display:flex; flex-wrap:wrap; align-items:baseline;
         column-gap:1em; row-gap:.1rem; padding:.28rem 0; }
  .label { flex:0 1 11em; min-width:6em; }
  /* A label with a hint says so. Nobody hovers something that looks inert, and
     a dotted underline is the one convention for "there is an explanation
     here" that costs no vertical space -- which matters when the alternative
     was two extra lines on every row. */
  .label.hinted { text-decoration:underline dotted; text-underline-offset:.2em;
                  cursor:help; }
  .ctl   { flex:1 1 auto; }

  /* What each kind of control asks for before it would rather have its own line.
     Set here and chosen in row(), where the type is already known, rather than
     inferred back out of the DOM by a selector.
     
     A checkbox and a button ask for nothing and so never wrap. A select or a
     number fits beside an 11em label in a 300px column. A slider with its value,
     or a text field, does not. */
  .ctl.narrow { min-width:7em; }
  .ctl.wide   { min-width:13em; flex-wrap:nowrap; }
  /* A heading inside a tab. Quieter than the tab labels above it and louder
     than a row, which is the whole job: 24 rows in one column are navigable
     because of six of these, and they must not read as a second tab bar.
     No rule beneath it -- spacing groups the rows under it, the way spacing
     separates the rows themselves. The first one skips its top margin so a tab
     that opens with a heading does not start with a gap. */
  .section { margin:.75rem 0 .15rem; font-size:.8rem; font-weight:600;
             letter-spacing:.06em; text-transform:uppercase; color:var(--dim); }
  .section:first-child { margin-top:0; }
  .label { color:var(--dim); }
  .ctl { display:flex; align-items:center; gap:.45rem; flex-wrap:wrap; }

  input, select, button.action { font:inherit; color:inherit; background:none;
    border:1px solid var(--line); border-radius:5px; padding:.2rem .45rem; }
  /* Canvas and CanvasText follow color-scheme, so this is right in both
     themes. A transparent select inherits white text while the browser paints
     the option list on its own default background -- white on white until a
     row is highlighted. */
  select, option { background:Canvas; color:CanvasText; }
  input:focus, select:focus, button.action:focus { outline:2px solid var(--accent);
    outline-offset:1px; border-color:transparent; }
  /* Size the control to the value: a port number does not get a full-width box. */
  input[type=number] { width:7rem; text-align:right; }
  input[type=text], input[type=password] { width:100%; max-width:20rem; }
  /* Fills what it is given, up to a comfortable length. The max was 11rem and
     so unrelated to the panel's own scale. */
  input[type=range] { width:100%; max-width:14em; border:0; padding:0; }
  input[type=checkbox], input[type=radio] { width:auto; border:0; padding:0; }
  label { display:inline-flex; align-items:center; gap:.3rem; }

  button.action { cursor:pointer; padding:.35rem .9rem; }
  button.action:hover { border-color:var(--accent); }
  /* Export and import act on the whole device, so they sit with the title
     rather than inside a tab. Restore defaults is per tab and sits with it. */
  /* Its own row now, since the actions outlive the title. Right-aligned so it
     reads as a toolbar rather than as the first setting, and it wraps rather
     than widening the column. */
  #top { display:flex; justify-content:flex-end; gap:.5rem; flex-wrap:wrap;
         font-size:.85em; margin:0 0 .7rem; }
  .foot { margin-top:1rem; padding-top:.7rem; border-top:1px solid var(--line); }
  button.danger { border-color:var(--bad); color:var(--bad); }

  .unit, .bound, .note, .ro { color:var(--dim); font-size:.85em; }
  /* A device URL is 55 characters with no space in it, so it overflows a 280px
     column and takes the layout with it. Broken anywhere rather than truncated,
     because the reason this row exists is to be copied, and you cannot select
     what an ellipsis hid. */
  .ro { overflow-wrap:anywhere; }
  .track { display:inline-flex; align-items:center; gap:.5rem; }
  .value { font-variant-numeric:tabular-nums; margin-left:.4rem; }
  /* The reserved line stops the row jumping when a write answers. Reserved only
     on rows that can be written: a readonly row never has a message, and paying
     a line each for the six on the Device tab is most of a screen in a narrow
     column -- which is where the gap under the URL came from, the empty box
     wrapping onto its own line because the URL had filled the first. */
  .state { font-size:.85em; color:var(--dim); min-height:1.2em; }
  .row.readonly .state { min-height:0; }
  .state.err { color:var(--bad); }
  .state.ok  { color:var(--ok); }`;

/* Two separable pieces, not one "chrome".
 *
 * The title goes when embedded, because the page has already said what this is:
 * a 300px column headed SETTINGS does not want a second Settings inside it.
 *
 * The actions stay. They were dropped alongside the title at first, reasoning
 * that whole-device operations belong on a whole-device page -- which sounded
 * right and was wrong in practice, because the embedded panel is where the work
 * happens, so export and import ended up reachable only by constructing a URL.
 * Two small buttons cost less than that. */
const TITLE = `<h1>Settings</h1>`;

/* Their own row rather than inside the title, since they now outlive it. */
const ACTIONS = `
<div id="top">
  <button class="action" id="export">Export</button>
  <button class="action" id="import">Import</button>
  <input type="file" id="importfile" accept="application/json,.json" hidden>
</div>`;

const PANEL = `
<div id="tabs" role="tablist"></div>
<div id="panel"></div>
<div id="err" class="state err"></div>`;

/*
 * Render into `host`.
 *
 *   opts.title    the "Settings" heading. Default true; the embedded mount
 *                 passes false, because the page supplies its own label.
 *   opts.actions  export and import. Default true everywhere, embedded
 *                 included -- see ACTIONS above for why that changed.
 *
 * Everything below lives in this function rather than at module scope, so two
 * panels on one page would not share `all`, `rev` or the in-flight map. Nothing
 * mounts two today; it costs a closure to not have to remember that.
 */
export function mount(host, opts = {}) {
  const title = opts.title !== false;
  const actions = opts.actions !== false;
  /* Marks the host so the stylesheet can drop the page padding and the reading
     width cap: embedded, the sketch chose the column. */
  if (!title) host.setAttribute('data-bb-embedded', '');

  const root = host.attachShadow({ mode: 'open' });
  const style = document.createElement('style');
  style.textContent = STYLE;
  root.appendChild(style);

  const frag = document.createElement('div');
  frag.innerHTML = (title ? TITLE : '') + (actions ? ACTIONS : '') + PANEL;
  while (frag.firstChild) root.appendChild(frag.firstChild);

  const SRC = new URLSearchParams(location.search).get('src') || '/__bitbang/settings';

  /* Absent `n`, derive from the key: underscores to spaces, first letter up. */
  const label = s => s.n || (s.k.replace(/_/g, ' ').replace(/^./, c => c.toUpperCase()));

  /* One request in flight per key. A timer alone still allows two POSTs for the
     same setting to be outstanding, and the older landing last leaves the device
     holding a stale value with nothing reporting an error. */
  const inflight = new Map(), pending = new Map();

  let current = null;          // selected tab label

  /* The declaration revision the device last reported. Offered back on a poll so
     it can answer "nothing changed" without building 2 KB of JSON and calling
     every getter to do it. Null until the first load.

     `rev` and not `v` because a write's reply is flat and `v` there is the
     setting's value. */
  let rev = null;

  async function load(group) {
    const url = group && SRC.startsWith('/') ? SRC + '?g=' + encodeURIComponent(group) : SRC;
    const r = await fetch(url);
    if (!r.ok) throw new Error(r.status + ' from ' + url);
    const body = await r.json();
    if ('rev' in body) rev = body.rev;
    return body.settings || [];
  }

  /* Ask whether anything changed and fetch only if it did. Returns the new
     settings, or null for "nothing to do".

     Before the first load there is no revision to offer, so this is a plain
     fetch. After that the usual answer is a dozen bytes. */
  async function poll() {
    if (rev === null) return load(null);
    const r = await fetch(`${SRC.split('?')[0]}?rev=${encodeURIComponent(rev)}`);
    if (!r.ok) throw new Error(r.status + ' from ' + SRC);
    const body = await r.json();
    if ('rev' in body) rev = body.rev;
    /* The device sends settings only when they are worth sending. */
    return body.settings || null;
  }

  /* Reads the module-level `all` rather than taking the declarations as an
     argument. It used to take one, and the tab buttons closed over it:
     `render(settings)` inside b.onclick captured whichever array built the bar,
     and the bar is only rebuilt when the set of tab *names* changes. So after
     any `all = ...` replacement -- a range narrowing, a membership change, a
     full refetch -- clicking a tab rendered the original array, while absorb
     went on merging into the new one. The rows on screen were then closed over
     objects nothing updated, so values stopped moving and a Restore defaults
     that the device had honored changed nothing on screen.

     Every caller passed `all` anyway. The parameter bought nothing and could
     only ever disagree with it. */
  async function render() {
    const settings = all;
    const tabs = [...new Set(settings.map(s => s.g || 'Other'))];
    if (!tabs.includes(current)) current = tabs[0];

    /* Rebuild the bar only when the set of tabs actually changes, and update
       the selected state in place otherwise.

       Not an optimization. A re-render triggered between mousedown and mouseup
       replaces the button under the pointer, and a click only fires when both
       land on the same element -- so the first click after a refresh was being
       swallowed by the focus handler's reload, which fires because that click is
       what returns focus to the window. */
    const tabBar = root.getElementById('tabs');
    const shown = [...tabBar.children].map(b => b.textContent);
    const same = shown.length === tabs.length && shown.every((t, i) => t === tabs[i]);
    /* One group means the tab bar is noise. */
    if (!same) {
      tabBar.textContent = '';
      if (tabs.length > 1) {
        for (const t of tabs) {
          const b = document.createElement('button');
          b.textContent = t;
          b.setAttribute('role', 'tab');
          /* render() and not render(settings): a button outlives the array. */
          b.onclick = () => { current = t; render(); };
          tabBar.appendChild(b);
        }
      }
    }
    for (const b of tabBar.children) {
      b.setAttribute('aria-selected', String(b.textContent === current));
    }

    const panel = root.getElementById('panel');
    panel.textContent = '';
    /* A heading wherever `sec` changes from the row before, so the order is the
       device's and nothing is grouped or sorted on its behalf. A row with no
       section sits under no heading, which is how a tab declaring none at all
       renders exactly as it used to. A table alternating between two sections gets
       the heading twice -- the table saying something odd out loud rather than this
       quietly tidying it.

       The tab is still the unit for Restore defaults below. A button per section
       would multiply a control whose whole point is that its scope is obvious from
       where it sits. */
    let shownSection = null;
    for (const s of settings) {
      if ((s.g || 'Other') !== current) continue;
      const sec = s.sec || null;
      if (sec !== shownSection) {
        if (sec !== null) {
          const h = document.createElement('div');
          h.className = 'section';
          h.textContent = sec;
          panel.appendChild(h);
        }
        shownSection = sec;
      }
      panel.appendChild(row(s));
    }

    /* Restore defaults belongs on the tab it applies to. A button's scope
       should be visible from where it sits, and one above the tab bar is not --
       which is how a demo reset that only ever touched three keys read as
       something that would reset the device.

       Offered only when this tab has something to restore: a device tab that
       is all readonly values has no defaults, and a button that would do
       nothing should not be there to press. */
    if (settings.some(s => (s.g || 'Other') === current && s.d !== undefined)) {
      const foot = document.createElement('div');
      foot.className = 'foot';
      const b = document.createElement('button');
      b.className = 'action';
      b.textContent = 'Restore defaults';
      b.onclick = async () => {
        if (!confirm(`Restore the ${current} settings to their defaults?`)) return;
        await resetGroup(current);
      };
      foot.appendChild(b);
      panel.appendChild(foot);
    }
  }

  /* No array parameter. It had one, unused, which shadowed the module-level
     `all` -- the same trap render() just fell into, sitting one function away. */
  function row(s) {
    const div = document.createElement('div');
    div.className = 'row';

    const l = document.createElement('div');
    l.className = 'label';
    l.textContent = label(s);
    /* The browser's own tooltip. No layout, no positioning inside a 300px
       column, and no background color to match against the host -- which the
       styled version would need, and which would be a seventh custom property
       in the contract.
     
       On the row rather than the label, so hovering anywhere across it works,
       including the control. What it does not do is touch: there is no hover
       there, and a tap reveals nothing. That is the known gap, and the fix if
       this proves worth keeping is :focus-within with the hint positioned
       absolutely so it does not shove the rows below it down the column. */
    if (s.hint) {
      div.title = s.hint;
      l.classList.add('hinted');
    }
    div.appendChild(l);

    const ctl = document.createElement('div');
    ctl.className = 'ctl';
    const state = document.createElement('div');
    state.className = 'state';

    const say = (msg, cls) => { state.textContent = msg; state.className = 'state ' + (cls || ''); };

    const send = async (body) => {
      if (inflight.get(s.k)) { pending.set(s.k, body); return; }   // coalesce
      inflight.set(s.k, true);
      say('...');
      try {
        const r = await fetch(SRC.split('?')[0], {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(body),
        });
        const j = await r.json().catch(() => ({}));
        if (!r.ok) {
          /* The error string is the whole guidance -- there is no pattern in the
             declaration a page could have checked first.

             A range used to arrive as separate min and max fields and get
             appended here. The device writes it into the message now, because
             the same dispatch answers callers that have no page to decorate
             anything with. */
          say(j.error || ('HTTP ' + r.status), 'err');
        } else {
          say(j.msg || 'applied', 'ok');
          setTimeout(() => { if (state.textContent === (j.msg || 'applied')) say(''); }, 1500);
          /* Display what came back, not what was sent: a setter may quantize.
             And write it into the declaration, not only into the control --
             switching tabs re-renders from that array, so a DOM-only update
             looks right until you leave the tab and come back to the old
             value. */
          /* Our own write moved the revision. Taking it here keeps the next poll
             from seeing a number it does not know and refetching the change we
             just made and have already applied. */
          if ('rev' in j) rev = j.rev;
          if ('v' in j) s.v = j.v;
          if ('set' in j) s.set = j.set;
          if ('pv' in j) s.pv = j.pv; else delete s.pv;
          if ('v' in j && input && input.type !== 'checkbox') input.value = j.v;
          if ('v' in j && input && input.type === 'checkbox') input.checked = !!j.v;
          if (out) out.textContent = j.v;
          if (j.reload) reload(typeof j.reload === 'string' ? j.reload : null);
        }
      } catch (e) {
        say(String(e), 'err');
      } finally {
        inflight.delete(s.k);
        const next = pending.get(s.k);
        if (next) { pending.delete(s.k); send(next); }
      }
    };

    let input = null, out = null;

    /* Set by each branch to push s's current value into the nodes it built.
       render() rebuilds the panel, which replaces the element under the pointer
       and swallows the click -- the same defect the tab bar above describes, and
       it was fixed there and not here. A refetch that changed no declaration
       calls this instead of rebuilding anything.

       Two things it must not overwrite: an input the person is typing in, and a
       key with a write in flight, whose reply is the authority on what the value
       ended up as. */
    let sync = null;
    const syncable = (el) => el !== root.activeElement && !inflight.get(s.k);

    if (s.ro) {
      /* No message can appear on a row that cannot be written, so it reserves
         no line for one. */
      div.classList.add('readonly');
      const span = document.createElement('span');
      span.className = 'ro';
      /* Text, not a disabled input -- a disabled box reads as broken rather
         than as deliberate. A bool reads as on/off; "false" is not a word
         anyone wants on a settings page. */
      const shown = () =>
        (s.t === 'bool' ? (s.v ? 'on' : 'off') : (s.v ?? '')) + (s.u ? ' ' + s.u : '');
      span.textContent = shown();
      /* The readonly rows are the ones that actually move on their own -- free
         memory, uptime, the address -- so this is the case the focus refetch
         exists for. */
      sync = () => { span.textContent = shown(); };
      ctl.appendChild(span);
      if (typeof s.ro === 'string') {
        const why = document.createElement('span');
        why.className = 'note';
        why.textContent = '-- ' + s.ro;
        ctl.appendChild(why);
      }
    } else if (s.t === 'action') {
      const b = document.createElement('button');
      b.className = 'action' + (s.confirm ? ' danger' : '');
      b.textContent = label(s);
      l.textContent = '';
      b.onclick = () => { if (!s.confirm || confirm(s.confirm)) send({ k: s.k }); };
      ctl.appendChild(b);
    } else if (s.t === 'bool') {
      input = document.createElement('input');
      input.type = 'checkbox';
      input.checked = !!s.v;
      /* No class: a checkbox is 1em wide and never wants a line of its own. */
      input.onchange = () => send({ k: s.k, v: input.checked });
      sync = () => { if (syncable(input)) input.checked = !!s.v; };
      ctl.appendChild(input);
    } else if (s.t === 'enum' && s.r === 'radio') {
      /* Honoring the hint. A client that ignores `r` and renders the select
         below is equally correct -- which is what a terminal does. */
      const name = 'r' + Math.random().toString(36).slice(2);
      const radios = [];
      for (const o of s.o || []) {
        const lab = document.createElement('label');
        const rb = document.createElement('input');
        rb.type = 'radio';
        rb.name = name;
        rb.value = o;
        rb.checked = o === s.v;
        rb.onchange = () => send({ k: s.k, v: o });
        radios.push(rb);
        lab.append(rb, document.createTextNode(' ' + o));
        ctl.appendChild(lab);
      }
      sync = () => {
        if (inflight.get(s.k)) return;
        for (const rb of radios) rb.checked = rb.value === s.v;
      };
    } else if (s.t === 'enum') {
      input = document.createElement('select');
      for (const o of s.o || []) {
        const opt = document.createElement('option');
        opt.value = opt.textContent = o;
        input.appendChild(opt);
      }
      input.value = s.v;
      input.onchange = () => send({ k: s.k, v: input.value });
      sync = () => { if (syncable(input)) input.value = s.v; };
      ctl.classList.add('narrow');
      ctl.appendChild(input);
    } else if (s.t === 'int' || s.t === 'float') {
      const slider = s.r === 'slider' && s.min !== undefined;
      input = document.createElement('input');
      input.type = slider ? 'range' : 'number';
      if (s.min !== undefined) { input.min = s.min; input.max = s.max; }
      if (s.step) input.step = s.step;
      input.value = s.v;
      if (slider) {
        const lo = document.createElement('span'); lo.className = 'bound'; lo.textContent = s.min;
        const hi = document.createElement('span'); hi.className = 'bound'; hi.textContent = s.max;
        out = document.createElement('span');
        out.textContent = s.v;
        /* Debounce on a timer and commit on release: a slow drag can sit inside
           the timer for a long time. */
        let t = null;
        input.oninput = () => {
          out.textContent = input.value;
          clearTimeout(t);
          t = setTimeout(() => send({ k: s.k, v: Number(input.value) }), 300);
        };
        input.onchange = () => { clearTimeout(t); send({ k: s.k, v: Number(input.value) }); };
        /* The bounds travel with the slider; the value stands apart from them,
           or the max bound and the current value read as one number pair. */
        const track = document.createElement('span');
        track.className = 'track';
        track.append(lo, input, hi);
        out.className = 'value';
        /* The track and its value are one thing: the row wraps around them
           rather than the number dropping below the slider. */
        ctl.classList.add('wide');
        /* The readout is part of the value, so it moves with it. Skipped while
           the slider is being dragged, which is what activeElement catches. */
        sync = () => {
          if (!syncable(input)) return;
          input.value = s.v;
          out.textContent = s.v;
        };
        ctl.append(track, out);
      } else {
        input.onchange = () => send({ k: s.k, v: Number(input.value) });
        sync = () => { if (syncable(input)) input.value = s.v; };
        ctl.classList.add('narrow');
        ctl.appendChild(input);
        if (s.min !== undefined) {
          const b = document.createElement('span');
          b.className = 'bound';
          b.textContent = `${s.min}-${s.max}`;
          ctl.appendChild(b);
        }
      }
    } else {                                    /* str */
      input = document.createElement('input');
      input.type = s.secret ? 'password' : 'text';
      if (s.maxlen) input.maxLength = s.maxlen;
      const place = () => (s.set ? 'set -- leave blank to keep' : 'not set');
      if (s.secret) {
        input.placeholder = place();
      } else {
        input.value = s.v ?? '';
      }
      input.onchange = () => {
        if (s.secret && input.value === '') return;
        send({ k: s.k, v: input.value });
      };
      /* A secret has no value to sync, only whether one is set. Not clobbering
         a half-typed credential is the reason syncable checks activeElement. */
      sync = () => {
        if (!syncable(input)) return;
        if (s.secret) input.placeholder = place();
        else input.value = s.v ?? '';
      };
      ctl.classList.add('wide');
      ctl.appendChild(input);
    }

    if (s.u && !s.ro) {
      const u = document.createElement('span');
      u.className = 'unit';
      u.textContent = s.u;                      /* beside the value, not in the label */
      ctl.appendChild(u);
    }
    if (s.rb) {
      const n = document.createElement('span');
      n.className = 'note';
      n.textContent = '-- after restart';   /* at the row, not in a banner */
      ctl.appendChild(n);
    }
    if (s.pv !== undefined) {
      const n = document.createElement('span');
      n.className = 'note';
      n.textContent = `-- ${s.pv} pending`;
      ctl.appendChild(n);
    }

    /* -- the device's refine hook, applied once for every type --

       `en:false` greys whatever control this row built and puts the device's
       reason beside it. Done here rather than in each branch because the answer is
       the same shape for a checkbox, a slider and a select, and because `why` is a
       sentence the device wrote -- nothing here decides what it says.

       Advisory, and the device knows it: the setter refuses the same write with
       the same sentence. So a page that has not polled since the condition
       changed shows a live control, and clicking it produces the explanation
       rather than silence. */
    const why = document.createElement('span');
    why.className = 'note';
    const gate = () => {
      const off = s.en === false;
      for (const el of ctl.querySelectorAll('input,select,button')) el.disabled = off;
      why.textContent = off && s.why ? '-- ' + s.why : '';
      /* Hidden is the stronger form and the device has to ask for it by name.
         Greying is preferred: a control that vanishes leaves someone hunting for
         what was there a moment ago, which is what the camera's own panel does. */
      div.style.display = s.hide ? 'none' : '';
    };
    ctl.appendChild(why);

    ctl.appendChild(state);
    div.appendChild(ctl);
    gate();
    /* An action has no value, so its sync may be null -- but every row gates. */
    div._sync = () => { if (sync) sync(); gate(); };
    return div;
  }

  /* Everything the DOM's shape depends on, which is everything but the value.
     Two declarations with the same signature can swap values without a node
     being replaced.

     `pv` is in here rather than treated as a value: a pending marker appears and
     disappears as a whole element, so a change in it is structural. That means a
     value arriving as pending still rebuilds -- rare enough to accept, and
     honest about which case is handled. */
  /* What _sync can apply to nodes that already exist, so a change in one of these
     is not structural and costs no rebuild.

     `en`, `why` and `hide` come from the device's refine hook and move at runtime:
     toggling automatic gain disables the manual one. Disabling an input and
     putting a reason beside it are properties of a node, not a reason for a new
     one -- and rebuilding is what swallows a click mid-press, so keeping these out
     of the signature is what makes a conditional control cheap.

     min, max and step are deliberately *not* here even though refine can move
     them. They are attributes of a live input, but a slider's bound labels travel
     with them, and the case that moves a range is a mode change -- a deliberate,
     rare click where a rebuild costs nothing. */
  const SYNCED = new Set(['v', 'set', 'en', 'why', 'hide']);

  function sig(s) {
    const o = {};
    for (const k of Object.keys(s).sort()) {
      if (SYNCED.has(k)) continue;
      o[k] = s[k];
    }
    return JSON.stringify(o);
  }

  /* Fold a refetch into the declarations already on screen, keeping their object
     identity so every row's closures stay pointed at live data. False when the
     structure moved and the caller has to rebuild.

     This is what makes the focus refetch free. Without it, returning to the
     window destroys and recreates every row, and the click that brought focus
     back lands on an element that no longer exists. */
  function absorb(next, group) {
    const mine = group ? all.filter(s => (s.g || 'Other') === group) : all;
    if (next.length !== mine.length) return false;
    for (let i = 0; i < next.length; i++) {
      if (next[i].k !== mine[i].k || sig(next[i]) !== sig(mine[i])) return false;
    }
    /* Every synced field, copied or removed. Removal matters as much as the copy:
       a control that became available again sends no `en`, and leaving the old
       false behind would keep it greyed with a reason that is no longer true. */
    for (let i = 0; i < next.length; i++) {
      mine[i].v = next[i].v;
      for (const k of SYNCED) {
        if (k === 'v') continue;
        if (k in next[i]) mine[i][k] = next[i][k]; else delete mine[i][k];
      }
    }
    return true;
  }

  function syncRows() {
    for (const el of root.getElementById('panel').children) {
      if (el._sync) el._sync();
    }
  }

  /* -- restore, export, import ------------------------------------------- */

  const note = (msg, cls) => {
    const el = root.getElementById('err');
    el.textContent = msg;
    el.className = 'state ' + (cls || '');
  };

  /* The device answers a reset with the re-read declaration, because every
     value on the tab just changed -- so this needs no follow-up fetch. */
  async function resetGroup(group) {
    try {
      const r = await fetch(`${SRC.split('?')[0]}?reset&g=${encodeURIComponent(group)}`,
                            { method: 'POST' });
      if (!r.ok) throw new Error('HTTP ' + r.status);
      /* ?reset replies with a declaration for the group, which is the same
         {settings: [...]} envelope a GET returns -- not a bare array. This read
         the body as the array and died on part.map, because nothing exercised
         it: the mock never implemented ?reset, and until log_level declared a
         default the only tab with this button was one nobody pressed.

         Checked rather than defaulted to []. An || [] here would turn the next
         shape change into a no-op that still reported success. */
      const part = (await r.json()).settings;
      if (!Array.isArray(part)) throw new Error('reset: unexpected reply');

      /* The reply covers this tab, and a reset can move settings on others: a
         mode returning to its default narrows or widens a range somewhere else
         through that setting's refine hook. The device says nothing about those --
         ?reset answers with the group it was asked about and carries no reload
         hint -- so a page that merged only this tab kept stale rows elsewhere and
         had no way to know.

         So refetch everything. A reset is a deliberate and rare click, one full
         fetch is always correct, and this replaces a partial merge that also got
         the ordering wrong. `part` goes unused beyond the shape check, which is
         worth keeping: it is what catches the reply changing shape. */
      await reload(null);
      note(`${group} restored to defaults`, 'ok');
    } catch (e) {
      note(String(e), 'err');
    }
  }

  /* Readonly values are in the document on purpose -- the URL, the address, the
     firmware it was running. Import ignores them; a person reading the file
     later will not. */
  async function exportSettings() {
    try {
      const r = await fetch(`${SRC.split('?')[0]}?export`);
      if (!r.ok) throw new Error('HTTP ' + r.status);
      const text = JSON.stringify(await r.json(), null, 2);
      const url = URL.createObjectURL(new Blob([text], { type: 'application/json' }));
      const a = document.createElement('a');
      a.href = url;
      a.download = 'settings.json';
      a.click();
      /* Revoked on a turn of the event loop rather than immediately: the click
         is asynchronous and revoking first can race the download. */
      setTimeout(() => URL.revokeObjectURL(url), 10000);
      note('exported', 'ok');
    } catch (e) {
      note(String(e), 'err');
    }
  }

  async function importSettings(file) {
    try {
      const text = await file.text();
      JSON.parse(text);                 /* fail here, not on the device */
      const r = await fetch(`${SRC.split('?')[0]}?import`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: text,
      });
      const j = await r.json().catch(() => ({}));
      if (!r.ok) throw new Error(j.error || ('HTTP ' + r.status));
      await reload(null);
      /* Skipped is worth naming rather than hiding: a range that narrowed
         between firmwares makes a once-valid value invalid, and that is
         information. Readonly keys are not counted -- they were never
         importable and the device knows it. */
      note(j.skipped
             ? `imported ${j.applied}, skipped ${j.skipped}`
             : `imported ${j.applied}`,
           j.skipped ? 'err' : 'ok');
    } catch (e) {
      note(String(e), 'err');
    }
  }

  /* A scoped reload is an optimization, not a mechanism: fetching everything is
     always correct, which is what a first implementation and every terminal
     client should do. */
  async function reload(group) {
    try {
      const part = await load(group);
      /* Values only, no rebuild -- which is the common case, since a refetch
         usually finds the same firmware declaring the same things. */
      if (absorb(part, group)) { syncRows(); return; }
      if (group) {
        /* Replaced in place, not filtered and appended. Appending moved the
           refetched tab to the end of `all`, so the tab bar reordered itself under
           whoever was looking at it, and the next full fetch found `all` in a
           different order than the device's -- which defeats absorb's
           index-aligned compare and rebuilds every row from then on. The symptom
           was a tab that worked until another tab had been reset.

           A membership change is not expressible in place, so it falls through to
           fetching the whole declaration, where the device's order is the
           answer. */
        const fresh = new Map(part.map(s => [s.k, s]));
        const merged = all.map(s => {
          const n = fresh.get(s.k);
          if (n === undefined) return s;
          fresh.delete(s.k);
          return n;
        });
        if (fresh.size > 0) { all = await load(null); render(); return; }
        all = merged;
      } else {
        all = part;
      }
      render();
    } catch (e) {
      root.getElementById('err').textContent = String(e);
    }
  }

  let all = [];
  (async () => {
    try {
      all = await load(null);
      render();
    } catch (e) {
      /* Names the two things that are actually wrong when this fires: no session
         to carry the request, or a device that has settings switched off. The
         old text sent people to a mock file, which told them nothing about
         their device and no longer exists. */
      root.getElementById('err').textContent =
        String(e) + ' -- no answer from the device. Check that it is connected '
        + 'and that this build has the settings module enabled.';
    }
  })();

  /* Values move without us: another admin edits, an action lands late. Refetch
     when the window comes back rather than polling. */
  /* Present unless the caller said otherwise. */
  if (actions) {
    root.getElementById('export').onclick = exportSettings;
    root.getElementById('import').onclick = () =>
      root.getElementById('importfile').click();
    root.getElementById('importfile').onchange = (e) => {
      const f = e.target.files[0];
      /* Cleared so choosing the same file twice fires change again, which is
         what someone editing a file and re-importing expects. */
      e.target.value = '';
      if (f) importSettings(f);
    };
  }

  /* Returning to the window fetches everything, unconditionally. Always correct,
     and the one moment where being sure costs less than being clever. */
  addEventListener('focus', () => reload(null));

  /* -- keeping up while the page is just sitting there -------------------- */

  /* Another admin writes a setting, or the device changes one itself, and this
     page should not go on showing the old value until someone clicks on it.

     Visibility rather than focus: a settings page open beside the thing it
     configures is visible and unfocused for most of its life, which is exactly
     when it should be keeping up. Hidden, it stops entirely -- a background tab
     is not worth a packet on a link where the console contends with video.

     Two shapes, and the tab decides which:

     - a tab with a `live` value on it (uptime, free memory, the address) fetches
       that group, because nothing bumps the revision for a value nobody wrote,
       and a revision check would show it frozen at page load;
     - every other tab asks whether the revision moved, and is told no in about
       a dozen bytes.

     So one request per tick either way, and on the tabs where nothing is
     happening the device does not build a declaration to say so. */
  const POLL_MS = 4000;

  function tabHasLive(group) {
    return all.some(s => (s.g || 'Other') === group && s.live);
  }

  async function tick() {
    if (document.visibilityState !== 'visible') return;
    try {
      if (tabHasLive(current)) {
        /* A real fetch of this tab. reload() absorbs it without replacing nodes
           when the declaration is unchanged, which is the usual case -- so a
           counter ticking up does not rebuild the row it sits in. */
        await reload(current);
        return;
      }
      const next = await poll();
      if (!next) return;                       /* revision unmoved */
      if (absorb(next, null)) { syncRows(); return; }
      all = next;
      render();
    } catch (e) {
      /* Quiet on purpose. A failed poll is not worth a red line in the corner of
         a page that is otherwise fine; the next tick tries again, and a device
         that is really gone shows up the moment someone touches a control. */
    }
  }

  setInterval(tick, POLL_MS);
  /* Coming back from hidden, catch up now rather than waiting out the interval. */
  document.addEventListener('visibilitychange', () => {
    if (document.visibilityState === 'visible') tick();
  });
}

/*
 * Mount into every element that asked, when this module is loaded.
 *
 * So a sketch's page is one line of markup and one of script:
 *
 *     <div data-bitbang-page="settings"></div>
 *     <script type="module" src="/__bitbang__/settings-panel.js"></script>
 *
 * Here rather than in an injected shim, which is where this first went. The
 * service worker injects ws-shim and xhr-shim because those replace
 * window.WebSocket and window.fetch and have to run before the page's own
 * script -- there is no other way to do it. Nothing about this is like that: it
 * is an ordinary module that talks to the device over fetch, and any script tag
 * can load it.
 *
 * The stream library is injected for a different reason again, and one that does
 * not transfer: injection means a device already in the field renders new codecs
 * without being reflashed. A panel needs data-bitbang-page in the page's HTML,
 * which only firmware someone reflashed has -- and the same reflash could have
 * added this script tag. So injection would buy nothing here and would cost a
 * request on every device page, including the ones that want no panel.
 *
 * Explicit mount() is still exported, for a page that wants to choose the moment
 * or pass title:true. This is the convenient case, not the only one.
 */
function mountDeclared() {
    for (const el of document.querySelectorAll('[data-bitbang-page]')) {
        const name = el.getAttribute('data-bitbang-page');
        /* One module, one panel it knows how to be. A page asking for a console
           here is asking the wrong file, and saying so beats rendering settings
           under the wrong heading. */
        if (name !== 'settings') {
            console.error(`[settings] this module renders "settings", not "${name}"`);
            continue;
        }
        if (el.shadowRoot) continue;          /* already mounted */
        /* No title: the page has already labelled the column. Actions stay,
           which is the default -- this is where the work happens, so making
           export and import need a hand-built URL was the wrong call.
           data-bitbang-omit="actions" turns them off for a page that wants the
           column bare. */
        const omit = (el.getAttribute('data-bitbang-omit') || '').split(/\s+/);
        mount(el, { title: false, actions: omit.indexOf('actions') < 0 });
    }
}

/* A module script is deferred, so the document is normally parsed by the time
   this runs. The check is for a page that imports it dynamically and early. */
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', mountDeclared);
} else {
    mountDeclared();
}
