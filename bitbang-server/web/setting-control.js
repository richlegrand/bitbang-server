/*
 * One setting's control, shared by every panel that shows settings.
 *
 * The settings panel shows a device's settings as rows; the console shows the
 * few that belong to it -- log level -- in its toolbar. Both are the same
 * thing: a control built from a declaration, written through
 * /__bitbang/settings, showing what the device answered, and kept current by a
 * refresh that must never rebuild it under someone's hand. The settings panel
 * paid for each of those lessons separately, and the console's first version
 * relearned one of them -- a refresh on window focus rebuilt its dropdown and
 * closed it a moment after it opened -- while missing two others. So it is
 * written once, here, and a panel decides only where its controls go.
 *
 * Moved out of settings-panel.js on 2026-10-01 with no change in behavior. The
 * comments that explain each decision came with it.
 *
 * In the core rather than either plugin: the console's panel and the
 * settings panel both import it, by relative path from /__bitbang__/.
 */

/* The theme every panel shares. Custom properties pierce a shadow boundary, so
   a page setting --accent on the host -- or anywhere above it -- reaches in,
   while every structural rule stays the panel's. */
export const THEME_CSS = `
  :host {
    --accent: #3b82f6;
    --dim: #8a8a8e;
    --line: #8884;
    --bad: #e5484d;
    --ok: #30a46c;
    accent-color: var(--accent);
  }
`;

/* The controls' own look. A panel adds the layout around them. */
export const CONTROL_CSS = `
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
  .label { flex:0 1 11em; min-width:6em; color:var(--dim); }
  /* A label with a hint says so. Nobody hovers something that looks inert, and
     a dotted underline is the one convention for "there is an explanation
     here" that costs no vertical space -- which matters when the alternative
     was two extra lines on every row. */
  .label.hinted { text-decoration:underline dotted; text-underline-offset:.2em;
                  cursor:help; }
  .ctl { flex:1 1 auto; display:flex; align-items:center; gap:.45rem; flex-wrap:wrap; }

  /* What each kind of control asks for before it would rather have its own line.
     Set here and chosen in control(), where the type is already known, rather
     than inferred back out of the DOM by a selector.

     A checkbox and a button ask for nothing and so never wrap. A select or a
     number fits beside an 11em label in a 300px column. A slider with its value,
     or a text field, does not. */
  .ctl.narrow { min-width:7em; }
  .ctl.wide   { min-width:13em; flex-wrap:nowrap; }

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
  button.danger { border-color:var(--bad); color:var(--bad); }

  /* A note used to lead with "-- ", which was punctuation doing a job the
     layout was already doing: .ctl's gap separates it and the dim smaller type
     says it is an aside. Two separators is one too many, and the dash read as
     part of the sentence the device wrote. */
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
  .state.ok  { color:var(--ok); }
`;

/* Absent `n`, derive from the key: underscores to spaces, first letter up. */
export const label = s => s.n || (s.k.replace(/_/g, ' ').replace(/^./, c => c.toUpperCase()));

/* An aside beside a control: why it is disabled, why it is readonly, that it
   needs a restart, what is pending. Four of these were built a line at a time
   in four places, which is three more places than a span needs. */
export const note = (text) => {
  const el = document.createElement('span');
  el.className = 'note';
  el.textContent = text;
  return el;
};

/*
 * One setting's control: a row of label, control and the device's answer.
 *
 * ctx is what the panel owns, and the only thing the control reaches outside
 * itself for:
 *
 *   root      the shadow root, for which element has focus
 *   base      the settings endpoint
 *   inflight  Map, key -> true while a write is out. One request in flight per
 *   pending   Map, key -> the next body       key: a timer alone still allows
 *             two POSTs for the same setting to be outstanding, and the older
 *             landing last leaves the device holding a stale value with nothing
 *             reporting an error. Owned by the panel so its controls share them.
 *   onRev     a write's reply moved the declaration's revision to this
 *   onReload  the device asked for this group, or everything (null), to be
 *             refetched
 *
 * The returned element carries _sync(): put the setting's current values on
 * the control without rebuilding it. That is what a refresh calls -- see
 * absorb() below.
 */
export function control(s, ctx) {
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
    if (ctx.inflight.get(s.k)) { ctx.pending.set(s.k, body); return; }   // coalesce
    ctx.inflight.set(s.k, true);
    say('...');
    try {
      const r = await fetch(ctx.base, {
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
        /* Our own write moved the revision. Taking it keeps the panel's next
           poll from seeing a number it does not know and refetching the change
           we just made and have already applied. */
        if ('rev' in j) ctx.onRev?.(j.rev);
        if ('v' in j) s.v = j.v;
        if ('set' in j) s.set = j.set;
        if ('pv' in j) s.pv = j.pv; else delete s.pv;
        /* show() rather than reaching for the control, which is what this did
           -- three lines that asked whether input.type was a checkbox and
           wrote .value or .checked accordingly. It had no answer for a radio
           group or for a secret's placeholder, so those two never showed a
           value the device had quantized. The branch that built the nodes
           knows how to put a value on them; nothing else needs to guess. */
        if (show !== null) show();
        if (j.reload) ctx.onReload?.(typeof j.reload === 'string' ? j.reload : null);
      }
    } catch (e) {
      say(String(e), 'err');
    } finally {
      ctx.inflight.delete(s.k);
      const next = ctx.pending.get(s.k);
      if (next) { ctx.pending.delete(s.k); send(next); }
    }
  };

  let input = null, out = null;

  /* Puts s's value on the nodes this row built. Set by whichever branch below
     builds them, because only that branch knows whether the value means
     `.value`, `.checked`, one of three radios, or a placeholder.

     Unconditional on purpose. Whether to overwrite is a different question
     with a different answer depending on who is asking -- a poll must not
     tread on a half-typed field, a write's own reply must -- and the two were
     tangled together in every branch, with the reply path re-deciding it by
     sniffing input.type. */
  let show = null;

  /* Which a refresh asks. Rebuilding replaces the element under the pointer
     and swallows the click -- or closes a dropdown a moment after it opened --
     so a refetch that changed no declaration calls this instead of rebuilding
     anything.

     Two things it must not overwrite: an input somebody is typing in, and a
     key with a write in flight, whose reply is the authority on where the
     value ended up. */
  const sync = () => {
    if (show === null || ctx.inflight.get(s.k)) return;
    if (input !== null && input === ctx.root.activeElement) return;
    show();
  };

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
    show = () => { span.textContent = shown(); };
    ctl.appendChild(span);
    if (typeof s.ro === 'string') {
      ctl.appendChild(note(s.ro));
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
    show = () => { input.checked = !!s.v; };
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
    show = () => { for (const rb of radios) rb.checked = rb.value === s.v; };
  } else if (s.t === 'enum') {
    input = document.createElement('select');
    for (const o of s.o || []) {
      const opt = document.createElement('option');
      opt.value = opt.textContent = o;
      input.appendChild(opt);
    }
    input.value = s.v;
    input.onchange = () => send({ k: s.k, v: input.value });
    show = () => { input.value = s.v; };
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
      show = () => {
        input.value = s.v;
        out.textContent = s.v;
      };
      ctl.append(track, out);
    } else {
      input.onchange = () => send({ k: s.k, v: Number(input.value) });
      show = () => { input.value = s.v; };
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
    /* A secret has no value to show, only whether one is set. Not clobbering
       a half-typed credential is why sync() checks activeElement. */
    show = () => {
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
  /* At the row, not in a banner. */
  if (s.rb) ctl.appendChild(note('after restart'));
  if (s.pv !== undefined) ctl.appendChild(note(`${s.pv} pending`));

  /* -- the device's refine hook, applied once for every type --

     `en:false` greys whatever control this row built and puts the device's
     reason beside it. Done here rather than in each branch because the answer is
     the same shape for a checkbox, a slider and a select, and because `why` is a
     sentence the device wrote -- nothing here decides what it says.

     Advisory, and the device knows it: the setter refuses the same write with
     the same sentence. So a page that has not polled since the condition
     changed shows a live control, and clicking it produces the explanation
     rather than silence. */
  const why = note('');
  const gate = () => {
    const off = s.en === false;
    for (const el of ctl.querySelectorAll('input,select,button')) el.disabled = off;
    why.textContent = off && s.why ? s.why : '';
    /* Hidden is the stronger form and the device has to ask for it by name.
       Greying is preferred: a control that vanishes leaves someone hunting for
       what was there a moment ago, which is what the camera's own panel does. */
    div.style.display = s.hide ? 'none' : '';
  };
  ctl.appendChild(why);

  ctl.appendChild(state);
  div.appendChild(ctl);
  gate();
  /* An action has no value to show, so show stays null -- but every row gates. */
  div._sync = () => { sync(); gate(); };
  return div;
}

/* What _sync can apply to nodes that already exist, so a change in one of
   these is not structural and costs no rebuild. Everything else is the DOM's
   shape: two declarations agreeing on all of it can swap values without a
   node being replaced, which is what sig() below compares.

   `pv` is deliberately outside this set, so a value arriving as pending does
   rebuild: a pending marker appears and disappears as a whole element, which
   is structural however small it looks.

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
   identity so every control's closures stay pointed at live data. False when
   the structure moved and the caller has to rebuild; true when it only has to
   call each control's _sync().

   This is what makes the focus refetch free. Without it, returning to the
   window destroys and recreates every control, and the click that brought focus
   back lands on an element that no longer exists. */
export function absorb(onScreen, next) {
  if (next.length !== onScreen.length) return false;
  for (let i = 0; i < next.length; i++) {
    if (next[i].k !== onScreen[i].k || sig(next[i]) !== sig(onScreen[i])) return false;
  }
  /* Every synced field, copied or removed. Removal matters as much as the copy:
     a control that became available again sends no `en`, and leaving the old
     false behind would keep it greyed with a reason that is no longer true. */
  for (let i = 0; i < next.length; i++) {
    onScreen[i].v = next[i].v;
    for (const k of SYNCED) {
      if (k === 'v') continue;
      if (k in next[i]) onScreen[i][k] = next[i][k]; else delete onScreen[i][k];
    }
  }
  return true;
}
