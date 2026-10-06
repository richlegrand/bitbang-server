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
 * The settings plugin's, with settings.html; both listed in plugin.json.
 */

import { foldable, FOLD_CSS } from './panel-fold.js';
import { control, absorb, THEME_CSS, CONTROL_CSS } from './setting-control.js';

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
    /* The colors are setting-control.js's THEME_CSS, shared with the console. */
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

  /* The rows themselves -- label, control, the device's answer -- are styled
     by setting-control.js's CONTROL_CSS, shared with the console. */

  /* A heading inside a tab. Quieter than the tab labels above it and louder
     than a row, which is the whole job: 24 rows in one column are navigable
     because of six of these, and they must not read as a second tab bar.
     No rule beneath it -- spacing groups the rows under it, the way spacing
     separates the rows themselves. The first one skips its top margin so a tab
     that opens with a heading does not start with a gap. */
  .section { margin:.75rem 0 .15rem; font-size:.8rem; font-weight:600;
             letter-spacing:.06em; text-transform:uppercase; color:var(--dim); }
  .section:first-child { margin-top:0; }

  /* Export and import act on the whole device, so they sit with the title
     rather than inside a tab. Restore defaults is per tab and sits with it. */
  /* Its own row now, since the actions outlive the title. Right-aligned so it
     reads as a toolbar rather than as the first setting, and it wraps rather
     than widening the column. */
  #top { display:flex; justify-content:flex-end; gap:.5rem; flex-wrap:wrap;
         align-items:center; font-size:.85em; margin:0 0 .7rem; }
  /* The toggle to the left of the actions, so omitting them does not move it. */
  #fold { margin-right:auto; }
  /* Folded, the row is the whole panel, and export and import are not what a
     strip is for -- they would widen it and act on settings nobody can see.
     They are one click away, which is the click that already happened. */
  :host([data-bb-collapsed]) #top > .action:not(#fold) { display:none; }
  :host([data-bb-collapsed]) #top { margin-bottom:0; }
  /* The toggle's own look, and the rule that takes the rows out of flow when
     folded, are in panel-fold.js's FOLD_CSS, shared with the console. */
  .foot { margin-top:1rem; padding-top:.7rem; border-top:1px solid var(--line); }`;

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
  <button class="action" id="export">Export</button>
  <button class="action" id="import">Import</button>
  <input type="file" id="importfile" accept="application/json,.json" hidden>`;

/* The toggle sits in that same row, which is the one part that does not
   collapse -- put it inside the folding region and it folds away with
   everything else, leaving nothing to press. Left, so it keeps its place when
   the actions beside it are omitted. */
const TOGGLE = `<button class="action" id="fold" aria-expanded="true">Hide</button>`;

/* Everything but the toggle row lives in one wrapper, so folding is one rule
   about one element rather than three about three. */
const PANEL = `
<div id="fold-wrap">
  <div id="tabs" role="tablist"></div>
  <div id="panel"></div>
  <div id="err" class="state err"></div>
</div>`;

/*
 * Render into `host`.
 *
 *   opts.title    the "Settings" heading. Default true; the embedded mount
 *                 passes false, because the page supplies its own label.
 *   opts.actions  export and import. Default true everywhere, embedded
 *                 included -- see ACTIONS above for why that changed.
 *   opts.collapsible
 *                 a toggle that puts everything below it away, leaving the
 *                 toggle. Default false. The host gets data-bb-collapsed while
 *                 folded; the page says what that is worth in width, and this
 *                 animates the host between the two.
 *
 * Everything below lives in this function rather than at module scope, so two
 * panels on one page would not share `all`, `rev` or the in-flight map. Nothing
 * mounts two today; it costs a closure to not have to remember that.
 */
export function mount(host, opts = {}) {
  const title = opts.title !== false;
  const actions = opts.actions !== false;
  const collapsible = opts.collapsible === true;
  /* Marks the host so the stylesheet can drop the page padding and the reading
     width cap: embedded, the sketch chose the column. */
  if (!title) host.setAttribute('data-bb-embedded', '');

  const root = host.attachShadow({ mode: 'open' });
  const style = document.createElement('style');
  /* The shared pieces first, so this panel's own rules can refine them. */
  style.textContent = THEME_CSS + CONTROL_CSS + STYLE + FOLD_CSS;
  root.appendChild(style);

  const frag = document.createElement('div');
  /* One row holds the toggle and the actions, and exists if either does. */
  const top = (collapsible ? TOGGLE : '') + (actions ? ACTIONS : '');
  frag.innerHTML = (title ? TITLE : '')
                 + (top ? `<div id="top">${top}</div>` : '')
                 + PANEL;
  while (frag.firstChild) root.appendChild(frag.firstChild);

  const SRC = new URLSearchParams(location.search).get('src') || '/__bitbang/settings';
  /* SRC without any query it arrived with, which is what everything but load()
     wants: a POST body, ?rev, ?reset, ?export and ?import all put their own
     query on. Written out as SRC.split('?')[0] at five call sites, where it read
     as five separate small decisions rather than one. */
  const BASE = SRC.split('?')[0];

  /* One request in flight per key. A timer alone still allows two POSTs for the
     same setting to be outstanding, and the older landing last leaves the device
     holding a stale value with nothing reporting an error. */
  const inflight = new Map(), pending = new Map();

  /* What every row reaches outside itself for -- see control() in
     setting-control.js. Arrow functions, so they read `rev` and reload() at
     the time of the call rather than when this was built. */
  const ctx = {
    root, base: BASE, inflight, pending,
    onRev: (r) => { rev = r; },
    onReload: (group) => reload(group),
  };

  let current = null;          // selected tab label
  let fold = null;             // the fold, when opts.collapsible

  /* The declaration revision the device last reported. Offered back on a poll so
     it can answer "nothing changed" without building 2 KB of JSON and calling
     every getter to do it. Null until the first load.

     `rev` and not `v` because a write's reply is flat and `v` there is the
     setting's value. */
  let rev = null;

  /* Only the settings this panel renders. A setting can name another panel in
     "p" -- log level is "console", a control on the log it changes -- and is
     then that panel's to show. Applied wherever a declaration arrives, not just
     the first load: a partial refetch that kept a setting `all` had dropped
     would look like a new one every time, and send absorb() for a full reload
     on every poll. */
  const mine = (list) => list.filter(s => !s.p || s.p === 'settings');

  async function load(group) {
    const url = group && SRC.startsWith('/') ? SRC + '?g=' + encodeURIComponent(group) : SRC;
    const r = await fetch(url);
    if (!r.ok) throw new Error(r.status + ' from ' + url);
    const body = await r.json();
    if ('rev' in body) rev = body.rev;
    return mine(body.settings || []);
  }

  /* Ask whether anything changed and fetch only if it did. Returns the new
     settings, or null for "nothing to do".

     Before the first load there is no revision to offer, so this is a plain
     fetch. After that the usual answer is a dozen bytes. */
  async function poll() {
    if (rev === null) return load(null);
    const r = await fetch(`${BASE}?rev=${encodeURIComponent(rev)}`);
    if (!r.ok) throw new Error(r.status + ' from ' + SRC);
    const body = await r.json();
    if ('rev' in body) rev = body.rev;
    /* The device sends settings only when they are worth sending. */
    return body.settings ? mine(body.settings) : null;
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
      panel.appendChild(control(s, ctx));
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

  function syncRows() {
    for (const el of root.getElementById('panel').children) {
      if (el._sync) el._sync();
    }
  }

  /* -- restore, export, import ------------------------------------------- */

  /* The one line under the panel, for what a whole-panel action did. Called
     banner and not note because note() in setting-control.js builds the asides
     beside a control, and two different things under one name is one name too
     few. */
  const banner = (msg, cls) => {
    const el = root.getElementById('err');
    el.textContent = msg;
    el.className = 'state ' + (cls || '');
  };

  /* The device answers a reset with the re-read declaration, because every
     value on the tab just changed -- so this needs no follow-up fetch. */
  async function resetGroup(group) {
    try {
      const r = await fetch(`${BASE}?reset&g=${encodeURIComponent(group)}`,
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
      banner(`${group} restored to defaults`, 'ok');
    } catch (e) {
      banner(String(e), 'err');
    }
  }

  /* Readonly values are in the document on purpose -- the URL, the address, the
     firmware it was running. Import ignores them; a person reading the file
     later will not. */
  async function exportSettings() {
    try {
      const r = await fetch(`${BASE}?export`);
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
      banner('exported', 'ok');
    } catch (e) {
      banner(String(e), 'err');
    }
  }

  async function importSettings(file) {
    try {
      const text = await file.text();
      JSON.parse(text);                 /* fail here, not on the device */
      const r = await fetch(`${BASE}?import`, {
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
      banner(j.skipped
             ? `imported ${j.applied}, skipped ${j.skipped}`
             : `imported ${j.applied}`,
           j.skipped ? 'err' : 'ok');
    } catch (e) {
      banner(String(e), 'err');
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
      const onScreen = group ? all.filter(s => (s.g || 'Other') === group) : all;
      if (absorb(onScreen, part)) { syncRows(); return; }
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

  /* Folds sideways: a column beside the video, which takes the width back.
     The mechanism is panel-fold.js's, shared with the console. */
  if (collapsible) {
    fold = foldable({
      host, axis: 'width', name: 'Settings',
      fold: root.getElementById('fold'),
      wrap: root.getElementById('fold-wrap'),
      /* Opening is when the values are most likely stale, since the poll has
         been off for as long as it was shut. */
      onChange: (folded) => { if (!folded) tick(); },
    });
  }

  /* Values move without us: another admin edits, an action lands late. Refetch
     when the window comes back rather than polling.

     Returning to the window fetches everything, unconditionally. Always correct,
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
    /* Folded is not merely invisible, it is uninteresting: polling the device
       every four seconds to refresh rows nobody can see spends link the video is
       competing for. visibilityState cannot see this -- that is the tab's, and
       the tab is perfectly visible. */
    if (fold?.isFolded()) return;
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
      if (absorb(all, next)) { syncRows(); return; }
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
 * So a sketch's page is one line of markup and one of script, the script being
 * bitbang.js, which loads this file because the page has the element:
 *
 *     <div data-bitbang-page="settings"></div>
 *     <script src="/__bitbang__/bitbang.js"></script>
 *
 * Naming settings-panel.js in the tag instead would work today and break the
 * day this file is renamed, which bitbang.js exists so that it can be.
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
    /* Only its own: a page can carry a console too, which console-panel.js
       mounts, and a name nothing renders is reported by bitbang.js. */
    for (const el of document.querySelectorAll('[data-bitbang-page="settings"]')) {
        if (el.shadowRoot) continue;          /* already mounted */
        /* No title: the page has already labelled the column. Actions stay,
           which is the default -- this is where the work happens, so making
           export and import need a hand-built URL was the wrong call.
           data-bitbang-omit="actions" turns them off for a page that wants the
           column bare. */
        const omit = (el.getAttribute('data-bitbang-omit') || '').split(/\s+/);
        /* Opt in, because folding is a claim about the page's layout that this
           cannot check: it is right when the panel is a column beside something
           worth seeing, and silly when the panel is the page. The element that
           asks is the one that knows, and it costs the page one attribute. */
        mount(el, {
            title:       false,
            actions:     omit.indexOf('actions') < 0,
            collapsible: el.hasAttribute('data-bitbang-collapsible'),
        });
    }
}

/* A module script is deferred, so the document is normally parsed by the time
   this runs. The check is for a page that imports it dynamically and early. */
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', mountDeclared);
} else {
    mountDeclared();
}
