/*
 * Folding a panel away to just its toggle, shared by the settings panel and
 * the console.
 *
 * Settings folds sideways -- it is a column beside the video, and the video
 * takes the width back. The console folds downward -- it is a row along the
 * bottom of the window, and the page above takes the height back. Same
 * mechanism along a different axis, so it is written once here rather than
 * once in each panel.
 *
 * Folded state lives on the host as data-bb-collapsed, so the page can say
 * what a folded panel does to its own layout -- #side[data-bb-collapsed]
 * {width:auto}, and the video beside it widens -- without the panel knowing
 * what is beside it.
 *
 * In the core rather than either plugin: the console's panel and the
 * settings panel both import it, by relative path from /__bitbang__/.
 */

/* The toggle's look, identical in every panel that folds -- the two buttons sit
   in corners of the same page, and a Settings and a Console that differed in
   size and face would look like they came from different places. So it does
   not inherit: a fixed face, size and width, and the theme variables for
   color, which is the part a page is meant to set. The size is the settings
   panel's own buttons', so the toggle is the same height as Export and Import
   beside it. */
export const FOLD_CSS = `
  #fold { font: 11px/1.3 -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto,
                "Helvetica Neue", Arial, sans-serif;
          width: 7em; padding: .35rem 0; text-align: center;
          color: inherit; background: none; cursor: pointer;
          border: 1px solid var(--line); border-radius: 5px; }
  #fold:hover { border-color: var(--accent); }
  #fold:focus-visible { outline: 2px solid var(--accent); outline-offset: 1px; }
  /* Out of flow the moment it is folded, in the same rule that the page's own
     collapsed size keys off. That matters: while the content is in flow it has a
     size, so a host sized to its content would size itself to that for as long
     as the two were out of step. Nothing here animates; the animation is the
     host's, in apply() below. */
  :host([data-bb-collapsed]) #fold-wrap { display: none; }
`;

const DUR = 220;

/*
 * host     the element the panel is mounted on, which is what moves
 * fold     the toggle button
 * wrap     everything that folds away
 * axis     'width' for a column, 'height' for a row
 * name     what the toggle says when folded ("Settings"), and part of the key
 *          the state is remembered under
 * onChange called with the new state after a click, not for the remembered
 *          state applied at mount -- a panel reads isFolded() for that
 * dock     'end' for a panel docked at the far end of its axis -- the console,
 *          along the bottom of the window -- so it grows and shrinks from that
 *          edge. Omitted, the near edge stays put, which is right for the
 *          settings column on the left.
 *
 * Returns { isFolded }.
 */
export function foldable({ host, fold, wrap, axis, name, onChange, dock }) {
  /* Remembered per viewer and per device, because whether the panel is in the
     way is a fact about this screen rather than about the device. The read is
     wrapped because storage throws in a private window and comes back empty
     after a clear, and a panel that will not render is worse than one that
     forgets which way it was left. */
  const KEY = 'bb-' + name.toLowerCase() + '-folded:' + location.pathname;
  let folded = false;
  try { folded = localStorage.getItem(KEY) === '1'; } catch (e) { /* fine */ }

  /* The state, and only the state. Applying it is one change of one attribute
     and the stylesheet does the rest, so there is never a moment where the
     panel is half in one state and half in the other. */
  const setState = (next) => {
    folded = next;
    host.toggleAttribute('data-bb-collapsed', folded);
    fold.textContent = folded ? name : 'Hide';
    fold.setAttribute('aria-expanded', String(!folded));
    try { localStorage.setItem(KEY, folded ? '1' : '0'); } catch (e) { /* fine */ }
  };

  const stillness = matchMedia('(prefers-reduced-motion: reduce)');
  let anim = null;

  /*
   * What moves is the host, not the content inside it.
   *
   * The first version folded the content away over 220ms and left the size to
   * the page, and it flashed: the attribute that starts the fold is the one the
   * page's collapsed size keys off, so for the length of the animation the host
   * was shrink-to-fit around content that was still in flow -- the settings
   * column sized itself to its widest row and squeezed the video before giving
   * anything back.
   *
   * Measure, then animate. The size the host has now, the size it has in the
   * new state -- both read from a layout that is settled and correct -- and the
   * host moved between the two. The intermediate layout that flashed does not
   * exist any more: the content leaves flow in the same style rule that shrinks
   * the host, so there is no frame where one has happened and the other has
   * not. Nothing in between is painted; `to` is measured and the animation
   * starts before the frame ends.
   *
   * Reading `from` off the current rect rather than remembering where the host
   * started is what makes a click during an animation behave: it carries on
   * from wherever it had reached.
   */
  const apply = (next) => {
    const from = host.getBoundingClientRect()[axis];
    setState(next);
    const to = host.getBoundingClientRect()[axis];
    if (stillness.matches || Math.abs(to - from) < 1) return;

    /* Opening, the content is back in flow and would lay out to each
       intermediate size in turn -- for settings, the rows rewrap all the way
       out. Pinned to the size it has when open and clipped by the host, it
       sits still and the host uncovers it. Closing needs neither: it is
       already out of flow. */
    if (!folded) wrap.style[axis] = wrap.getBoundingClientRect()[axis] + 'px';
    host.style.overflow = 'hidden';

    /* Docked at the far end, the panel has to stay there while it is held to
       the animated size. Opening, the page goes straight to its open layout
       -- the rows above give up the room the console will take -- while the
       console is still small, which leaves room between them; without this
       the console sat at the top of that room and grew down, popping up and
       then dropping, the reverse of how it folds. An auto margin on the near
       side takes the room instead, so the panel stays against its edge and
       grows from it. In ordinary flow an auto margin is nothing, so it only
       acts where there is room to take. For the animation only: settled, the
       panel fills the room and there is none. */
    const nearMargin = axis === 'height' ? 'marginTop' : 'marginLeft';
    if (dock === 'end') host.style[nearMargin] = 'auto';

    /* The min and max animated with the size, all three the same, so the host
       is exactly the animated size whatever the page's layout wants. A page
       can make the host grow into free space -- the camera page's console
       fills whatever height the video leaves -- and a growing box animated by
       its height alone grows to fill straight away and skips the animation;
       a page minimum would do the same in the other direction. */
    const Axis = axis[0].toUpperCase() + axis.slice(1);
    const at = (v) => ({ [axis]: v + 'px', ['min' + Axis]: v + 'px', ['max' + Axis]: v + 'px' });
    anim?.cancel();
    anim = host.animate([at(from), at(to)], { duration: DUR, easing: 'ease' });
    /* No fill, so the size goes back to the stylesheet's when it ends -- which
       is the size just animated to. A cancelled animation leaves the cleanup to
       whichever call cancelled it, since that one is mid-flight and still needs
       the pin and the clipping. */
    anim.finished.then(() => {
      wrap.style[axis] = '';
      host.style.overflow = '';
      if (dock === 'end') host.style[nearMargin] = '';
    }, () => {});
  };

  /* The remembered state, put on directly. apply() is for a change someone is
     watching; this one was decided on a previous visit. */
  setState(folded);

  fold.onclick = () => {
    apply(!folded);
    onChange?.(folded);
  };

  return { isFolded: () => folded };
}
