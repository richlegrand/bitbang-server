/**
 * BitBang's retired service worker
 *
 * bitba.ng's page used to install a worker here that carried every device's
 * requests, with every device's pages in bitba.ng's own origin. Device pages
 * now live in origins of their own, each with its own worker (label-sw.js);
 * bitba.ng's page has none. See bitbang-docs/device-origins.md.
 *
 * Browsers that installed the old worker keep it until it is replaced, so
 * this file replaces it, and then removes itself:
 *
 *   1. It deletes what the old worker stored in this origin. That includes
 *      every device's access code (its session table) and the cookie jar it
 *      kept for all devices together. Unregistering a worker leaves its
 *      storage behind, so this has to be done by hand.
 *   2. It unregisters, so nothing intercepts bitba.ng's requests again.
 *   3. It reloads any tab the old worker was still serving: such a tab is
 *      running the old runtime against a worker that no longer exists, and
 *      its device page has stopped working. The reload brings up the new
 *      runtime.
 *
 * bootstrap.js does steps 1 and 2 as well, from the page, so a browser
 * that never fetches this file is cleaned up too.
 */

// Spliced in by the server as this file is served (handler.buildStamp). A
// page of the old runtime asks for it, finds it is not its own, and offers a
// reload.
const BUILD = '__BB_BUILD__';

// What the old worker kept. Named rather than "every cache in the origin":
// bitba.ng's page keeps nothing in the Cache API now, but a future one might.
const OLD_CACHES = ['bitbang-sessions', 'bitbang-cookies', 'bitbang-active-session'];

self.addEventListener('install', () => self.skipWaiting());

self.addEventListener('activate', (event) => {
    event.waitUntil((async () => {
        await Promise.all(OLD_CACHES.map((name) => caches.delete(name).catch(() => false)));
        // The open tabs are still the old worker's until claimed, and a worker
        // can only navigate tabs it controls.
        await self.clients.claim().catch(() => {});
        await self.registration.unregister();
        const tabs = await self.clients.matchAll({ type: 'window' });
        for (const tab of tabs) {
            // Top-level tabs only: an old device frame goes with its tab.
            if (tab.frameType !== 'top-level' && tab.frameType !== 'auxiliary') continue;
            // Not to tab.url itself: a device tab's URL ends in #<code>, and
            // navigating to the same URL with a fragment is a jump within the
            // page, not a load. A query nobody reads makes it one; bitba.ng's
            // page replaces the address as soon as the device page reports
            // where it is.
            const u = new URL(tab.url);
            u.searchParams.set('bb-retired', '1');
            tab.navigate(u.href).catch(() => {});
        }
        console.log('[SW] retired: storage cleared, unregistered,', tabs.length, 'tab(s) reloaded');
    })());
});

// No fetch handler: everything goes to the network.

self.addEventListener('message', (event) => {
    if (event.data?.type === 'get_build') {
        event.ports[0]?.postMessage({ type: 'build', build: BUILD });
    }
});
