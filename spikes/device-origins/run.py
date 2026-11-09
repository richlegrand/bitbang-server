import asyncio, sys, time
from playwright.async_api import async_playwright

TOP = 'http://bb.localhost:8800/?uid=device-one'
RESTARTS = int(sys.argv[2]) if len(sys.argv) > 2 else 10

def ok(cond, what, detail=''):
    print(('  PASS ' if cond else '  FAIL ') + what + (('  [' + detail + ']') if detail else ''))
    return cond

async def frame_text(pg):
    f = pg.frame_locator('#f')
    return await f.locator('#t').inner_text(timeout=8000)

async def expect(pg, want, what):
    f = pg.frame_locator('#f')
    try:
        await f.locator('#t', has_text=want).wait_for(timeout=8000)
        return ok(True, what)
    except Exception:
        try: got = await frame_text(pg)
        except Exception as e: got = 'unreadable: ' + str(e)[:80]
        return ok(False, what, 'got ' + got)

async def run(name):
    async with async_playwright() as p:
        bt = getattr(p, name)
        kw = {}
        if name == 'firefox':
            # Make Firefox stop idle workers after 1 s, so restarts happen.
            kw['firefox_user_prefs'] = {
                'dom.serviceWorkers.idle_timeout': 1000,
                'dom.serviceWorkers.idle_extended_timeout': 1000,
            }
        b = await bt.launch(**kw)
        ctx = await b.new_context()
        pg = await ctx.new_page()
        pg.on('console', lambda m: m.type == 'error' and print('    console error:', m.text[:160]))
        print(f'== {name}')

        # -- first visit: no worker yet, so the loader installs one --
        t0 = time.time()
        await pg.goto(TOP)
        await expect(pg, 'ROOT', 'first visit loads the device page')
        first = await pg.evaluate('stats.navs.length ? stats.navs[stats.navs.length-1].ms : -1')
        print(f'    first visit: {first} ms from iframe src to device page load '
              f'(wall {int((time.time()-t0)*1000)} ms incl. top page)')
        fr = pg.frames[1]
        ok('.bb.localhost:8800' in fr.url, 'iframe is on a label origin', fr.url)

        # -- second visit: worker already installed --
        await pg.reload()
        await expect(pg, 'ROOT', 'second visit loads')
        second = await pg.evaluate('stats.navs.length ? stats.navs[stats.navs.length-1].ms : -1')
        print(f'    second visit: {second} ms from iframe src to device page load')

        f = pg.frame_locator('#f')
        # -- navigation cases --
        await f.locator('#l-b').click(); await expect(pg, 'B', 'link to /b')
        await pg.go_back() if False else await pg.evaluate('history.back()')
        await expect(pg, 'ROOT', 'back to /')
        await pg.evaluate('history.forward()')
        await expect(pg, 'B', 'forward to /b')
        await f.locator('#l-root').click(); await expect(pg, 'ROOT', 'link to / (short path)')
        await f.locator('#l-settings').click(); await expect(pg, 'SETTINGS', 'link to /*settings')
        await pg.evaluate('history.back()'); await expect(pg, 'ROOT', 'back from /*settings')
        await pg.evaluate('history.forward()'); await expect(pg, 'SETTINGS', 'forward to /*settings')
        await f.locator('#l-root').click(); await expect(pg, 'ROOT', 'root again')
        await f.locator('#l-b').click(); await expect(pg, 'B', 'to /b')
        await f.locator('#jsnav').click(); await expect(pg, 'ROOT', 'script navigation location.href = "/"')
        await f.locator('#l-deep').click(); await expect(pg, 'DEEP /x/y/z?q=1', 'deep path with query')
        await pg.evaluate('history.back()'); await expect(pg, 'ROOT', 'back from deep path')

        # -- form post, redirect, cookies --
        await f.locator('#fb').click()
        try:
            await f.locator('#ck', has_text='sid=').wait_for(timeout=8000)
        except Exception:
            pass
        await expect(pg, 'ROOT', 'form POST /login -> 302 -> /')
        ck = await f.locator('#ck').inner_text()
        ok('sid=S-device-one' in ck and 'pref=P-device-one' in ck,
           'device receives both cookies (HttpOnly sid and plain pref)', ck)

        # -- isolation: device page can't read the top page --
        fr = pg.frames[1]
        r = await fr.evaluate('''() => { try { return 'READ ' + parent.location.href; }
                                         catch (e) { return 'blocked ' + e.name; } }''')
        ok(r.startswith('blocked'), 'device page cannot read parent.location', r)
        r = await fr.evaluate('''() => { try { return 'READ ' + parent.localStorage.length; }
                                         catch (e) { return 'blocked ' + e.name; } }''')
        ok(r.startswith('blocked'), 'device page cannot read parent localStorage', r)

        # -- popup from the device page --
        try:
            async with pg.expect_popup(timeout=8000) as pi:
                await f.locator('#pop').click()
            pop = await pi.value
            await pop.locator('#t', has_text='POPUP').wait_for(timeout=8000)
            ok(True, 'popup window.open("/popup") served', pop.url)
            await pop.close()
        except Exception as e:
            txt = ''
            try: txt = await pop.locator('body').inner_text(timeout=2000)
            except Exception: pass
            ok(False, 'popup window.open("/popup") served', (str(e)[:100] + ' ' + txt[:80]))

        # -- worker restarts --
        boots = set()
        good = 0
        cdp = None
        if name == 'chromium':
            cdp = await ctx.new_cdp_session(pg)
            await cdp.send('ServiceWorker.enable')
        for i in range(RESTARTS):
            if name == 'chromium':
                await cdp.send('ServiceWorker.stopAllWorkers')
                await pg.wait_for_timeout(200)
            elif name == 'firefox':
                await pg.wait_for_timeout(2500)   # past the 1 s idle timeout
            else:
                await pg.wait_for_timeout(200)    # WebKit: no way to force it here
            target = 'B' if i % 2 == 0 else 'ROOT'
            sel = '#l-b' if i % 2 == 0 else '#l-root'
            t = time.time()
            await f.locator(sel).click()
            try:
                await f.locator('#t', has_text=target).wait_for(timeout=8000)
                good += 1
                boots.add(await pg.frames[1].evaluate('window.__boot'))
            except Exception:
                print(f'    restart {i}: FAILED, frame shows: {await frame_text(pg)}')
            if i == 0:
                print(f'    navigation after a restart: {int((time.time()-t)*1000)} ms wall')
        ok(good == RESTARTS, f'navigation after each forced worker stop ({good}/{RESTARTS})')
        print(f'    distinct worker boots seen: {len(boots)}  (more than 1 means restarts really happened)')
        ck = await f.locator('#ck').inner_text()
        ok('sid=S-device-one' in ck, 'cookies survive worker restarts', ck)
        st = await pg.evaluate('stats')
        print(f'    ports handed: {st["ports"]}, device requests: {st["requests"]}')
        await b.close()

for n in (sys.argv[1].split(',') if len(sys.argv) > 1 else ['chromium', 'firefox', 'webkit']):
    try:
        asyncio.run(run(n))
    except Exception as e:
        print(f'== {n}: aborted: {str(e)[:300]}')
