# Device-origins spike server.
#
# localhost:PORT          -> the top page (stands in for bitba.ng)
# <label>.localhost:PORT  -> only the loader and the label worker; every
#                            other path gets the loader, which is what a
#                            request reaching the network (no worker yet)
#                            should get. Device content never comes from here.
import http.server, socket, sys, os

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8800
HERE = os.path.dirname(os.path.abspath(__file__))
LOG = open(os.path.join(HERE, 'server.log'), 'a')

def read(name):
    with open(os.path.join(HERE, name), encoding='utf-8') as f:
        return f.read().replace('__PORT__', str(PORT)).encode()

class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        host = (self.headers.get('Host') or '').split(':')[0]
        path = self.path.split('?')[0]
        LOG.write(f'{host} {self.command} {self.path}\n'); LOG.flush()
        # bb.localhost and <label>.bb.localhost share the registrable domain
        # bb.localhost, so they are same-site, as bitba.ng and
        # <label>.bitba.ng are. (localhost and x.localhost are not.)
        if host == 'bb.localhost':
            if path == '/top.js':
                return self.send(read('top.js'), 'application/javascript')
            return self.send(read('top.html'), 'text/html')
        if host.endswith('.bb.localhost'):
            if path == '/sw.js':
                return self.send(read('sw.js'), 'application/javascript')
            return self.send(read('loader.html'), 'text/html', {
                'Content-Security-Policy': f'frame-ancestors http://bb.localhost:{PORT}',
            })
        self.send_response(404); self.end_headers()

    do_POST = do_GET

    def send(self, body, ctype, extra=None):
        self.send_response(200)
        self.send_header('Content-Type', ctype + '; charset=utf-8')
        self.send_header('Cache-Control', 'no-store')
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass

class S(http.server.ThreadingHTTPServer):
    address_family = socket.AF_INET6
    def server_bind(self):
        self.socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
        super().server_bind()

S(('::', PORT), H).serve_forever()
