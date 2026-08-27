import html
import json
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs

MAX_BODY = 1_000_000
MAX_FIELDS = 32
_RATE_WINDOW = 60.0
_RATE_LIMIT = 30
_rate_buckets = {}

def esc(value):
    return html.escape(str(value), quote=True)

def render_json(data):
    return '<pre class="result">' + esc(json.dumps(data, indent=2, sort_keys=True, default=str)) + '</pre>'

def page(title, fields, result=''):
    controls = []
    for name, label, kind, placeholder in fields:
        if kind == 'textarea':
            control = f'<textarea name="{esc(name)}" maxlength="1000000" placeholder="{esc(placeholder)}" required></textarea>'
        else:
            control = f'<input name="{esc(name)}" type="{esc(kind)}" maxlength="4096" placeholder="{esc(placeholder)}" required>'
        controls.append(f'<label>{esc(label)}{control}</label>')
    return f'''<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{esc(title)}</title><style>
:root{{color-scheme:dark}}body{{font-family:system-ui,sans-serif;max-width:920px;margin:2rem auto;padding:0 1rem;background:#0b1220;color:#e5e7eb}}
main{{background:#111827;border:1px solid #334155;border-radius:16px;padding:1.5rem;box-shadow:0 10px 30px #0004}}h1{{margin-top:0;color:#93c5fd}}
label{{display:block;margin:1rem 0;color:#cbd5e1}}input,textarea{{display:block;width:100%;box-sizing:border-box;margin-top:.45rem;padding:.75rem;border-radius:8px;border:1px solid #475569;background:#0f172a;color:#f8fafc;font:inherit}}textarea{{min-height:180px}}
button{{padding:.75rem 1.2rem;border:0;border-radius:8px;background:#2563eb;color:#fff;font-weight:700;cursor:pointer}}small{{color:#94a3b8}}.result{{white-space:pre-wrap;overflow:auto;background:#020617;padding:1rem;border-radius:10px;border:1px solid #334155}}
</style></head><body><main><h1>{esc(title)}</h1><p><small>Local defensive utility. Network checks are single-request, no-redirect, and intended for systems you own or are authorized to assess. Sensitive offline inputs are not stored.</small></p>
<form method="post">{''.join(controls)}<button type="submit">Analyze</button></form>{result}</main></body></html>'''

def _allowed(client):
    now = time.monotonic()
    bucket = _rate_buckets.setdefault(client, [])
    bucket[:] = [stamp for stamp in bucket if now - stamp < _RATE_WINDOW]
    if len(bucket) >= _RATE_LIMIT:
        return False
    bucket.append(now)
    if len(_rate_buckets) > 256:
        for key in list(_rate_buckets)[:64]:
            if not _rate_buckets[key]: _rate_buckets.pop(key, None)
    return True

def serve(title, fields, analyze, port):
    class Handler(BaseHTTPRequestHandler):
        server_version = 'CyberSecLocal/1.0'
        def log_message(self, format, *args):
            return
        def _send(self, body, status=200):
            encoded = body.encode('utf-8')
            self.send_response(status)
            self.send_header('Content-Type', 'text/html; charset=utf-8')
            self.send_header('Content-Length', str(len(encoded)))
            self.send_header('Cache-Control', 'no-store')
            self.send_header('X-Content-Type-Options', 'nosniff')
            self.send_header('X-Frame-Options', 'DENY')
            self.send_header('Referrer-Policy', 'no-referrer')
            self.send_header('Content-Security-Policy', "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; base-uri 'none'")
            self.end_headers()
            self.wfile.write(encoded)
        def do_GET(self):
            if not _allowed(self.client_address[0]):
                self._send('<h1>Rate limit exceeded</h1>', 429); return
            self._send(page(title, fields))
        def do_POST(self):
            if not _allowed(self.client_address[0]):
                self._send('<h1>Rate limit exceeded</h1>', 429); return
            try:
                length = int(self.headers.get('Content-Length', '0'))
            except ValueError:
                self._send('<h1>Invalid request</h1>', 400); return
            if length < 0 or length > MAX_BODY:
                self._send('<h1>Request too large</h1>', 413); return
            self.connection.settimeout(10)
            try:
                raw = self.rfile.read(length)
                values = {key: vals[0] for key, vals in parse_qs(raw.decode('utf-8', 'replace'), max_num_fields=MAX_FIELDS).items()}
            except (TimeoutError, ValueError):
                self._send('<h1>Invalid form data</h1>', 400); return
            try:
                result = analyze(values)
            except Exception:
                result = {'error': 'Analysis failed. Check the input and try again.'}
            self._send(page(title, fields, render_json(result)))
    class Server(ThreadingHTTPServer):
        daemon_threads = True
        allow_reuse_address = True
    print(f'Listening on http://127.0.0.1:{port}')
    Server(('127.0.0.1', port), Handler).serve_forever()
