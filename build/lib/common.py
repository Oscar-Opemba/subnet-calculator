import hmac
import html
import json
import secrets
import socket
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs

MAX_BODY = 1_000_000
MAX_FIELDS = 32
MAX_HEADERS = 64
MAX_HEADER_VALUE = 8_192
MAX_OUTPUT_CHARS = 512_000
MAX_CONCURRENT_REQUESTS = 16
REQUEST_TIMEOUT = 10
RATE_WINDOW = 60.0
RATE_LIMIT = 30
_rate_buckets = {}
_rate_lock = threading.Lock()
_request_slots = threading.BoundedSemaphore(MAX_CONCURRENT_REQUESTS)
_FORM_TOKEN = secrets.token_urlsafe(32)


def esc(value):
    return html.escape(str(value), quote=True)


def render_json(data):
    serialized = json.dumps(data, indent=2, sort_keys=True, default=str)
    if len(serialized) > MAX_OUTPUT_CHARS:
        serialized = json.dumps({'error': 'analysis output exceeded the display safety limit', 'output_truncated': True, 'preview': serialized[:MAX_OUTPUT_CHARS // 4]})
    return '<pre class="result">' + esc(serialized) + '</pre>'


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
<form method="post" accept-charset="UTF-8"><input type="hidden" name="_csrf" value="{esc(_FORM_TOKEN)}">{''.join(controls)}<button type="submit">Analyze</button></form>{result}</main></body></html>'''


def _allowed(client):
    with _rate_lock:
        now = time.monotonic()
        bucket = _rate_buckets.setdefault(client, [])
        bucket[:] = [stamp for stamp in bucket if now - stamp < RATE_WINDOW]
        if len(bucket) >= RATE_LIMIT:
            return False
        bucket.append(now)
        if len(_rate_buckets) > 256:
            non_empty = [(key, values[-1]) for key, values in _rate_buckets.items() if values]
            for key, _ in sorted(non_empty, key=lambda item: item[1])[:64]:
                _rate_buckets.pop(key, None)
        return True


def _valid_request_headers(headers):
    if len(headers) > MAX_HEADERS:
        return False
    return all(len(str(name)) <= 128 and len(str(value)) <= MAX_HEADER_VALUE for name, value in headers.items())


def serve(title, fields, analyze, port):
    if not isinstance(port, int) or not 1024 <= port <= 65535:
        raise ValueError('web port must be an integer between 1024 and 65535')

    class Handler(BaseHTTPRequestHandler):
        server_version = ''
        sys_version = ''

        def setup(self):
            super().setup()
            self.connection.settimeout(REQUEST_TIMEOUT)

        def log_message(self, format, *args):
            return

        def finish(self):
            try:
                super().finish()
            finally:
                if getattr(self, '_slot_acquired', False):
                    _request_slots.release()
                    self._slot_acquired = False

        def _send(self, body, status=200, extra_headers=None):
            encoded = body.encode('utf-8')
            try:
                self.send_response(status)
                self.send_header('Content-Type', 'text/html; charset=utf-8')
                self.send_header('Content-Length', str(len(encoded)))
                self.send_header('Connection', 'close')
                self.send_header('Cache-Control', 'no-store, max-age=0')
                self.send_header('Pragma', 'no-cache')
                self.send_header('X-Content-Type-Options', 'nosniff')
                self.send_header('X-Frame-Options', 'DENY')
                self.send_header('Cross-Origin-Resource-Policy', 'same-origin')
                self.send_header('Referrer-Policy', 'no-referrer')
                self.send_header('Permissions-Policy', 'geolocation=(), camera=(), microphone=()')
                self.send_header('Content-Security-Policy', "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; base-uri 'none'")
                if extra_headers:
                    for name, value in extra_headers.items():
                        self.send_header(name, value)
                self.end_headers()
                self.wfile.write(encoded)
            except OSError:
                pass

        def _allow_or_rate_limit(self):
            if self.client_address[0] not in ('127.0.0.1', '::1'):
                self._send('<h1>Loopback access only</h1>', 403)
                return False
            host_header = self.headers.get('Host', '').casefold()
            allowed_hosts = {f'127.0.0.1:{port}', f'localhost:{port}', '127.0.0.1', 'localhost'}
            if host_header not in allowed_hosts:
                self._send('<h1>Host header not allowed</h1>', 421)
                return False
            if not _allowed(self.client_address[0]):
                self._send('<h1>Rate limit exceeded</h1>', 429, {'Retry-After': str(int(RATE_WINDOW))})
                return False
            if not _valid_request_headers(self.headers):
                self._send('<h1>Request headers exceed the safety limits</h1>', 431)
                return False
            if not _request_slots.acquire(blocking=False):
                self._send('<h1>Server is busy; try again later</h1>', 503, {'Retry-After': '5'})
                return False
            self._slot_acquired = True
            return True

        def do_GET(self):
            if self._allow_or_rate_limit():
                self._send(page(title, fields))

        def do_POST(self):
            if not self._allow_or_rate_limit():
                return
            try:
                length = int(self.headers.get('Content-Length', '0'))
            except ValueError:
                self._send('<h1>Invalid request</h1>', 400)
                return
            content_type = self.headers.get('Content-Type', '').split(';', 1)[0].strip().lower()
            if content_type not in ('', 'application/x-www-form-urlencoded'):
                self._send('<h1>Unsupported content type</h1>', 415)
                return
            if length < 0 or length > MAX_BODY:
                self._send('<h1>Request too large</h1>', 413)
                return
            try:
                raw = self.rfile.read(length)
                values = {key: vals[0] for key, vals in parse_qs(raw.decode('utf-8', 'replace'), keep_blank_values=True, max_num_fields=MAX_FIELDS).items()}
            except (TimeoutError, ValueError):
                self._send('<h1>Invalid form data</h1>', 400)
                return
            csrf = values.pop('_csrf', '')
            if not hmac.compare_digest(csrf, _FORM_TOKEN):
                self._send('<h1>Invalid form token</h1>', 403)
                return
            try:
                result = analyze(values)
            except Exception:
                result = {'error': 'Analysis failed. Check the input and try again.'}
            self._send(page(title, fields, render_json(result)))

        def _method_not_allowed(self):
            self._send('<h1>Method not allowed</h1>', 405, {'Allow': 'GET, POST'})

        do_PUT = _method_not_allowed
        do_PATCH = _method_not_allowed
        do_DELETE = _method_not_allowed
        do_OPTIONS = _method_not_allowed
        do_HEAD = _method_not_allowed
        do_TRACE = _method_not_allowed
        do_CONNECT = _method_not_allowed

    class Server(ThreadingHTTPServer):
        address_family = socket.AF_INET
        daemon_threads = True
        allow_reuse_address = True
        request_queue_size = 16

    print(f'Listening on http://127.0.0.1:{port}')
    Server(('127.0.0.1', port), Handler).serve_forever()
