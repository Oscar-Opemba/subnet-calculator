import html
import json
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs

MAX_BODY = 1_000_000

def esc(value):
    return html.escape(str(value), quote=True)

def render_json(data):
    return '<pre class="result">' + esc(json.dumps(data, indent=2, sort_keys=True, default=str)) + '</pre>'

def page(title, fields, result=''):
    controls = []
    for name, label, kind, placeholder in fields:
        if kind == 'textarea':
            control = f'<textarea name="{esc(name)}" placeholder="{esc(placeholder)}" required></textarea>'
        else:
            control = f'<input name="{esc(name)}" type="{esc(kind)}" placeholder="{esc(placeholder)}" required>'
        controls.append(f'<label>{esc(label)}{control}</label>')
    return f'''<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{esc(title)}</title><style>
:root{{color-scheme:dark}}body{{font-family:system-ui,sans-serif;max-width:920px;margin:2rem auto;padding:0 1rem;background:#0b1220;color:#e5e7eb}}
main{{background:#111827;border:1px solid #334155;border-radius:16px;padding:1.5rem;box-shadow:0 10px 30px #0004}}h1{{margin-top:0;color:#93c5fd}}
label{{display:block;margin:1rem 0;color:#cbd5e1}}input,textarea{{display:block;width:100%;box-sizing:border-box;margin-top:.45rem;padding:.75rem;border-radius:8px;border:1px solid #475569;background:#0f172a;color:#f8fafc;font:inherit}}textarea{{min-height:180px}}
button{{padding:.75rem 1.2rem;border:0;border-radius:8px;background:#2563eb;color:#fff;font-weight:700;cursor:pointer}}small{{color:#94a3b8}}.result{{white-space:pre-wrap;overflow:auto;background:#020617;padding:1rem;border-radius:10px;border:1px solid #334155}}
</style></head><body><main><h1>{esc(title)}</h1><p><small>Local defensive utility. Use network checks only on systems you own or are authorized to assess. Inputs are processed by this local server.</small></p>
<form method="post">{''.join(controls)}<button type="submit">Analyze</button></form>{result}</main></body></html>'''

def serve(title, fields, analyze, port):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, format, *args):
            return
        def do_GET(self):
            body = page(title, fields)
            self.send_response(200); self.send_header('Content-Type', 'text/html; charset=utf-8'); self.end_headers(); self.wfile.write(body.encode())
        def do_POST(self):
            length = int(self.headers.get('Content-Length', '0'))
            if length < 0 or length > MAX_BODY:
                self.send_error(413, 'Request too large'); return
            raw = self.rfile.read(length)
            values = {key: vals[0] for key, vals in parse_qs(raw.decode('utf-8', 'replace')).items()}
            try:
                result = analyze(values)
            except Exception as exc:
                result = {'error': f'{type(exc).__name__}: {exc}'}
            body = page(title, fields, render_json(result))
            self.send_response(200); self.send_header('Content-Type', 'text/html; charset=utf-8'); self.end_headers(); self.wfile.write(body.encode())
    print(f'Listening on http://127.0.0.1:{port}')
    HTTPServer(('127.0.0.1', port), Handler).serve_forever()
