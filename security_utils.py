import ipaddress
import os
import socket
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import HTTPRedirectHandler, build_opener
from urllib.parse import urlsplit

MAX_TEXT_BYTES = 1_000_000
MAX_RESPONSE_BYTES = 256_000

class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise HTTPError(req.full_url, code, 'redirects disabled', headers, fp)

_NO_REDIRECT = build_opener(NoRedirect)

def open_no_redirect(request, timeout=8):
    return _NO_REDIRECT.open(request, timeout=timeout)

def bounded_read(response, limit=MAX_RESPONSE_BYTES):
    data = response.read(limit + 1)
    if len(data) > limit:
        raise ValueError('remote response exceeded the safety limit')
    return data

def validate_host(host, allow_private=False):
    host = (host or '').strip().rstrip('.')
    if not host or len(host) > 253 or any(ch.isspace() or ch in '/?#@' for ch in host):
        raise ValueError('enter one hostname only')
    try:
        ascii_host = host.encode('idna').decode('ascii').lower()
    except UnicodeError as exc:
        raise ValueError('hostname contains invalid characters') from exc
    try:
        address = ipaddress.ip_address(ascii_host)
        if not allow_private and (address.is_private or address.is_loopback or address.is_link_local or address.is_reserved or address.is_multicast or address.is_unspecified):
            raise ValueError('private or reserved addresses are blocked by default')
    except ValueError as exc:
        if str(exc) == 'private or reserved addresses are blocked by default': raise
        labels = ascii_host.split('.')
        if any(not label or len(label) > 63 or label.startswith('-') or label.endswith('-') for label in labels):
            raise ValueError('hostname labels are invalid')
    return ascii_host

def assert_public_resolution(host):
    try:
        infos = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    except OSError as exc:
        raise ValueError('hostname did not resolve') from exc
    addresses = {ipaddress.ip_address(info[4][0]) for info in infos if info[4]}
    if not addresses: raise ValueError('hostname did not resolve to an address')
    if any(address.is_private or address.is_loopback or address.is_link_local or address.is_reserved or address.is_multicast or address.is_unspecified for address in addresses):
        raise ValueError('hostname resolves to a private or reserved address')

def validate_url(value, allow_private=False, resolve=False):
    raw = (value or '').strip()
    if len(raw) > 4096 or any(ord(ch) < 32 or ord(ch) == 127 for ch in raw):
        raise ValueError('URL is empty, too long, or contains control characters')
    parsed = urlsplit(raw)
    if parsed.scheme not in ('http', 'https') or not parsed.netloc or parsed.username or parsed.password or parsed.fragment:
        raise ValueError('enter one absolute http(s) URL without credentials or a fragment')
    host = validate_host(parsed.hostname, allow_private=allow_private)
    try: port = parsed.port
    except ValueError as exc: raise ValueError('URL port is invalid') from exc
    if port is not None and not (1 <= port <= 65535): raise ValueError('URL port is out of range')
    netloc = host
    if ':' in host and not host.startswith('['): netloc = '[' + host + ']'
    if port is not None: netloc += ':' + str(port)
    if resolve and not allow_private: assert_public_resolution(host)
    return parsed._replace(netloc=netloc)

def read_local_file(path_value, max_bytes=MAX_TEXT_BYTES):
    path = Path(path_value)
    if not path.is_file() or path.is_symlink(): raise ValueError('path must be a regular non-symlink file')
    size = path.stat().st_size
    if size > max_bytes: raise ValueError(f'file exceeds the {max_bytes} byte safety limit')
    return path.read_bytes()

def valid_origin(origin):
    parsed = validate_url(origin, allow_private=False)
    return parsed.geturl().rstrip('/')
