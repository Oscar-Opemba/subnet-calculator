import http.client
import ipaddress
import os
import socket
import ssl
import stat
from email.message import Message
from pathlib import Path
from urllib.error import HTTPError
from urllib.parse import urlsplit, urlunsplit
from urllib.request import Request

MAX_TEXT_BYTES = 1_000_000
MAX_RESPONSE_BYTES = 256_000
MAX_URL_LENGTH = 4096
MAX_PATH_LENGTH = 4096
MAX_REQUEST_BODY = 1_000_000


def _is_blocked(address):
    return address.is_private or address.is_loopback or address.is_link_local or address.is_reserved or address.is_multicast or address.is_unspecified


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
        if not allow_private and _is_blocked(address):
            raise ValueError('private or reserved addresses are blocked by default')
    except ValueError as exc:
        if str(exc) == 'private or reserved addresses are blocked by default':
            raise
        labels = ascii_host.split('.')
        if any(not label or len(label) > 63 or label.startswith('-') or label.endswith('-') for label in labels):
            raise ValueError('hostname labels are invalid')
    return ascii_host


def resolve_public_addresses(host):
    try:
        infos = socket.getaddrinfo(host, None, family=socket.AF_UNSPEC, type=socket.SOCK_STREAM)
    except OSError as exc:
        raise ValueError('hostname did not resolve') from exc
    addresses = []
    seen = set()
    for info in infos:
        if not info[4]:
            continue
        address = ipaddress.ip_address(info[4][0])
        if _is_blocked(address):
            raise ValueError('hostname resolves to a private or reserved address')
        if address not in seen:
            addresses.append(address)
            seen.add(address)
    if not addresses:
        raise ValueError('hostname did not resolve to an address')
    return tuple(addresses)


def assert_public_resolution(host):
    resolve_public_addresses(host)


def validate_url(value, allow_private=False, resolve=False):
    raw = (value or '').strip()
    if len(raw) > MAX_URL_LENGTH or any(ord(ch) < 32 or ord(ch) == 127 for ch in raw):
        raise ValueError('URL is empty, too long, or contains control characters')
    parsed = urlsplit(raw)
    if parsed.scheme not in ('http', 'https') or not parsed.netloc or parsed.username or parsed.password or parsed.fragment:
        raise ValueError('enter one absolute http(s) URL without credentials or a fragment')
    host = validate_host(parsed.hostname, allow_private=allow_private)
    try:
        port = parsed.port
    except ValueError as exc:
        raise ValueError('URL port is invalid') from exc
    if port is not None and not 1 <= port <= 65535:
        raise ValueError('URL port is out of range')
    if resolve and not allow_private:
        assert_public_resolution(host)
    netloc = host
    if ':' in host and not host.startswith('['):
        netloc = '[' + host + ']'
    if port is not None:
        netloc += ':' + str(port)
    return parsed._replace(netloc=netloc)


class _PinnedHTTPConnection(http.client.HTTPConnection):
    def __init__(self, connect_ip, host, port, timeout):
        super().__init__(host=host, port=port, timeout=timeout)
        self._connect_ip = str(connect_ip)

    def connect(self):
        self.sock = socket.create_connection((self._connect_ip, self.port), self.timeout)


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    def __init__(self, connect_ip, host, port, timeout, context):
        super().__init__(host=host, port=port, timeout=timeout, context=context)
        self._connect_ip = str(connect_ip)

    def connect(self):
        self.sock = socket.create_connection((self._connect_ip, self.port), self.timeout)
        if self._tunnel_host:
            self._tunnel()
        self.sock = self._context.wrap_socket(self.sock, server_hostname=self.host)


class _PinnedResponse:
    def __init__(self, connection, response):
        self._connection = connection
        self._response = response
        self.status = response.status
        self.reason = response.reason
        self.headers = response.headers

    def read(self, amount=-1):
        return self._response.read(amount)

    def close(self):
        try:
            self._response.close()
        finally:
            self._connection.close()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()


def open_no_redirect(request, timeout=8):
    if not isinstance(request, Request):
        raise ValueError('request must be urllib.request.Request')
    if timeout <= 0 or timeout > 30:
        raise ValueError('timeout must be between 1 and 30 seconds')
    method = request.get_method().upper()
    if method not in {'GET', 'HEAD', 'OPTIONS', 'POST'}:
        raise ValueError('HTTP method is not allowed')
    body = request.data or b''
    if isinstance(body, str):
        body = body.encode('utf-8')
    if len(body) > MAX_REQUEST_BODY:
        raise ValueError('request body exceeded the safety limit')
    parsed = validate_url(request.full_url, resolve=True)
    host = parsed.hostname
    port = parsed.port or (443 if parsed.scheme == 'https' else 80)
    path = urlunsplit(('', '', parsed.path or '/', parsed.query, ''))
    if len(path) > MAX_URL_LENGTH:
        raise ValueError('request path exceeded the safety limit')
    headers = {name: value for name, value in request.header_items() if name.casefold() != 'host'}
    headers['Host'] = parsed.netloc
    addresses = resolve_public_addresses(host)
    last_error = None
    for address in addresses:
        connection = None
        try:
            if parsed.scheme == 'https':
                context = ssl.create_default_context()
                connection = _PinnedHTTPSConnection(address, host, port, timeout, context)
            else:
                connection = _PinnedHTTPConnection(address, host, port, timeout)
            connection.request(method, path, body=body, headers=headers)
            response = connection.getresponse()
            if 300 <= response.status < 400:
                response.close(); connection.close()
                raise HTTPError(request.full_url, response.status, 'redirects disabled', response.headers, None)
            if response.status >= 400:
                error = HTTPError(request.full_url, response.status, response.reason or 'HTTP error', response.headers, None)
                response.close(); connection.close()
                raise error
            return _PinnedResponse(connection, response)
        except HTTPError:
            raise
        except (OSError, ssl.SSLError) as exc:
            last_error = exc
            if connection is not None:
                connection.close()
    raise OSError(f'connection failed: {type(last_error).__name__ if last_error else "unknown"}')


def connect_tls(host, port, context, timeout=8, allow_private=False):
    host = validate_host(host, allow_private=allow_private)
    if not isinstance(port, int) or not 1 <= port <= 65535:
        raise ValueError('port must be between 1 and 65535')
    infos = socket.getaddrinfo(host, port, family=socket.AF_UNSPEC, type=socket.SOCK_STREAM)
    addresses = []
    seen = set()
    for info in infos:
        address = ipaddress.ip_address(info[4][0])
        if not allow_private and _is_blocked(address):
            raise ValueError('hostname resolves to a private or reserved address')
        if address not in seen:
            addresses.append(address)
            seen.add(address)
    if not addresses:
        raise ValueError('hostname did not resolve to an address')
    last_error = None
    for address in addresses:
        raw = None
        try:
            raw = socket.create_connection((str(address), port), timeout=timeout)
            return context.wrap_socket(raw, server_hostname=host)
        except (OSError, ssl.SSLError) as exc:
            last_error = exc
            if raw is not None:
                raw.close()
    raise OSError(f'TLS connection failed: {type(last_error).__name__ if last_error else "unknown"}')


def bounded_read(response, limit=MAX_RESPONSE_BYTES):
    if not isinstance(limit, int) or limit <= 0 or limit > MAX_RESPONSE_BYTES:
        raise ValueError('response limit is invalid')
    data = response.read(limit + 1)
    if len(data) > limit:
        raise ValueError('remote response exceeded the safety limit')
    return data


def read_local_file(path_value, max_bytes=MAX_TEXT_BYTES):
    if not isinstance(max_bytes, int) or max_bytes <= 0 or max_bytes > 512 * 1024 * 1024:
        raise ValueError('file size limit is invalid')
    if not isinstance(path_value, (str, os.PathLike)):
        raise ValueError('path must be a string or path-like value')
    try:
        path_string = os.fspath(path_value)
    except TypeError as exc:
        raise ValueError('path is invalid') from exc
    if not path_string or len(path_string) > MAX_PATH_LENGTH or '\x00' in path_string:
        raise ValueError('path is empty, too long, or contains a NUL byte')
    path = Path(path_string)
    flags = os.O_RDONLY
    if hasattr(os, 'O_NOFOLLOW'):
        flags |= os.O_NOFOLLOW
    try:
        fd = os.open(path, flags)
    except (OSError, ValueError, TypeError) as exc:
        raise ValueError(f'unable to open regular local file: {getattr(exc, "strerror", None) or str(exc)}') from exc
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            raise ValueError('path must be a regular file')
        chunks = []
        total = 0
        while total <= max_bytes:
            chunk = os.read(fd, min(1024 * 1024, max_bytes - total + 1))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > max_bytes:
                raise ValueError(f'file exceeds the {max_bytes} byte safety limit')
        return b''.join(chunks)
    finally:
        os.close(fd)


def valid_origin(origin):
    parsed = validate_url(origin, allow_private=False)
    if parsed.path not in ('', '/') or parsed.query:
        raise ValueError('origin must contain only scheme, host, and optional port')
    return parsed.geturl().rstrip('/')
