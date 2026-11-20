"""SSRF-safe HTTP client used by every website check.

Design (defence against SSRF and DNS rebinding):
  * The target URL is parsed and validated (scheme, credentials, port).
  * The hostname is resolved ONCE; every returned address must be a public,
    globally routable address. Otherwise the request is refused.
  * The TCP connection is opened to that already-validated IP address, so the
    HTTP library never performs a second DNS lookup that could be rebound.
    TLS still validates the certificate against the original hostname (SNI).
  * Redirects are followed manually and each hop goes through the same checks.
  * Response size, total time, redirect count and request count are limited.
Certificate validation is never disabled.
"""
from __future__ import annotations

import http.client
import ipaddress
import socket
import ssl
import time
from dataclasses import dataclass, field
from typing import Callable
from urllib.parse import urljoin, urlsplit

USER_AGENT = "SecureScanAI/1.0 (authorized security assessment)"
_BLOCKED_SUFFIXES = (".localhost", ".local", ".internal", ".lan", ".home.arpa", ".intranet", ".corp")
MAX_URL_LENGTH = 2048


class UnsafeTargetError(ValueError):
    """The target is not allowed (private, malformed, unresolvable...)."""


class FetchError(Exception):
    def __init__(self, kind: str, message: str):
        super().__init__(message)
        self.kind = kind  # dns | connect | timeout | tls | protocol


class ScanLimitError(Exception):
    pass


class ScanCancelled(Exception):
    pass


def is_public_ip(value: str) -> bool:
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return False
    if isinstance(ip, ipaddress.IPv6Address):
        if ip.ipv4_mapped is not None:
            return is_public_ip(str(ip.ipv4_mapped))
        if ip.sixtofour is not None and not is_public_ip(str(ip.sixtofour)):
            return False
        if ip.teredo is not None:
            return False
    return bool(
        ip.is_global
        and not (ip.is_multicast or ip.is_reserved or ip.is_unspecified
                 or ip.is_loopback or ip.is_link_local or ip.is_private)
    )


def _resolve(host: str, port: int) -> list[str]:
    try:
        infos = socket.getaddrinfo(host, port, proto=socket.IPPROTO_TCP)
    except (socket.gaierror, UnicodeError) as exc:
        raise UnsafeTargetError(f"The host name '{host}' could not be resolved.") from exc
    ips: list[str] = []
    for info in infos:
        addr = info[4][0].split("%")[0]
        if addr not in ips:
            ips.append(addr)
    if not ips:
        raise UnsafeTargetError(f"The host name '{host}' has no IP address.")
    return ips


@dataclass
class Target:
    url: str
    scheme: str
    host: str
    port: int
    path: str  # path + query
    ips: list[str] = field(default_factory=list)

    @property
    def origin(self) -> str:
        default = 443 if self.scheme == "https" else 80
        return f"{self.scheme}://{self.host}" + ("" if self.port == default else f":{self.port}")


def parse_target(url: str, allow_private: bool = False, resolve: bool = True) -> Target:
    url = (url or "").strip()
    if not url:
        raise UnsafeTargetError("Enter a website address.")
    if len(url) > MAX_URL_LENGTH:
        raise UnsafeTargetError("The URL is too long.")
    if any(ord(c) < 33 or ord(c) == 127 for c in url):
        raise UnsafeTargetError("The URL contains spaces or control characters.")
    try:
        parts = urlsplit(url)
        port = parts.port
    except ValueError as exc:
        raise UnsafeTargetError("The URL is not valid.") from exc
    scheme = parts.scheme.lower()
    if scheme not in ("http", "https"):
        raise UnsafeTargetError("Only http:// and https:// addresses can be scanned.")
    if parts.username is not None or parts.password is not None:
        raise UnsafeTargetError("URLs with embedded credentials are not allowed.")
    host = (parts.hostname or "").rstrip(".").lower()
    if not host:
        raise UnsafeTargetError("The URL has no host name.")
    try:
        host_ascii = host.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise UnsafeTargetError("The host name is not valid.") from exc
    port = port or (443 if scheme == "https" else 80)
    if not (1 <= port <= 65535):
        raise UnsafeTargetError("The port number is not valid.")
    if not allow_private:
        if host_ascii == "localhost" or host_ascii.endswith(_BLOCKED_SUFFIXES):
            raise UnsafeTargetError("Local and internal host names cannot be scanned.")
    path = parts.path or "/"
    if parts.query:
        path += "?" + parts.query
    target = Target(url=url, scheme=scheme, host=host_ascii, port=port, path=path)
    if resolve:
        try:
            literal = ipaddress.ip_address(host_ascii)
            ips = [str(literal)]
        except ValueError:
            ips = _resolve(host_ascii, port)
        if not allow_private:
            bad = [ip for ip in ips if not is_public_ip(ip)]
            if bad:
                raise UnsafeTargetError(
                    "The address resolves to a private, loopback, link-local or reserved "
                    "network, which cannot be scanned."
                )
        target.ips = ips
    return target


@dataclass
class Response:
    url: str
    status: int
    reason: str
    headers: list[tuple[str, str]]
    body: bytes
    elapsed_ms: int
    truncated: bool = False

    def header(self, name: str) -> str | None:
        lname = name.lower()
        for k, v in self.headers:
            if k.lower() == lname:
                return v
        return None

    def header_all(self, name: str) -> list[str]:
        lname = name.lower()
        return [v for k, v in self.headers if k.lower() == lname]

    @property
    def text(self) -> str:
        charset = "utf-8"
        ctype = self.header("content-type") or ""
        if "charset=" in ctype.lower():
            charset = ctype.lower().split("charset=")[1].split(";")[0].strip().strip('"') or "utf-8"
        try:
            return self.body.decode(charset, errors="replace")
        except LookupError:
            return self.body.decode("utf-8", errors="replace")

    @property
    def is_html(self) -> bool:
        return "html" in (self.header("content-type") or "").lower()


class _PinnedHTTP(http.client.HTTPConnection):
    def __init__(self, host, port, ip, timeout):
        super().__init__(host, port, timeout=timeout)
        self._ip = ip

    def connect(self):
        self.sock = socket.create_connection((self._ip, self.port), self.timeout)


class _PinnedHTTPS(http.client.HTTPSConnection):
    def __init__(self, host, port, ip, timeout, context):
        super().__init__(host, port, timeout=timeout, context=context)
        self._ip = ip

    def connect(self):
        sock = socket.create_connection((self._ip, self.port), self.timeout)
        try:
            self.sock = self._context.wrap_socket(sock, server_hostname=self.host)
        except Exception:
            sock.close()
            raise


@dataclass
class FetchResult:
    response: Response
    chain: list[Response]  # every response, including redirects, in order

    @property
    def final_url(self) -> str:
        return self.response.url


class SafeClient:
    def __init__(self, *, allow_private=False, timeout=10, max_requests=120, max_bytes=1_000_000,
                 delay_ms=0, should_cancel: Callable[[], bool] | None = None):
        self.allow_private = allow_private
        self.timeout = timeout
        self.max_requests = max_requests
        self.max_bytes = max_bytes
        self.delay = delay_ms / 1000.0
        self.should_cancel = should_cancel or (lambda: False)
        self.request_count = 0
        self._ctx = ssl.create_default_context()  # verification stays ON

    def request(self, url: str, method: str = "GET", headers: dict[str, str] | None = None,
                follow_redirects: bool = True, max_redirects: int = 5) -> FetchResult:
        chain: list[Response] = []
        current = url
        for _hop in range(max_redirects + 1):
            resp = self._single(current, method, headers or {})
            chain.append(resp)
            location = resp.header("location")
            if follow_redirects and resp.status in (301, 302, 303, 307, 308) and location:
                current = urljoin(current, location)
                if method != "HEAD" and resp.status in (301, 302, 303):
                    method = "GET"
                continue
            return FetchResult(resp, chain)
        raise FetchError("protocol", "Too many redirects.")

    def _single(self, url: str, method: str, extra: dict[str, str]) -> Response:
        if self.should_cancel():
            raise ScanCancelled()
        if self.request_count >= self.max_requests:
            raise ScanLimitError("The request limit for this scan was reached.")
        self.request_count += 1
        if self.delay and self.request_count > 1:
            time.sleep(self.delay)
        target = parse_target(url, self.allow_private, resolve=True)  # every hop re-validated
        hdrs = {
            "User-Agent": USER_AGENT,
            "Accept": "text/html,application/xhtml+xml,*/*;q=0.8",
            "Accept-Encoding": "identity",
            "Connection": "close",
        }
        hdrs.update(extra)
        last_err: Exception | None = None
        for ip in target.ips:
            conn = None
            try:
                if target.scheme == "https":
                    conn = _PinnedHTTPS(target.host, target.port, ip, self.timeout, self._ctx)
                else:
                    conn = _PinnedHTTP(target.host, target.port, ip, self.timeout)
                started = time.monotonic()
                conn.request(method, target.path, headers=hdrs)
                resp = conn.getresponse()
                body = b""
                truncated = False
                if method != "HEAD":
                    deadline = started + self.timeout * 3
                    chunks: list[bytes] = []
                    total = 0
                    while True:
                        chunk = resp.read(16384)
                        if not chunk:
                            break
                        chunks.append(chunk)
                        total += len(chunk)
                        if total > self.max_bytes:
                            truncated = True
                            break
                        if time.monotonic() > deadline:
                            truncated = True
                            break
                    body = b"".join(chunks)[: self.max_bytes]
                return Response(
                    url=url, status=resp.status, reason=resp.reason or "",
                    headers=list(resp.getheaders()), body=body,
                    elapsed_ms=int((time.monotonic() - started) * 1000), truncated=truncated,
                )
            except ssl.SSLCertVerificationError as exc:
                raise FetchError("tls", exc.verify_message or str(exc)) from exc
            except ssl.SSLError as exc:
                raise FetchError("tls", f"TLS handshake failed: {exc.reason or exc}") from exc
            except socket.timeout as exc:
                last_err = FetchError("timeout", "The connection timed out.")
                last_err.__cause__ = exc
            except (OSError, http.client.HTTPException) as exc:
                last_err = FetchError("connect", f"Could not connect: {exc.__class__.__name__}")
                last_err.__cause__ = exc
            finally:
                if conn is not None:
                    conn.close()
        raise last_err or FetchError("connect", "Could not connect.")


def inspect_tls(host: str, port: int, ip: str, timeout: int = 10) -> dict:
    """Verified TLS handshake that reports protocol, cipher and certificate dates."""
    ctx = ssl.create_default_context()
    info: dict = {"verified": False}
    try:
        with socket.create_connection((ip, port), timeout) as raw:
            with ctx.wrap_socket(raw, server_hostname=host) as tls:
                cert = tls.getpeercert() or {}
                info.update(verified=True, protocol=tls.version(), cipher=(tls.cipher() or ("",))[0])
                not_after = cert.get("notAfter")
                if not_after:
                    expires = ssl.cert_time_to_seconds(not_after)
                    info["not_after"] = not_after
                    info["days_left"] = int((expires - time.time()) // 86400)
                for key in ("subject", "issuer"):
                    flat = {k: v for rdn in cert.get(key, ()) for (k, v) in rdn}
                    info[key] = flat.get("commonName") or flat.get("organizationName") or ""
    except ssl.SSLCertVerificationError as exc:
        info["error"] = exc.verify_message or str(exc)
    except ssl.SSLError as exc:
        info["error"] = f"TLS handshake failed: {exc.reason or exc}"
    except (OSError, socket.timeout) as exc:
        info["error"] = f"Could not connect: {exc.__class__.__name__}"
    return info
