"""Address resolution and connecting that works for IPv4, IPv6 and dual-stack.

A target may be a hostname with A and/or AAAA records, an IPv4 literal or an
IPv6 literal. ``resolve`` asks for every family (``AF_UNSPEC``) and keeps the
order the resolver returns; ``connect_any`` tries each address until one
accepts the TCP connection. ``endpoint.host`` in a finding stays the name
that was given; the address actually used goes under ``raw``.

When no address accepts, the error raised is the one from an address this
pod can route to: "Network is unreachable" for IPv6 in an IPv4-only pod
network says nothing about the host, so it never hides the IPv4 answer. Its
message names every address tried. ``HTTPConnection``, ``HTTPSConnection``
and the two urllib handlers connect the same way.

``await_egress`` holds a scan until the pod's first connection goes through:
some NetworkPolicy controllers (k3s's kube-router) reject a new pod's traffic
for about a second until they have programmed its address.
"""

import errno
import http.client
import os
import socket
import sys
import time
import urllib.parse
import urllib.request

FAMILY_NAMES = {socket.AF_INET: "ipv4", socket.AF_INET6: "ipv6"}

# This pod has no path to that address at all (no IPv6 route in an IPv4-only
# pod network), as opposed to an answer from the host or the network.
UNROUTABLE_ERRNOS = frozenset((errno.ENETUNREACH, errno.EAFNOSUPPORT, errno.EADDRNOTAVAIL))

ENV_EGRESS_WAIT = "SAMMA_EGRESS_WAIT_SECONDS"
DEFAULT_EGRESS_WAIT = 10.0


class ResolvedAddress(object):
    __slots__ = ("family", "address", "sockaddr")

    def __init__(self, family, address, sockaddr):
        self.family = family
        self.address = address
        self.sockaddr = sockaddr

    @property
    def family_name(self):
        return FAMILY_NAMES.get(self.family, str(self.family))

    def describe(self):
        return {"address": self.address, "family": self.family_name}

    def __repr__(self):
        return "ResolvedAddress(%s %s)" % (self.family_name, self.address)


def resolve(host, port=None, getaddrinfo=socket.getaddrinfo):
    """Every address ``host`` resolves to, both families, duplicates removed.

    Raises ``socket.gaierror`` when the name does not resolve at all, as the
    socket module does; a scanner lets that surface as a failed run.
    """
    infos = getaddrinfo(host, port, socket.AF_UNSPEC, socket.SOCK_STREAM)
    seen = set()
    addresses = []
    for family, _socktype, _proto, _canonname, sockaddr in infos:
        if family not in FAMILY_NAMES:
            continue
        address = sockaddr[0]
        key = (family, address)
        if key in seen:
            continue
        seen.add(key)
        addresses.append(ResolvedAddress(family, address, sockaddr))
    if not addresses:
        raise socket.gaierror("no IPv4 or IPv6 address for %r" % (host,))
    return addresses


def with_port(resolved, port):
    """A copy of ``resolved`` whose sockaddr points at ``port``."""
    sockaddr = (resolved.sockaddr[0], port) + tuple(resolved.sockaddr[2:])
    return ResolvedAddress(resolved.family, resolved.address, sockaddr)


def unroutable(exc):
    """True when ``exc`` says this pod cannot reach that address family at all."""
    return isinstance(exc, OSError) and exc.errno in UNROUTABLE_ERRNOS


def _reason(exc):
    if isinstance(exc, OSError) and exc.strerror:
        return exc.strerror
    text = str(exc).strip()
    return text or type(exc).__name__


def connection_error(host, port, errors):
    """The error to raise when no address of ``host`` accepted ``port``.

    ``errors`` is ``[(ResolvedAddress, exception)]`` in the order tried. The
    last error from an address this pod can route to wins, keeping its class
    and errno, so a caller that treats ``ConnectionRefusedError`` or a timeout
    as "nothing listens" still does; with more than one address the message
    names each one and what it answered.
    """
    if not errors:
        return OSError("no address to connect to for %r" % (host,))
    routable = [exc for _addr, exc in errors if not unroutable(exc)]
    chosen = routable[-1] if routable else errors[-1][1]
    if len(errors) == 1:
        return chosen
    message = "no address of %s accepted port %s (%s)" % (
        host, port, "; ".join("%s %s: %s" % (addr.family_name, addr.address, _reason(exc))
                              for addr, exc in errors))
    cls = type(chosen) if isinstance(chosen, OSError) else OSError
    code = chosen.errno if isinstance(chosen, OSError) else None
    try:
        error = cls(code, message) if code is not None else cls(message)
    except TypeError:
        error = OSError(code, message)
    error.__cause__ = chosen
    error.attempts = list(errors)
    return error


def connect_any(host, port, timeout, addresses=None, socket_factory=socket.socket):
    """Connect to the first address of ``host`` that accepts; return ``(sock, resolved)``.

    Raises :func:`connection_error` when no address accepts, or
    ``socket.gaierror`` when the name does not resolve.
    """
    candidates = addresses if addresses is not None else resolve(host, port)
    errors = []
    for candidate in candidates:
        candidate = with_port(candidate, port)
        sock = socket_factory(candidate.family, socket.SOCK_STREAM)
        try:
            sock.settimeout(timeout)
            sock.connect(candidate.sockaddr)
            return sock, candidate
        except OSError as exc:
            errors.append((candidate, exc))
            sock.close()
    raise connection_error(host, port, errors)


def create_connection(address, timeout=socket._GLOBAL_DEFAULT_TIMEOUT, source_address=None,
                      connect=None, **_ignored):
    """``socket.create_connection`` through :func:`connect_any` (what http.client calls)."""
    host, port = address[0], address[1]
    if timeout is socket._GLOBAL_DEFAULT_TIMEOUT:
        timeout = socket.getdefaulttimeout()
    sock, _used = (connect or connect_any)(host, port, timeout)
    return sock


class HTTPConnection(http.client.HTTPConnection):
    """``http.client.HTTPConnection`` that connects with :func:`connect_any`."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._create_connection = create_connection


class HTTPSConnection(http.client.HTTPSConnection):
    """``http.client.HTTPSConnection`` that connects with :func:`connect_any`."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._create_connection = create_connection


class HTTPHandler(urllib.request.HTTPHandler):
    def http_open(self, req):
        return self.do_open(HTTPConnection, req)


class HTTPSHandler(urllib.request.HTTPSHandler):
    def https_open(self, req):
        return self.do_open(HTTPSConnection, req, context=self._context)


class EgressResult(object):
    __slots__ = ("waited", "ready", "attempts", "error")

    def __init__(self, waited, ready, attempts, error=None):
        self.waited = waited
        self.ready = ready
        self.attempts = attempts
        self.error = error


def nats_address(environ):
    """``(host, port)`` of the NATS server the scan publishes to, or ``None``."""
    if environ.get("NATS_ENABLED", "False") == "False":
        return None
    try:
        parts = urllib.parse.urlsplit(environ.get("NATS_URL", ""))
        host, port = parts.hostname, parts.port or 4222
    except ValueError:
        return None
    return (host, port) if host else None


def await_egress(environ=None, budget=None, connect=None, sleep=time.sleep,
                 clock=time.monotonic, stderr=None):
    """Wait until this pod can open a TCP connection, at most ``budget`` seconds.

    A NetworkPolicy controller that programs a new pod asynchronously (k3s's
    kube-router) rejects the pod's first connections for about a second, so
    a scanner that connects right away records a refused or unreachable
    target, or a closed port, that is not there. The probe is the NATS
    server in ``NATS_URL``, the one destination every scanner's policy lets
    it reach; once that connects, the pod's egress rules are in place. The
    scan goes ahead either way: when NATS never answers, publishing fails
    later and says so. Returns an :class:`EgressResult`, or ``None`` when
    there is no NATS to probe or the wait is switched off (``0``).
    """
    env = os.environ if environ is None else environ
    target = nats_address(env)
    if target is None:
        return None
    if budget is None:
        try:
            budget = float(env.get(ENV_EGRESS_WAIT, DEFAULT_EGRESS_WAIT))
        except ValueError:
            budget = DEFAULT_EGRESS_WAIT
    if budget <= 0:
        return None
    connect = connect or connect_any
    out = sys.stderr if stderr is None else stderr
    start = clock()
    attempts = 0
    delay = 0.1
    while True:
        attempts += 1
        try:
            sock, _used = connect(target[0], target[1], min(1.0, budget))
        except OSError as exc:  # socket.gaierror too: DNS waits for the same rules
            last = exc
        else:
            sock.close()
            waited = clock() - start
            if attempts > 1:
                out.write("samma: network ready after %.2fs (%d attempts)\n" % (waited, attempts))
            return EgressResult(waited, True, attempts)
        waited = clock() - start
        if waited >= budget:
            out.write("samma: NATS at %s:%s not reachable after %.1fs (%s); scanning anyway\n"
                      % (target[0], target[1], waited, _reason(last)))
            return EgressResult(waited, False, attempts, last)
        sleep(min(delay, budget - waited))
        delay = min(delay * 2, 1.0)


def probe_port(resolved, port, timeout, socket_factory=socket.socket):
    """``True`` when ``port`` accepts a TCP connection on ``resolved``."""
    candidate = with_port(resolved, port)
    sock = socket_factory(candidate.family, socket.SOCK_STREAM)
    try:
        sock.settimeout(timeout)
        return sock.connect_ex(candidate.sockaddr) == 0
    finally:
        sock.close()
