"""Per-protocol TLS acceptance enumeration.

scan.py does one handshake and records ssl.SSLSocket.version(), which is the
HIGHEST mutually supported protocol. A host that still accepts TLS 1.0 through
1.3 is therefore indistinguishable from a 1.3-only host -- both report
"TLSv1.3". That makes the deprecated-protocol half of a TLS baseline
unmeasurable.

This module pins each version in turn and reports acceptance per protocol.

Findings use only keys the bridge's tls-scanner redaction allowlist passes
(host, port, protocol, valid, cipher, error, type), so nothing is stripped
before Panther. `valid` means "the server accepted this protocol version".

The network call is isolated in probe_protocol() and injected, so
enumerate_protocols() and finding_for() are testable without a socket.
"""
from __future__ import annotations

import socket
import ssl

# Protocols whose continued acceptance is a baseline failure regardless of
# certificate validity.
DEPRECATED = ("SSLv2", "SSLv3", "TLSv1", "TLSv1.0", "TLSv1.1")

DEPRECATED_NOTE = "DEPRECATED PROTOCOL ACCEPTED"
FINDING_TYPE = "TLSProtocolScan"


def supported_versions():
    """(label, ssl.TLSVersion) pairs this client can actually pin.

    Older OpenSSL/LibreSSL builds refuse to select TLS 1.0/1.1 at all; those
    are reported as untestable rather than silently counted as refused.
    """
    candidates = [
        ("TLSv1.0", "TLSv1"),
        ("TLSv1.1", "TLSv1_1"),
        ("TLSv1.2", "TLSv1_2"),
        ("TLSv1.3", "TLSv1_3"),
    ]
    out = []
    for label, attr in candidates:
        ver = getattr(ssl.TLSVersion, attr, None)
        if ver is not None:
            out.append((label, ver))
    return out


def finding_for(host, port, protocol, accepted, cipher=None, error=None):
    """Build one finding. Pure -- no I/O."""
    finding = {
        "host": host,
        "port": port,
        "protocol": protocol,
        "valid": bool(accepted),
        "cipher": cipher,
        "type": FINDING_TYPE,
    }
    if accepted and protocol in DEPRECATED:
        finding["error"] = DEPRECATED_NOTE
    elif error:
        finding["error"] = error
    return finding


def probe_protocol(host, port, version, timeout=8.0):
    """Attempt a handshake pinned to exactly one protocol version.

    Returns (accepted, negotiated_protocol_or_None, cipher_or_None, error_or_None).
    Certificate validity is deliberately NOT checked -- this asks whether the
    protocol is offered, and an expired cert would otherwise mask that.
    """
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        ctx.minimum_version = version
        ctx.maximum_version = version
    except ValueError as e:
        return (False, None, None, "client cannot pin this version: {0}".format(e))
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cipher = ssock.cipher()
                return (True, ssock.version(), cipher[0] if cipher else None, None)
    except Exception as e:  # noqa: BLE001 - any failure means "not offered"
        return (False, None, None, "{0}: refused".format(type(e).__name__))


def enumerate_protocols(host, port=443, timeout=8.0, prober=probe_protocol,
                        versions=None):
    """One finding per protocol version. Injectable prober for tests."""
    findings = []
    for label, version in (versions if versions is not None else supported_versions()):
        accepted, negotiated, cipher, error = prober(host, port, version, timeout)
        findings.append(
            finding_for(host, port, negotiated or label, accepted, cipher, error)
        )
    return findings


def deprecated_accepted(findings):
    """The subset that is an actual baseline failure."""
    return [f for f in findings if f["valid"] and f["protocol"] in DEPRECATED]
