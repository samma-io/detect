"""Tests for per-protocol TLS enumeration.

No network: probe_protocol is injected, so these run anywhere and cannot be
made to pass or fail by the state of an external host.

    docker run --rm -v "$(pwd):/app" -w /app python:3.12-slim \
      sh -c 'pip install -q pytest && python -m pytest tls-scanner/code -q'
"""
from __future__ import annotations

import ssl

import pytest

from protocols import (
    DEPRECATED_NOTE,
    FINDING_TYPE,
    deprecated_accepted,
    enumerate_protocols,
    finding_for,
    supported_versions,
)

V = [("TLSv1.0", ssl.TLSVersion.TLSv1), ("TLSv1.3", ssl.TLSVersion.TLSv1_3)]


def fake_prober(accept_labels, cipher="TLS_AES_128_GCM_SHA256"):
    """Accept only the named protocols; refuse everything else."""
    label_of = {ssl.TLSVersion.TLSv1: "TLSv1.0", ssl.TLSVersion.TLSv1_3: "TLSv1.3"}

    def prober(host, port, version, timeout):
        label = label_of[version]
        if label in accept_labels:
            return (True, label, cipher, None)
        return (False, None, None, "SSLError: refused")

    return prober


# --- finding_for: pure shape ------------------------------------------------

def test_accepted_deprecated_is_flagged():
    f = finding_for("h", 443, "TLSv1.0", accepted=True, cipher="X")
    assert f["valid"] is True
    assert f["error"] == DEPRECATED_NOTE


def test_accepted_modern_carries_no_error():
    f = finding_for("h", 443, "TLSv1.3", accepted=True, cipher="X")
    assert f["valid"] is True
    assert "error" not in f


def test_refused_keeps_the_probe_error_not_the_deprecated_note():
    f = finding_for("h", 443, "TLSv1.0", accepted=False, error="SSLError: refused")
    assert f["valid"] is False
    assert f["error"] == "SSLError: refused"


def test_finding_only_uses_redaction_allowlisted_keys():
    """The bridge drops any details key outside the tls-scanner allowlist."""
    allowed = {"host", "port", "protocol", "valid", "cipher", "error", "type"}
    f = finding_for("h", 443, "TLSv1.0", accepted=True, cipher="X")
    assert set(f) <= allowed, set(f) - allowed


def test_finding_type_is_the_one_the_bridge_switches_on():
    assert finding_for("h", 443, "TLSv1.3", True)["type"] == FINDING_TYPE


# --- enumerate_protocols ----------------------------------------------------

def test_one_finding_per_version_tested():
    out = enumerate_protocols("h", prober=fake_prober({"TLSv1.3"}), versions=V)
    assert len(out) == 2
    assert [f["protocol"] for f in out] == ["TLSv1.0", "TLSv1.3"]


def test_modern_only_host_yields_no_deprecated_failures():
    out = enumerate_protocols("h", prober=fake_prober({"TLSv1.3"}), versions=V)
    assert deprecated_accepted(out) == []


def test_legacy_host_is_caught():
    """The case the single-handshake scanner cannot see: 1.0 AND 1.3 both live."""
    out = enumerate_protocols("h", prober=fake_prober({"TLSv1.0", "TLSv1.3"}), versions=V)
    bad = deprecated_accepted(out)
    assert [f["protocol"] for f in bad] == ["TLSv1.0"]


def test_refused_protocol_is_not_a_failure():
    out = enumerate_protocols("h", prober=fake_prober(set()), versions=V)
    assert all(f["valid"] is False for f in out)
    assert deprecated_accepted(out) == []


def test_untestable_version_is_not_counted_as_refused_silently():
    def prober(host, port, version, timeout):
        return (False, None, None, "client cannot pin this version: x")

    out = enumerate_protocols("h", prober=prober, versions=V)
    assert all("client cannot pin" in f["error"] for f in out)


def test_supported_versions_is_non_empty_and_includes_tls13():
    labels = [label for label, _ in supported_versions()]
    assert "TLSv1.3" in labels
