"""Pure syslog decode + template mining (no I/O, no external deps).

These cover the ingest core carried over from the Ringdown prototype: PRI/severity
mapping, the three parse paths (Cisco IOS, RFC5424, RFC3164), the undecodable
fallback, and template masking/fingerprinting.
"""
from __future__ import annotations

from ringdown.syslog_parse import mine_template, parse_syslog


def test_cisco_ios_line():
    raw = "<189>123: rtr-core-1: Jun 30 14:03:11.001 UTC: %LINK-3-UPDOWN: Interface Gi0/1, changed state to down"
    ev = parse_syslog(raw, "10.0.0.9")
    assert ev["source"] == "rtr-core-1"          # host recovered from Cisco prefix, not peer
    assert ev["program"] == "%LINK-3-UPDOWN"
    assert ev["severity"] == 17                    # mnemonic level 3 -> OTel 17 (err)
    assert ev["severity_text"] == "err"
    assert "changed state to down" in ev["body"]


def test_rfc5424_line():
    raw = '<34>1 2026-06-30T14:03:11.000Z host-a app-b 4321 ID47 - core dumped'
    ev = parse_syslog(raw, "10.0.0.1")
    assert ev["source"] == "host-a"
    assert ev["program"] == "app-b"
    assert ev["body"] == "core dumped"
    assert ev["attributes"].get("procid") == "4321"
    assert ev["ts"].year == 2026 and ev["ts"].month == 6


def test_rfc3164_line():
    raw = "<13>Jun 30 14:03:11 web-3 sshd[2211]: Failed password for root"
    ev = parse_syslog(raw, "10.0.0.2")
    assert ev["source"] == "web-3"
    assert ev["program"] == "sshd"
    assert ev["attributes"].get("pid") == "2211"
    assert "Failed password" in ev["body"]


def test_undecodable_falls_back_to_peer():
    ev = parse_syslog("this is not syslog at all", "10.0.0.42")
    assert ev["source"] == "10.0.0.42"
    assert ev["body"] == "this is not syslog at all"
    assert ev["ts"] is not None                    # always stamped, never raises


def test_template_masks_variable_bits():
    fp1, t1 = mine_template("%LINK-3-UPDOWN", "Interface Gi0/1 changed state to down, ip 10.0.0.9")
    fp2, t2 = mine_template("%LINK-3-UPDOWN", "Interface Gi0/2 changed state to down, ip 10.0.0.7")
    assert t1 == t2                                # variable bits masked -> same shape
    assert fp1 == fp2
    assert "<*>" in t1 and "10.0.0" not in t1


def test_template_fingerprint_separates_programs():
    fp_a, _ = mine_template("progA", "value is 5")
    fp_b, _ = mine_template("progB", "value is 5")
    assert fp_a != fp_b                            # program is part of the fingerprint
