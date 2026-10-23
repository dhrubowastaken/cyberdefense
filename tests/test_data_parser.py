"""Unit tests for LogParser and SyntheticLogGenerator."""

from datetime import datetime
from cyberdefense.data_stream import LogParser, SyntheticLogGenerator
from cyberdefense.models import EventType


def test_parse_structured_line():
    line = "2026-10-23T01:15:00Z | AUTH_LOGIN | 192.168.1.105:50000 -> 10.0.0.5:22 | admin | FAILURE | 128 | SSH auth failed"
    event = LogParser.parse_line(line)
    assert event is not None
    assert event.source_ip == "192.168.1.105"
    assert event.dest_ip == "10.0.0.5"
    assert event.dest_port == 22
    assert event.event_type == EventType.AUTH_LOGIN
    assert event.status == "FAILURE"
    assert event.user == "admin"


def test_parse_syslog_auth_line():
    line = "Oct 23 01:15:10 web-srv sshd[1422]: Failed password for invalid user admin from 192.168.1.105 port 54321 ssh2"
    event = LogParser.parse_line(line)
    assert event is not None
    assert event.source_ip == "192.168.1.105"
    assert event.dest_port == 22
    assert event.event_type == EventType.AUTH_LOGIN
    assert event.status == "FAILURE"
    assert event.user == "admin"


def test_synthetic_generator_full_chain():
    gen = SyntheticLogGenerator()
    events = gen.generate_full_attack_chain()
    assert len(events) >= 30
    event_types = {e.event_type for e in events}
    assert EventType.CONNECTION in event_types
    assert EventType.AUTH_LOGIN in event_types
    assert EventType.PRIV_CHANGE in event_types
    assert EventType.DATA_TRANSFER in event_types
