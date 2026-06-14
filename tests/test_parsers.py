import datetime as dt

from intune_analyzer.models import Level, Source
from intune_analyzer.parsers import base, parse_file, select
from intune_analyzer.parsers import defender, install, intune


def test_timestamp_formats():
    assert base.parse_timestamp("2026-06-10 09:14:22.014 hi") == \
        dt.datetime(2026, 6, 10, 9, 14, 22, 14000)
    assert base.parse_timestamp("2026-06-10 09:14:22 hi") == \
        dt.datetime(2026, 6, 10, 9, 14, 22)
    # ms with ':' separator (Intune style)
    assert base.parse_timestamp("2026-06-10 09:14:22:014 hi").microsecond == 14000
    # syslog style fills in current year
    ts = base.parse_timestamp("Jun 10 09:14:22 host")
    assert ts is not None and ts.month == 6 and ts.day == 10


def test_level_detection():
    assert base.detect_level("| E | something failed") == Level.ERROR
    assert base.detect_level("[ERROR] boom") == Level.ERROR
    assert base.detect_level("plain informational line") == Level.INFO
    assert base.detect_level("operation failed unexpectedly") == Level.ERROR
    assert base.detect_level("retrying connection") == Level.WARNING


def test_parser_selection_by_directory():
    # mdatp install.log must route to Defender, not the generic installer.
    assert select("/Library/Logs/Microsoft/mdatp/install.log") is defender
    assert select("/var/log/install.log") is install
    assert select("/Library/Logs/Microsoft/Intune/IntuneMDMAgent x.log") is intune


def test_parse_generic_continuation():
    text = ("2026-06-10 09:14:22.014 | E | something failed\n"
            "    at frame 1\n"
            "    at frame 2\n"
            "2026-06-10 09:14:23.000 | I | next line\n")
    entries = base.parse_generic(text, Source.INTUNE)
    assert len(entries) == 2
    assert "frame 1" in entries[0].raw
    assert entries[0].level == Level.ERROR


def test_parse_file_returns_source_and_entries():
    src, entries = parse_file("2026-06-10 09:00:00 | E | enrollment failed",
                              "/x/Intune/IntuneMDMAgent.log")
    assert src == Source.INTUNE
    assert entries and entries[0].level == Level.ERROR
