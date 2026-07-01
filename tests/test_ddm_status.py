import json

from intune_analyzer import apple_ddm
from intune_analyzer.models import Level, Source
from intune_analyzer.parsers import ddm_status, parse_file, select


def test_ddm_status_parser_selection():
    assert select("/x/DeviceStatusReport.json") is ddm_status
    assert select("/x/MDMCommandResponse.json") is ddm_status
    # An unrelated JSON file (no matching filename hint) is not claimed.
    assert select("/x/random-notes.json") is None


def test_status_report_declarations():
    payload = {
        "StatusItems": {
            "management": {
                "declarations": {
                    "activations": [
                        {"active": True, "identifier": "good", "valid": "valid"},
                        {"active": False, "identifier": "bad", "valid": "invalid"},
                    ],
                    "configurations": [
                        {"identifier": "clean-config", "reasons": []},
                        {"identifier": "broken-config",
                         "reasons": [{"description": "bad payload"}]},
                    ],
                }
            }
        }
    }
    entries = ddm_status.parse(json.dumps(payload), "ddm-status.json")
    by_ident = {e.message.split()[2]: e for e in entries
               if e.message.startswith(("DDM declaration", "DDM configuration"))}
    assert by_ident["good"].level == Level.INFO
    assert by_ident["bad"].level == Level.ERROR
    assert "ddm-status: declaration-inactive identifier=bad" in by_ident["bad"].raw
    assert by_ident["clean-config"].level == Level.INFO
    assert by_ident["broken-config"].level == Level.ERROR
    assert "bad payload" in by_ident["broken-config"].message


def test_status_report_app_list_and_softwareupdate():
    payload = {
        "StatusItems": {
            "app": {"managed": {"list": [
                {"identifier": "com.foo.bar", "version": "1.0", "state": "managed"},
                {"identifier": "com.foo.baz", "version": "2.0", "state": "failed"},
            ]}},
            "softwareupdate": {
                "install-state": "failed",
                "failure-reason": {"count": 1, "reason": "download-failed",
                                   "timestamp": "2026-01-01T00:00:00Z"},
            },
        }
    }
    entries = ddm_status.parse(json.dumps(payload), "status.json")
    messages = "\n".join(e.message for e in entries)
    assert "com.foo.bar" in messages and "state=managed" in messages
    assert "com.foo.baz" in messages and "state=failed" in messages
    assert "install-state=failed" in messages
    assert "failure-reason: count=1 reason=download-failed" in messages
    # decode_failure_reasons should surface the human-readable text too.
    assert "Download failed" in messages


def test_mdm_error_envelope_decoded():
    payload = {
        "Status": "Error",
        "ErrorChain": [
            {"ErrorDomain": "MCMDMErrorDomain", "ErrorCode": 12040,
             "LocalizedDescription": "Please log in to your iTunes Store account"},
        ],
    }
    entries = ddm_status.parse(json.dumps(payload), "MDMCommandResponse.json")
    assert len(entries) == 1
    assert entries[0].level == Level.ERROR
    assert "ErrorDomain=MCMDMErrorDomain" in entries[0].message
    assert "iTunes/App Store account" in entries[0].message  # decoded text
    assert "mdm-error: domain=MCMDMErrorDomain code=12040" in entries[0].raw


def test_mdm_error_envelope_unknown_code_falls_back_to_device_text():
    payload = {"ErrorChain": [
        {"ErrorDomain": "SomeOtherDomain", "ErrorCode": 999,
         "LocalizedDescription": "Some device-supplied text"},
    ]}
    entries = ddm_status.parse(json.dumps(payload), "error.json")
    assert "Some device-supplied text" in entries[0].message


def test_non_ddm_json_yields_no_entries():
    assert ddm_status.parse(json.dumps({"foo": "bar"}), "statusreport.json") == []
    assert ddm_status.parse("not json at all", "statusreport.json") == []


def test_decode_mdm_error_unknown_pair_returns_empty():
    assert apple_ddm.decode_mdm_error("Nope", 1) == ""
    assert apple_ddm.decode_mdm_error("MCMDMErrorDomain", "not-an-int") == ""


def test_parse_file_dispatches_to_ddm_status():
    text = json.dumps({"StatusItems": {"app": {"managed": {"list": []}}}})
    source, entries = parse_file(text, "/x/DeviceStatusReport.json")
    assert source == Source.SYSTEM
