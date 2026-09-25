"""Regression tests for shared event shaping used by custom commands."""

import event_generator
from utility import get_dict, nested_dict_iter


def test_batch_groups_records_by_ip_field():
    records = [
        {"src": "1.1.1.1", "id": "a"},
        {"src": "8.8.8.8", "id": "b"},
        {"src": "1.1.1.1", "id": "c"},
        {"id": "missing"},
    ]
    chunks = event_generator.batch(records, "src", events_per_chunk=1000, logger=__import__("logging").getLogger("x"))
    assert set(chunks.keys()) == {0}
    events, ips = chunks[0]
    assert len(events) == 4
    assert set(ips) == {"1.1.1.1", "8.8.8.8"}


def test_batch_splits_when_unique_ips_exceed_chunk_size(logger):
    records = [{"src": "1.1.1.{}".format(i)} for i in range(1, 6)]
    chunks = event_generator.batch(records, "src", events_per_chunk=2, logger=logger, optimize_requests=False)
    assert len(chunks) == 3
    assert len(chunks[0][1]) == 2
    assert len(chunks[1][1]) == 2
    assert len(chunks[2][1]) == 1


def test_nested_dict_iter_prefixes_scanner_found_fields():
    payload = {
        "ip": "1.2.3.4",
        "internet_scanner_intelligence": {"found": True, "classification": "malicious"},
        "business_service_intelligence": {"found": False, "trust_level": "1"},
    }
    flattened = nested_dict_iter(payload)
    assert flattened["ip"] == "1.2.3.4"
    assert flattened["internet_scanner_intelligence_found"] is True
    assert flattened["classification"] == "malicious"
    assert flattened["business_service_intelligence_found"] is False
    assert flattened["trust_level"] == "1"


def test_make_valid_event_generating_command_sets_source_fields():
    data = {"ip": "8.8.8.8", "internet_scanner_intelligence": {"found": True, "classification": "benign"}}
    event = event_generator.make_valid_event("quick", data, first_event=True)
    assert event["source"] == "greynoise"
    assert event["sourcetype"] == "greynoise"
    assert event["ip"] == "8.8.8.8"
    assert event["_raw"]["results"] == data
    assert "internet_scanner_intelligence_found" in event
    assert event["internet_scanner_intelligence_found"] is True


def test_make_valid_event_transforming_command_prefixes_fields():
    record = {"src": "1.1.1.1", "action": "allow"}
    data = {"ip": "1.1.1.1", "internet_scanner_intelligence": {"found": True, "classification": "malicious"}}
    event = event_generator.make_valid_event("multi", data, first_event=True, record=record)
    assert event["src"] == "1.1.1.1"
    assert event["greynoise_ip"] == "1.1.1.1"
    assert event["greynoise_internet_scanner_intelligence_found"] is True
    assert event["greynoise_internet_scanner_intelligence_classification"] == "malicious"


def test_make_invalid_event_transforming_command_uses_greynoise_prefix():
    record = {"src": "not-an-ip"}
    event = event_generator.make_invalid_event("multi", {"ip": "not-an-ip", "error": "Invalid IP"}, True, record)
    assert event["greynoise_ip"] == "not-an-ip"
    assert event["greynoise_error"] == "Invalid IP"


def test_event_processor_matches_quick_results_and_marks_invalid_ips(logger):
    records = ([{"src": "1.1.1.1"}, {"src": "999.1.1.1"}], ["1.1.1.1", "999.1.1.1"])
    result = {
        "message": "ok",
        "response": [
            {
                "ip": "1.1.1.1",
                "internet_scanner_intelligence": {"found": True, "classification": "unknown"},
            }
        ],
    }
    events = list(event_generator.event_processor(records, result, "multi", "src", logger))
    assert len(events) == 2
    assert events[0]["greynoise_ip"] == "1.1.1.1"
    assert events[1]["greynoise_error"]


def test_event_processor_strips_raw_data_for_enrich(logger):
    records = ([{"src": "1.1.1.1"}], ["1.1.1.1"])
    result = {
        "message": "ok",
        "response": {"ip": "1.1.1.1", "classification": "malicious", "raw_data": {"scan": [1]}},
    }
    events = list(event_generator.event_processor(records, result, "enrich", "src", logger))
    assert len(events) == 1
    assert "greynoise_raw_data" not in events[0]
    assert events[0]["greynoise_classification"] == "malicious"


def test_get_dict_covers_command_methods():
    for method in ("ip", "quick", "query", "multi", "enrich", "callback", "callback_feed", "feed", "recall"):
        fields = get_dict(method)
        assert isinstance(fields, dict)
        assert fields
