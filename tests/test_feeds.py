"""Tests for GreyNoise feed indicator mapping, GNQL construction, and saved searches."""

from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import gncallbackfeed
import gnfeed
from conf_utils import load_conf, table_fields
from saved_search_utils import FEED_SELECTION_QUERIES, build_feed_gnql_query

SCANNER_HIT = {
    "ip": "203.0.113.10",
    "source_workspaces": ["greynoise", "community"],
    "internet_scanner_intelligence": {
        "actor": "unknown",
        "first_seen": "2024-01-01",
        "last_seen": "2024-06-01",
        "classification": "malicious",
        "cves": ["CVE-2024-0001", "CVE-2024-0001"],
        "spoofable": True,
        "tags": [{"name": "Scanner"}, {"name": "Mirai"}, "legacy-tag"],
        "metadata": {
            "source_country": "US",
            "asn": "AS64500",
            "organization": "Example Org",
        },
    },
}


def test_feed_selection_queries_match_historical_gnql():
    assert FEED_SELECTION_QUERIES["ALL"] == "last_seen:1d"
    assert FEED_SELECTION_QUERIES["MALICIOUS"] == "last_seen:1d classification:malicious"
    assert FEED_SELECTION_QUERIES["SUSPICIOUS"] == "last_seen:1d classification:suspicious"
    assert (
        FEED_SELECTION_QUERIES["MALICIOUS_BENIGN"] == "last_seen:1d (classification:benign OR classification:malicious)"
    )
    assert FEED_SELECTION_QUERIES["MALICIOUS_SUSPICIOUS_BENIGN"] == "last_seen:1d (-classification:unknown)"
    assert FEED_SELECTION_QUERIES["BENIGN"] == "last_seen:1d classification:benign"


def test_build_feed_gnql_query_appends_community_workspace_filter():
    query = build_feed_gnql_query("MALICIOUS", include_community_dataset=1)
    assert query == (
        "last_seen:1d classification:malicious AND " "(workspace_label:greynoise OR workspace_label:community)"
    )


def test_build_feed_gnql_query_defaults_unknown_selection_to_benign():
    assert build_feed_gnql_query("NOT_A_REAL_OPTION") == "last_seen:1d classification:benign"
    assert "workspace_label" not in build_feed_gnql_query("ALL", include_community_dataset="false")


def test_normalize_feed_hit_maps_lookup_schema():
    event = gnfeed.normalize_feed_hit(SCANNER_HIT)
    assert event["_key"] == "203.0.113.10"
    assert event["ip"] == "203.0.113.10"
    assert event["actor"] == "unknown"
    assert event["classification"] == "malicious"
    assert event["tags"] == "Scanner,Mirai,legacy-tag"
    assert event["cve"] == "CVE-2024-0001"
    assert event["source_country"] == "US"
    assert event["asn"] == "AS64500"
    assert event["organization"] == "Example Org"
    assert event["spoofable"] is True
    assert event["source_workspaces"] == "greynoise,community"
    assert "_raw" not in event


def test_normalize_feed_hit_rejects_missing_ip():
    assert gnfeed.normalize_feed_hit({"classification": "malicious"}) is None
    assert gnfeed.normalize_feed_hit("not-a-dict") is None


def test_normalize_spoofable_coerces_strings():
    assert gnfeed._normalize_spoofable("true") is True
    assert gnfeed._normalize_spoofable("0") is False
    assert gnfeed._normalize_spoofable(None) is None


def test_feed_scroller_excludes_raw_and_heavy_fields(logger):
    client = MagicMock()
    client.stats.return_value = {"count": 1}
    client.query.return_value = {
        "request_metadata": {"complete": True},
        "data": [SCANNER_HIT],
    }
    events = list(gnfeed.feed_scroller(client, logger, "last_seen:1d", 10, 10, include_raw=False))
    assert len(events) == 1
    assert "_raw" not in events[0]
    kwargs = client.query.call_args.kwargs
    assert kwargs["exclude_raw"] is True
    assert kwargs["exclude_fields"] == gnfeed.FEED_EXCLUDE_FIELDS


def test_feed_scroller_attaches_raw_when_requested(logger):
    client = MagicMock()
    client.stats.return_value = {"count": 1}
    client.query.return_value = {
        "request_metadata": {"complete": True},
        "data": [SCANNER_HIT],
    }
    events = list(gnfeed.feed_scroller(client, logger, "last_seen:1d", 10, 10, include_raw=True))
    assert "203.0.113.10" in events[0]["_raw"]


def test_latest_feed_query_uses_newest_kv_record(logger):
    service = MagicMock()
    service.kvstore = {
        "gn_feed_collection": SimpleNamespace(
            data=SimpleNamespace(
                query=lambda: [
                    {"query": "old", "created": 1},
                    {"query": " last_seen:1d ", "created": 9},
                ]
            )
        )
    }
    with patch("gnfeed.create_service", return_value=service):
        assert gnfeed._latest_feed_query("sess", logger) == "last_seen:1d"


def test_ingest_feed_enabled_parses_conf_flags():
    conf = MagicMock()
    conf.get.return_value = {"ingest_feed_to_index": "1"}
    with patch("gnfeed.get_conf_file", return_value=conf):
        assert gnfeed._ingest_feed_enabled("sess") is True
    conf.get.return_value = {"ingest_feed_to_index": "no"}
    with patch("gnfeed.get_conf_file", return_value=conf):
        assert gnfeed._ingest_feed_enabled("sess") is False


def test_callback_filters_from_conf():
    filters = gncallbackfeed._build_filters_from_conf(
        {
            "is_stage_1": "true",
            "is_stage_2": "any",
            "has_files": "0",
            "file_type": "exe",
            "scanner_ips": "1.1.1.1, 8.8.8.8",
            "ips": "",
        }
    )
    assert filters["is_stage_1"] is True
    assert filters["is_stage_2"] is None
    assert filters["has_files"] is False
    assert filters["file_type"] == "exe"
    assert filters["scanner_ips"] == ["1.1.1.1", "8.8.8.8"]
    assert filters["ips"] is None


def test_normalize_callback_item_flattens_files_and_bools():
    event = gncallbackfeed._normalize_callback_item(
        {
            "callback_ip": "198.51.100.9",
            "is_stage_1": True,
            "has_files": False,
            "source_workspaces": ["ws1", "ws2"],
            "files": [{"name": "drop.bin", "type": "bin", "sha256": "abc"}],
        }
    )
    assert event["ip"] == "198.51.100.9"
    assert event["is_stage_1"] == "true"
    assert event["has_files"] == "false"
    assert event["source_workspaces"] == "ws1,ws2"
    assert event["file_names"] == "drop.bin"
    assert event["file_types"] == "bin"
    assert event["file_hashes"] == "abc"


def test_callback_list_scroller_pages_until_short_page(logger):
    client = MagicMock()
    client.callback_list.side_effect = [
        {"data": [{"ip": "1.1.1.1"}, {"ip": "2.2.2.2"}], "total": 3},
        {"data": [{"ip": "3.3.3.3"}]},
    ]
    events = list(gncallbackfeed.callback_list_scroller(client, logger, {"is_stage_1": True}, page_size=2))
    assert [event["ip"] for event in events] == ["1.1.1.1", "2.2.2.2", "3.3.3.3"]
    assert client.callback_list.call_args_list[0].kwargs["page"] == 0
    assert client.callback_list.call_args_list[1].kwargs["page"] == 1


def test_feed_savedsearches_write_expected_lookup_fields(app_dir):
    searches = load_conf(app_dir / "default" / "savedsearches.conf")
    transforms = load_conf(app_dir / "default" / "transforms.conf")
    indicator_fields = {field.strip() for field in transforms.get("greynoise_indicators", "fields_list").split(",")}
    callback_fields = {
        field.strip() for field in transforms.get("greynoise_callback_indicators", "fields_list").split(",")
    }

    for stanza in ("greynoise_feed", "greynoise_feed_once"):
        search = searches.get(stanza, "search")
        assert "| gnfeed" in search
        assert "`greynoise_feed_partial_search`" in search
        assert "outputlookup greynoise_indicators" in search
        table_fields_set = table_fields(search)
        assert table_fields_set == indicator_fields

    for stanza in ("greynoise_callback_feed", "greynoise_callback_feed_once"):
        search = searches.get(stanza, "search")
        assert "| gncallbackfeed" in search
        assert "eval _key = ip" in search
        assert "outputlookup greynoise_callback_indicators" in search
        table_fields_set = table_fields(search)
        assert table_fields_set == callback_fields


def test_feed_purge_and_intel_population_searches(app_dir):
    searches = load_conf(app_dir / "default" / "savedsearches.conf")
    purge = searches.get("greynoise_feed_purge", "search")
    assert "inputlookup greynoise_indicators" in purge
    assert "where last_seen > nowstring" in purge

    callback_purge = searches.get("greynoise_callback_feed_purge", "search")
    assert "inputlookup greynoise_callback_indicators" in callback_purge

    for classification in ("malicious", "suspicious", "unknown", "benign"):
        stanza = "greynoise_populate_ip_intel_{}".format(classification)
        search = searches.get(stanza, "search")
        assert 'classification="{}"'.format(classification) in search
        assert "outputlookup greynoise_ip_intel_{}".format(classification) in search


def test_feed_macros_and_settings_spec(app_dir):
    macros = load_conf(app_dir / "default" / "macros.conf")
    assert macros.get("greynoise_feed_partial_search", "definition") == "| noop"
    spec = (app_dir / "README" / "app_greynoise_settings.conf.spec").read_text(encoding="utf-8")
    assert "[feed_configuration]" in spec
    assert "include_community_dataset" in spec
    assert "ingest_feed_to_index" in spec
    assert "[callback_feed_configuration]" in spec
