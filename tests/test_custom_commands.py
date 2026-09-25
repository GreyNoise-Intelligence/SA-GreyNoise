"""Behavioral tests for GreyNoise custom search commands."""

from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest
from gncallback import GNCallbackCommand
from gncve import GNCVECommand
from gnenrich import GNEnrichCommand
from gnfeed import GNFeedCommand
from gnfilter import GNFilterCommand, event_filter
from gnip import IPContextCommand
from gnippsychic import GNIPPsychicCommand
from gniptimeline import GNIPTimelineCommand
from gniptimeline import response_scroller as timeline_scroller
from gnmulti import GNMultiCommand
from gnquery import GNQueryCommand, _strip_gnquery_hit_fields, response_scroller
from gnquick import GNQuickCommand
from gnrecall import GNRecallCommand, recall_stats_generator, recall_timeseries_scroller
from gnstats import GNStatsCommand
from greynoise.exceptions import RequestFailure
from greynoise_overview import OverviewCommand


def test_gnip_emits_context_event(logger, command_metadata):
    command = IPContextCommand()
    command.ip = " 8.8.8.8 "
    command._metadata = command_metadata
    command.write_error = MagicMock()
    context = {
        "ip": "8.8.8.8",
        "internet_scanner_intelligence": {"found": True, "classification": "benign"},
    }
    with patch("gnip.get_response_for_generating", return_value=context), patch("gnip.GreyNoise"):
        events = list(command.do_generate("key", "", logger))
    assert len(events) == 1
    assert events[0]["ip"] == "8.8.8.8"
    assert events[0]["source"] == "greynoise"
    assert events[0]["internet_scanner_intelligence_found"] is True


def test_gnquick_generating_mode_yields_api_rows(logger, ready_eventing_command):
    command = ready_eventing_command(GNQuickCommand())
    command.ip = "1.1.1.1, 8.8.8.8"
    command.ip_field = None
    command.api_client = MagicMock()
    command.api_client.quick.return_value = [
        {"ip": "1.1.1.1", "internet_scanner_intelligence": {"found": True, "classification": "malicious"}},
        {"ip": "8.8.8.8", "internet_scanner_intelligence": {"found": False, "classification": "unknown"}},
    ]
    events = list(command.transform([]))
    assert [event["ip"] for event in events] == ["1.1.1.1", "8.8.8.8"]
    command.api_client.quick.assert_called_once_with(["1.1.1.1", "8.8.8.8"])


def test_gnquick_rejects_both_ip_and_ip_field(ready_eventing_command):
    command = ready_eventing_command(GNQuickCommand())
    command.ip = "1.1.1.1"
    command.ip_field = "src"
    with pytest.raises(SystemExit):
        list(command.transform([]))
    command.write_error.assert_called()


def test_gnquick_transforming_mode_uses_multi_method(ready_eventing_command):
    command = ready_eventing_command(GNQuickCommand())
    command.ip = None
    command.ip_field = "src"
    command.api_client = MagicMock()
    records = [{"src": "1.1.1.1"}]
    with patch(
        "event_generator.get_all_events", return_value=iter([{"src": "1.1.1.1", "greynoise_ip": "1.1.1.1"}])
    ) as mocked:
        events = list(command.transform(records))
    assert events[0]["greynoise_ip"] == "1.1.1.1"
    assert mocked.call_args.args[2] == "multi"


def test_gnmulti_enriches_events_and_skips_es_when_disabled(ready_eventing_command):
    command = ready_eventing_command(GNMultiCommand())
    command.ip_field = "gn_ip"
    command.api_client = MagicMock()
    conf = MagicMock()
    conf.get.return_value = {"update_risk_score_to_splunk_es": 0}
    enriched = {
        "gn_ip": "1.2.3.4",
        "greynoise_ip": "1.2.3.4",
        "greynoise_internet_scanner_intelligence_classification": "malicious",
        "greynoise_internet_scanner_intelligence_found": True,
        "greynoise_business_service_intelligence_found": False,
    }
    with patch("gnmulti.utility.get_conf_file", return_value=conf), patch(
        "event_generator.get_all_events", return_value=iter([enriched])
    ):
        events = list(command.transform([{"gn_ip": "1.2.3.4"}]))
    assert events == [enriched]


def test_gnenrich_uses_ip_multi(ready_eventing_command):
    command = ready_eventing_command(GNEnrichCommand())
    command.ip_field = "src"
    command.api_client = MagicMock()
    with patch("event_generator.get_all_events", return_value=iter([{"src": "1.1.1.1"}])) as mocked:
        list(command.transform([{"src": "1.1.1.1"}]))
    assert mocked.call_args.args[2] == "ip_multi"


def test_gnfilter_keeps_only_noisy_events():
    records = (
        [
            {"src": "1.1.1.1"},
            {"src": "8.8.8.8"},
            {"src": ""},
        ],
        ["1.1.1.1", "8.8.8.8"],
    )
    result = {
        "message": "ok",
        "response": [
            {"ip": "1.1.1.1", "internet_scanner_intelligence": True},
            {"ip": "8.8.8.8", "internet_scanner_intelligence": False},
        ],
    }
    noisy = list(event_filter(0, result, records, "src", True, "filter"))
    quiet = list(event_filter(0, result, records, "src", False, "filter"))
    assert [event["src"] for event in noisy] == ["1.1.1.1"]
    assert [event["src"] for event in quiet] == ["8.8.8.8", ""]


def test_gnfilter_command_wires_event_filter(ready_eventing_command):
    command = ready_eventing_command(GNFilterCommand())
    command.ip_field = "src"
    command.noise_events = "true"
    command.api_client = MagicMock()
    chunk = {0: ([{"src": "1.1.1.1"}], ["1.1.1.1"])}
    api_result = {
        "message": "ok",
        "response": [{"ip": "1.1.1.1", "internet_scanner_intelligence": True}],
    }
    with patch("event_generator.batch", return_value=chunk), patch(
        "event_generator.get_all_events", return_value=iter([(0, api_result)])
    ):
        events = list(command.transform([{"src": "1.1.1.1"}]))
    assert len(events) == 1
    assert events[0]["src"] == "1.1.1.1"


def test_gnquery_strips_verbose_tag_and_destination_fields():
    hit = {
        "ip": "1.2.3.4",
        "internet_scanner_intelligence": {
            "metadata": {
                "destination_countries": ["US"],
                "destination_country_codes": ["US"],
                "asn": "AS1",
            }
        },
        "tags": [{"name": "Mirai", "references": ["https://x"], "description": "bot"}],
    }
    _strip_gnquery_hit_fields(hit)
    assert "destination_countries" not in hit["internet_scanner_intelligence"]["metadata"]
    assert hit["internet_scanner_intelligence"]["metadata"]["asn"] == "AS1"
    assert hit["tags"][0] == {"name": "Mirai"}


def test_gnquery_scroller_pages_until_result_size(logger):
    client = MagicMock()
    client.stats.return_value = {"count": 3}
    client.query.side_effect = [
        {
            "request_metadata": {"scroll": "abc", "complete": False},
            "data": [{"ip": "1.1.1.1"}, {"ip": "2.2.2.2"}],
        },
        {
            "request_metadata": {"complete": True},
            "data": [{"ip": "3.3.3.3"}, {"ip": "4.4.4.4"}],
        },
    ]
    events = list(response_scroller(client, logger, "classification:malicious", 3, 2, True))
    assert [event["ip"] for event in events][:3] == ["1.1.1.1", "2.2.2.2", "3.3.3.3"]
    assert client.query.call_count == 2
    assert client.query.call_args_list[0].kwargs["size"] == 2
    assert client.query.call_args_list[0].kwargs["exclude_raw"] is True


def test_gnquery_command_validates_empty_query(logger, command_metadata):
    command = GNQueryCommand()
    command.query = ""
    command.result_size = "10"
    command.page_size = "10"
    command.exclude_raw = False
    command.exclude_fields = ""
    command._metadata = command_metadata
    command.write_error = MagicMock()
    with pytest.raises(SystemExit):
        list(command.do_generate("key", "", logger))


def test_gnquery_passes_exclude_fields(logger, command_metadata):
    command = GNQueryCommand()
    command.query = "last_seen:1d"
    command.result_size = "1"
    command.page_size = "1"
    command.exclude_raw = "true"
    command.exclude_fields = " raw_data, tags "
    command._metadata = command_metadata
    command.write_error = MagicMock()
    with patch("gnquery.response_scroller", return_value=iter([{"ip": "1.1.1.1"}])) as scroller, patch(
        "gnquery.GreyNoise"
    ):
        events = list(command.do_generate("key", "", logger))
    assert events[0]["ip"] == "1.1.1.1"
    assert scroller.call_args.kwargs["exclude_fields"] == "raw_data,tags"


def test_gnfeed_command_uses_saved_query_when_omitted(logger, command_metadata):
    command = GNFeedCommand()
    command.query = ""
    command.result_size = "10"
    command.page_size = "10"
    command.include_raw = None
    command._metadata = command_metadata
    command.write_error = MagicMock()
    with patch("gnfeed._latest_feed_query", return_value="last_seen:1d classification:benign"), patch(
        "gnfeed._ingest_feed_enabled", return_value=False
    ), patch("gnfeed.feed_scroller", return_value=iter([{"_key": "1.1.1.1"}])) as scroller, patch("gnfeed.GreyNoise"):
        events = list(command.do_generate("key", "", logger))
    assert events[0]["_key"] == "1.1.1.1"
    assert scroller.call_args.args[2] == "last_seen:1d classification:benign"
    assert scroller.call_args.args[5] is False


def test_gnfeed_command_errors_without_query(logger, command_metadata):
    command = GNFeedCommand()
    command.query = ""
    command.result_size = "10"
    command.page_size = "10"
    command.include_raw = "false"
    command._metadata = command_metadata
    command.write_error = MagicMock()
    with patch("gnfeed._latest_feed_query", return_value=None), patch("gnfeed.GreyNoise"):
        with pytest.raises(SystemExit):
            list(command.do_generate("key", "", logger))
    command.write_error.assert_called()


def test_gncallback_passes_source_workspace(ready_eventing_command):
    command = ready_eventing_command(GNCallbackCommand())
    command.ip_field = "src"
    command.source_workspace = "workspace-a"
    command.api_client = MagicMock()
    with patch("event_generator.get_all_events", return_value=iter([])) as mocked:
        list(command.transform([{"src": "1.1.1.1"}]))
    assert mocked.call_args.kwargs["api_kwargs"] == {"source_workspace": "workspace-a"}
    assert mocked.call_args.args[2] == "callback"


def test_gnippsychic_generating_mode_skips_invalid_ips(ready_eventing_command):
    command = ready_eventing_command(GNIPPsychicCommand())
    command.ip = "1.1.1.1, not-an-ip"
    command.ip_field = None
    command.api_client = MagicMock()
    command.api_client.psychic_lookup_ips.return_value = [
        {"ip": "1.1.1.1", "seen": True, "classification": "malicious"}
    ]
    events = list(command.transform([]))
    ips = [event.get("ip") for event in events]
    assert "1.1.1.1" in ips
    assert "not-an-ip" in ips
    command.api_client.psychic_lookup_ips.assert_called_once_with(["1.1.1.1"])
    command.write_warning.assert_called()


def test_gncve_generating_mode(ready_eventing_command):
    command = ready_eventing_command(GNCVECommand())
    command.cve = "CVE-2024-1234"
    command.cve_field = None
    command.api_client = MagicMock()
    command.api_client.cve.return_value = {"id": "CVE-2024-1234", "details": "x"}
    events = list(command.transform([]))
    assert events[0]["greynoise_id"] == "CVE-2024-1234"


def test_gnstats_yields_raw_aggregate_payload(logger, command_metadata):
    command = GNStatsCommand()
    command.query = "classification:malicious"
    command.count = "5"
    command._metadata = command_metadata
    command.write_error = MagicMock()
    stats = {"count": 2, "stats": {"classifications": [{"classification": "malicious", "count": 2}]}}
    with patch("gnstats.GreyNoise") as mocked:
        mocked.return_value.stats.return_value = stats
        events = list(command.do_generate("key", "", logger))
    assert events[0]["_raw"]["results"] == stats


def test_gnoverview_flattens_stats_into_lookup_rows(logger, command_metadata):
    command = OverviewCommand()
    command.RESULTS = []
    command._metadata = command_metadata
    command._search_results_info = SimpleNamespace()
    client = MagicMock()
    client.stats.return_value = {
        "stats": {
            "organizations": [{"organization": "Google", "count": 9}],
            "classifications": [{"classification": "malicious", "count": 9}],
            "countries": [],
            "tags": [],
            "operating_systems": [],
            "categories": [],
            "asns": [],
            "actors": [],
        }
    }
    with patch("greynoise_overview.GreyNoise", return_value=client):
        rows = list(command.generate())
    assert {
        "stats_field": "organization",
        "stats_value": "Google",
        "stats_count": 9,
        "classification": "malicious",
    } in rows
    assert client.stats.call_count == 4


def test_gniptimeline_scroller_attaches_metadata(logger):
    client = MagicMock()
    client.timeline.return_value = {
        "results": [{"timestamp": "2024-01-01", "classification": "malicious"}],
        "metadata": {"ip": "1.1.1.1"},
    }
    events = list(timeline_scroller(client, logger, "1.1.1.1", 30, "classification", "1h"))
    assert events[0]["_raw"]["results"]["metadata"]["ip"] == "1.1.1.1"


def test_gniptimeline_rejects_empty_ip(logger, command_metadata):
    command = GNIPTimelineCommand()
    command.ip_address = ""
    command.days = "30"
    command.field = "classification"
    command.granularity = "1h"
    command._metadata = command_metadata
    command.write_error = MagicMock()
    with pytest.raises(SystemExit):
        list(command.do_generate("key", "", logger))


def test_gnrecall_timeseries_paginates(logger):
    client = MagicMock()
    client.recall.side_effect = [
        {"data": [{"timestamp": "t1", "count": 1}, {"timestamp": "t2", "count": 2}], "query": "q"},
        {"data": [{"timestamp": "t3", "count": 3}], "query": "q"},
    ]
    events = list(recall_timeseries_scroller(client, logger, "q", "-7d", "now", 3, 2))
    assert [event["_raw"]["results"]["timestamp"] for event in events] == ["t1", "t2", "t3"]
    assert client.recall.call_args_list[1].kwargs["offset"] == 2


def test_gnrecall_stats_emits_buckets(logger):
    client = MagicMock()
    client.recall_stats.return_value = {
        "query": "classification:malicious",
        "interval": "day",
        "data": [{"timestamp": "2024-01-01", "count": 10}],
    }
    events = list(recall_stats_generator(client, logger, "classification:malicious", None, None, "day"))
    assert events[0]["_raw"]["results"]["count"] == 10
    assert events[0]["_raw"]["results"]["interval"] == "day"


def test_gnrecall_rejects_unknown_mode(logger, command_metadata):
    command = GNRecallCommand()
    command.query = "last_seen:1d"
    command.mode = "weekly"
    command.start = ""
    command.end = ""
    command.result_size = "10"
    command.page_size = "10"
    command.interval = "hour"
    command._metadata = command_metadata
    command.write_error = MagicMock()
    with pytest.raises(SystemExit):
        list(command.do_generate("key", "", logger))


def test_base_handler_surfaces_unauthorized_api_errors(logger, command_metadata):
    command = IPContextCommand()
    command.ip = "1.1.1.1"
    command._metadata = command_metadata
    command.write_error = MagicMock()

    def boom(*args, **kwargs):
        raise RequestFailure(401, {"error": "nope"})
        yield

    with patch.object(command, "do_generate", side_effect=boom):
        list(command.generate())
    command.write_error.assert_called_with("Unauthorized. Please check your API key.")
