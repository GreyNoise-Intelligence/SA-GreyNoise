"""Tests for scan-deployment macros, saved searches, and parameter comparison."""

from unittest.mock import MagicMock

import pytest
from conf_utils import load_conf, table_fields
from saved_search_utils import (
    CIM_IP_FIELDS,
    DATE,
    TIME_MAP,
    compare_parameters,
    get_macro_string,
    get_unique_set,
    handle_macros,
    is_api_configured,
)


def test_scan_savedsearches_use_gnmulti_and_current_lookup_schema(app_dir):
    searches = load_conf(app_dir / "default" / "savedsearches.conf")
    transforms = load_conf(app_dir / "default" / "transforms.conf")
    lookup_fields = {
        field.strip() for field in transforms.get("gn_scan_deployment_ip_lookup", "fields_list").split(",")
    }

    for stanza in ("greynoise_scan_deployment", "greynoise_scan_deployment_once"):
        search = searches.get(stanza, "search")
        assert "index IN (`greynoise_indexes`)" in search
        assert "`greynoise_fields`" in search
        assert "`greynoise_other_fields`" in search
        assert "| gnmulti ip_field=gn_ip" in search
        assert "eval internet_scanner_intelligence = greynoise_internet_scanner_intelligence_found" in search
        assert "eval business_service_intelligence = greynoise_business_service_intelligence_found" in search
        assert "eval classification = greynoise_internet_scanner_intelligence_classification" in search
        assert "eval trust_level = greynoise_business_service_intelligence_trust_level" in search
        assert "outputlookup gn_scan_deployment_ip_lookup" in search
        table_fields_set = table_fields(search)
        assert table_fields_set <= lookup_fields
        assert "_key" in table_fields_set
        assert "internet_scanner_intelligence" in table_fields_set
        assert "business_service_intelligence" in table_fields_set

    scheduled = searches["greynoise_scan_deployment"]
    assert scheduled.get("enableSched") == "1"
    assert scheduled.get("disabled") == "1"
    assert scheduled.get("cron_schedule") == "0 * * * *"
    assert scheduled.get("dispatch.earliest_time") == "-70m"
    assert searches.get("greynoise_scan_deployment_once", "dispatch.earliest_time") == "-24h"


def test_scan_search_still_filters_ipv4_before_gnmulti(app_dir):
    search = load_conf(app_dir / "default" / "savedsearches.conf").get("greynoise_scan_deployment", "search")
    assert r"| regex gn_ip = " in search
    assert "(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)" in search


def test_scan_macros_default_to_cim_ip_fields(app_dir):
    macros = load_conf(app_dir / "default" / "macros.conf")
    fields = {field.strip() for field in macros.get("greynoise_fields", "definition").split(",")}
    other = {field.strip() for field in macros.get("greynoise_other_fields", "definition").split(",")}
    assert fields == set(CIM_IP_FIELDS)
    assert other == set(CIM_IP_FIELDS)
    assert macros.get("greynoise_indexes", "definition") == "main"


def test_scan_start_time_map_covers_ui_options():
    assert DATE["NOW"] == "1"
    assert TIME_MAP[DATE["NOW"]] == "0"
    assert TIME_MAP[DATE["LAST_SIXTY_MINS"]] == "-60m"
    assert TIME_MAP[DATE["LAST_TWENTY_FOUR_HOURS"]] == "-24h"
    assert TIME_MAP[DATE["LAST_SIXTY_DAYS"]] == "-60d"


def test_compare_parameters_detects_expanded_indexes_fields_and_time():
    conf = {
        "ip_indexes": "main",
        "cim_ip_fields": "src, dest",
        "scan_start_time": "LAST_FIVE_MINS",
    }
    assert compare_parameters(
        {"ip_indexes": "main, firewall", "cim_ip_fields": "src, dest", "scan_start_time": "LAST_FIVE_MINS"}, conf
    )
    assert compare_parameters({"ip_indexes": "main", "cim_ip_fields": "all", "scan_start_time": "LAST_FIVE_MINS"}, conf)
    assert compare_parameters(
        {"ip_indexes": "main", "cim_ip_fields": "src, dest", "scan_start_time": "LAST_SEVEN_DAYS"}, conf
    )
    assert not compare_parameters(
        {"ip_indexes": "main", "cim_ip_fields": "src", "scan_start_time": "NOW"},
        conf,
    )


def test_handle_macros_posts_index_and_field_definitions():
    service = MagicMock()
    handle_macros(
        {
            "ip_indexes": "main, firewall",
            "cim_ip_fields": "src, dest",
            "other_ip_fields": "custom_ip",
        },
        service,
    )
    posted = {call.args[0]: call.kwargs["definition"] for call in service.post.call_args_list}
    assert set(get_unique_set(posted["properties/macros/greynoise_indexes"])) == {"main", "firewall"}
    assert "custom_ip" in posted["properties/macros/greynoise_fields"]
    assert "'custom_ip'" in posted["properties/macros/greynoise_other_fields"]


def test_handle_macros_rejects_invalid_other_fields():
    service = MagicMock()
    with pytest.raises(ValueError):
        handle_macros(
            {"ip_indexes": "main", "cim_ip_fields": "src", "other_ip_fields": "1bad"},
            service,
        )


def test_is_api_configured_and_macro_helpers():
    assert is_api_configured({"parameters": {"api_key": "abc"}}) == "abc"
    assert not is_api_configured({"parameters": {}})
    assert get_unique_set(" src, dest, src ") == {"src", "dest"}
    assert get_macro_string(["b", "a"]) == "b,a"


def test_scan_settings_spec_and_collections(app_dir):
    spec = (app_dir / "README" / "app_greynoise_settings.conf.spec").read_text(encoding="utf-8")
    assert "[scan_deployment]" in spec
    assert "update_risk_score_to_splunk_es" in spec
    collections = load_conf(app_dir / "default" / "collections.conf")
    assert "field.internet_scanner_intelligence" in collections.options("gn_scan_deployment_ip_collection")
    assert "field.business_service_intelligence" in collections.options("gn_scan_deployment_ip_collection")


def test_scan_migration_search_renames_legacy_riot_and_noise(app_dir):
    search = load_conf(app_dir / "default" / "savedsearches.conf").get(
        "greynoise_migrate_gn_scan_deployment_ip_lookup", "search"
    )
    assert "rename RIOT as business_service_intelligence, noise as internet_scanner_intelligence" in search
