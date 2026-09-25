import json
import sys
import time

import app_greynoise_declare  # noqa # pylint: disable=unused-import
import validator
from base_command_handler import BaseCommandHandler
from greynoise.api import APIConfig, GreyNoise
from greynoise_constants import INTEGRATION_NAME
from service_utils import create_service
from splunklib.searchcommands import Configuration, Option, dispatch
from utility import get_conf_file

FEED_EXCLUDE_FIELDS = "destination_asns,destination_cities,destination_countries,destination_country_codes,tags.details"


def _as_dict(value):
    """Return value when it is a dict, otherwise an empty dict."""
    return value if isinstance(value, dict) else {}


def _internet_scanner_intelligence(hit):
    """Return internet_scanner_intelligence from a GNQL hit."""
    return _as_dict(hit.get("internet_scanner_intelligence"))


def _metadata(hit):
    """Return metadata from internet_scanner_intelligence, then top-level metadata."""
    isi_meta = _as_dict(_internet_scanner_intelligence(hit).get("metadata"))
    if isi_meta:
        return isi_meta
    return _as_dict(hit.get("metadata"))


def _first_present(mappings, key):
    """Return the first non-None value for key across mappings."""
    for mapping in mappings:
        if mapping.get(key) is not None:
            return mapping.get(key)
    return None


def _unique_joined(values):
    """Join unique scalar values with commas, preserving first-seen order."""
    if values is None:
        return None
    if isinstance(values, str):
        return values
    if not isinstance(values, (list, tuple, set)):
        return str(values)

    parts = []
    seen = set()
    for item in values:
        if item is None:
            continue
        text = str(item)
        if text in seen:
            continue
        seen.add(text)
        parts.append(text)
    return ",".join(parts) if parts else None


def _tag_names(hit):
    """Extract tag names from a GNQL hit (list of dicts or strings)."""
    tags = _internet_scanner_intelligence(hit).get("tags")
    if tags is None:
        tags = hit.get("tags")
    if not isinstance(tags, list):
        return _unique_joined(tags)

    names = []
    for entry in tags:
        if isinstance(entry, dict):
            name = entry.get("name")
            if name is not None:
                names.append(name)
        elif entry is not None:
            names.append(entry)
    return _unique_joined(names)


def _cves(hit):
    """Extract CVE identifiers from a GNQL hit."""
    isi = _internet_scanner_intelligence(hit)
    cves = isi.get("cves")
    if cves is None:
        cves = hit.get("cves")
    if cves is None:
        cves = hit.get("cve")
    return _unique_joined(cves)


def _source_workspaces(hit):
    """Extract source workspace labels from a GNQL hit."""
    workspaces = hit.get("source_workspaces")
    if workspaces is None:
        workspaces = _internet_scanner_intelligence(hit).get("source_workspaces")
    return _unique_joined(workspaces)


def _normalize_spoofable(value):
    """Coerce spoofable to a boolean when possible."""
    if value is None:
        return None
    if isinstance(value, bool):
        return value
    text = str(value).strip().lower()
    if text in ("1", "true", "yes", "y"):
        return True
    if text in ("0", "false", "no", "n"):
        return False
    return value


def normalize_feed_hit(hit):
    """Map a GNQL IP hit to the greynoise_indicators lookup schema (no Splunk _raw)."""
    if not isinstance(hit, dict):
        return None

    ip_address = hit.get("ip")
    if not ip_address:
        return None

    isi = _internet_scanner_intelligence(hit)
    metadata = _metadata(hit)
    sources = (hit, isi, metadata)

    event = {
        "_key": ip_address,
        "ip": ip_address,
        "actor": _first_present(sources, "actor"),
        "first_seen": _first_present(sources, "first_seen"),
        "last_seen": _first_present(sources, "last_seen"),
        "classification": _first_present(sources, "classification"),
        "tags": _tag_names(hit),
        "cve": _cves(hit),
        "source_country": _first_present(sources, "source_country"),
        "asn": _first_present(sources, "asn"),
        "organization": _first_present(sources, "organization"),
        "spoofable": _normalize_spoofable(_first_present(sources, "spoofable")),
        "source_workspaces": _source_workspaces(hit),
        "source": "greynoise",
        "sourcetype": "greynoise",
        "_time": time.time(),
    }
    return event


def _latest_feed_query(session_key, logger):
    """Return the most recently saved feed GNQL query from gn_feed_collection."""
    service = create_service(session_key)
    if "gn_feed_collection" not in service.kvstore:
        logger.error("Collection gn_feed_collection does not exist.")
        return None

    records = service.kvstore["gn_feed_collection"].data.query() or []
    if not records:
        return None

    latest = max(records, key=lambda record: record.get("created") or 0)
    query = latest.get("query")
    if query:
        return str(query).strip()
    return None


def _ingest_feed_enabled(session_key):
    """Return True when Feed Configuration has ingest-to-index enabled."""
    conf = get_conf_file(session_key, file="app_greynoise_settings")
    conf_data = conf.get("feed_configuration", {}) or {}
    value = conf_data.get("ingest_feed_to_index", 0)
    try:
        return bool(int(value))
    except (TypeError, ValueError):
        return str(value).strip().lower() in ("1", "true", "yes", "y")


def feed_scroller(api_client, logger, query, result_size, page_size, include_raw):
    """Page GNQL metadata results and yield lean indicator events."""
    remaining_chunk_size = result_size
    completion_flag = False
    scroll = None
    total_events = 0
    size = page_size

    stats_api_response = api_client.stats(query=query)
    if stats_api_response.get("count", 0) < remaining_chunk_size:
        remaining_chunk_size = stats_api_response.get("count", 0)
        logger.debug("Query result count is smaller than result_max, total results: {}".format(remaining_chunk_size))

    if remaining_chunk_size < size:
        size = remaining_chunk_size
        logger.debug("Size for the GNQL query is configured to {}".format(size))

    while not completion_flag:
        event_count = 0

        if remaining_chunk_size <= 0:
            logger.debug("No GreyNoise feed results remaining to be sent, completing the search...")
            break

        api_response = api_client.query(
            query=query,
            exclude_raw=True,
            size=size,
            scroll=scroll,
            exclude_fields=FEED_EXCLUDE_FIELDS,
        )

        if "request_metadata" not in api_response:
            message = api_response.get("request_metadata", {}).get("message", "")
            adjusted_query = api_response.get("request_metadata", {}).get("adjusted_query", "")
            logger.info(
                "No results returned for GreyNoise feed query: {}, message: {}".format(
                    str(adjusted_query), str(message)
                )
            )
            yield {
                "message": message,
                "query": adjusted_query,
                "source": "greynoise",
                "sourcetype": "greynoise",
                "_time": time.time(),
            }
            return

        scroll = api_response["request_metadata"].get("scroll", None)
        completion_flag = api_response["request_metadata"].get("complete", True)
        api_data = api_response.get("data", []) or []

        for ip_data in api_data:
            event = normalize_feed_hit(ip_data)
            if not event:
                continue
            if include_raw:
                event["_raw"] = json.dumps(ip_data, separators=(",", ":"))
            yield event
            event_count += 1
            total_events += 1

        remaining_chunk_size = remaining_chunk_size - event_count
        logger.debug(
            "Statistics: Remaining chunk size: {} : Events written:{} : Total events:{}".format(
                remaining_chunk_size, event_count, total_events
            )
        )

        if scroll is None:
            logger.debug("Last page of the GreyNoise feed results detected, completing the search...")
            completion_flag = True

    logger.info("Retrieved {} GreyNoise feed indicators".format(total_events))


@Configuration(type="events")
class GNFeedCommand(BaseCommandHandler):
    """
    gnfeed - Generating Command.

    Generating command that retrieves GNQL results and emits only the fields stored in
    the greynoise_indicators lookup. Unlike gnquery, events do not include a Splunk _raw
    copy of each IP payload unless feed ingest-to-index is enabled.

    **Syntax**::
    `| gnfeed`
    `| gnfeed query="last_seen:1d classification:malicious" result_size="50000"`
    """

    query = Option(
        doc="""**Syntax:** **query=***<GNQL_query>*
        **Description:** GNQL query whose results are written as feed indicators.
        When omitted, the latest query from gn_feed_lookup is used.""",
        name="query",
        require=False,
    )

    result_size = Option(
        doc="""**Syntax:** **result_size=***<int>*
        **Description:** Total number of GNQL results to retrieve from GreyNoise""",
        default="2000000",
        name="result_size",
        require=False,
    )

    page_size = Option(
        doc="""**Syntax:** **page_size=***<int>*
        **Description:** Number of results per page returned by the GNQL API""",
        default="5000",
        name="page_size",
        require=False,
    )

    include_raw = Option(
        doc="""**Syntax:** **include_raw=***<bool>*
        **Description:** When true, attach the original GNQL hit as JSON _raw (needed to collect into an index).
        When omitted, follows the Feed Configuration ingest-to-index setting.""",
        name="include_raw",
        require=False,
    )

    def do_generate(self, api_key, proxy, logger):
        """Fetch GNQL hits and yield greynoise_indicators rows without storing _raw by default."""
        session_key = self._metadata.searchinfo.session_key
        query = (self.query or "").strip()
        result_size = self.result_size
        page_size = self.page_size
        include_raw = self.include_raw

        logger.info("Started retrieving GreyNoise feed indicators")

        if result_size:
            result_size = result_size.strip()
        if page_size:
            page_size = page_size.strip()

        try:
            result_size = validator.Integer(option_name="result_size", minimum=1).validate(result_size)
            page_size = validator.Integer(option_name="page_size", minimum=1, maximum=10000).validate(page_size)
            if include_raw is None or include_raw == "":
                include_raw = _ingest_feed_enabled(session_key)
            else:
                include_raw = validator.Boolean(option_name="include_raw").validate(include_raw)
        except ValueError as e:
            logger.error(str(e))
            self.write_error(str(e))
            exit(1)

        if not query:
            try:
                query = _latest_feed_query(session_key, logger) or ""
            except Exception as e:
                logger.error("Error reading gn_feed_collection: {}".format(e))
                self.write_error("Error reading the saved feed query. Check greynoise_main.log for more details")
                exit(1)

        if not query:
            logger.error("No GNQL query provided and none found in gn_feed_lookup.")
            self.write_error("No GNQL query provided and none found in gn_feed_lookup.")
            exit(1)

        if "http" in proxy:
            api_config = APIConfig(api_key=api_key, timeout=240, integration_name=INTEGRATION_NAME, proxy=proxy)
        else:
            api_config = APIConfig(api_key=api_key, timeout=240, integration_name=INTEGRATION_NAME)
        api_client = GreyNoise(api_config)

        logger.info(
            "Fetching feed results for GNQL query: {}, requested number of results: {}, "
            "page size: {}, include_raw: {}".format(str(query), str(result_size), str(page_size), include_raw)
        )

        for event in feed_scroller(api_client, logger, query, result_size, page_size, include_raw):
            yield event

        logger.info("Successfully retrieved GreyNoise feed indicators for query: {}".format(str(query)))

    def __init__(self):
        """Initialize custom command class."""
        super(GNFeedCommand, self).__init__()


dispatch(GNFeedCommand, sys.argv, sys.stdin, sys.stdout, __name__)
