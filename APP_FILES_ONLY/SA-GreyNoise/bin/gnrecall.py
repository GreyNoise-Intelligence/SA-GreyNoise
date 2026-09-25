import re  # noqa # pylint: disable=unused-import
import sys
import traceback  # noqa # pylint: disable=unused-import

import app_greynoise_declare  # noqa # pylint: disable=unused-import
import event_generator
import validator
from base_command_handler import BaseCommandHandler
from greynoise.api import APIConfig, GreyNoise
from greynoise_constants import INTEGRATION_NAME
from splunklib.searchcommands import Configuration, Option, dispatch

RECALL_MODES = ("timeseries", "stats")
RECALL_ROW_KEYS = ("data", "results", "points", "series", "buckets", "intervals")
RECALL_METADATA_KEYS = ("query", "start", "end", "format", "interval", "total", "count")


def _normalize_recall_response(api_response):
    """Recall endpoints may return a bare list; wrap for consistent handling."""
    if isinstance(api_response, list):
        return {"data": api_response}
    return api_response


def _extract_recall_rows(api_response):
    """Return tabular rows from a Recall API payload, if present."""
    if isinstance(api_response, list):
        return api_response

    for key in RECALL_ROW_KEYS:
        rows = api_response.get(key)
        if isinstance(rows, list):
            return rows
    return []


def _attach_recall_metadata(row, api_response):
    """Attach top-level Recall metadata to each row event."""
    if not isinstance(row, dict):
        row = {"value": row}

    event = dict(row)
    for key in RECALL_METADATA_KEYS:
        if key in api_response and key not in event:
            event[key] = api_response[key]
    return event


def _recall_error_response(api_response):
    """True when the API returned an error-style payload with no rows."""
    if not isinstance(api_response, dict):
        return False
    if api_response.get("error"):
        return True
    message = api_response.get("message")
    return bool(message) and not _extract_recall_rows(api_response) and "stats" not in api_response


def _iter_recall_row_events(api_response, first_event):
    """Yield Splunk events for tabular Recall rows."""
    rows = _extract_recall_rows(api_response)
    for row in rows:
        event_data = _attach_recall_metadata(row, api_response)
        yield event_generator.make_valid_event("recall", event_data, first_event)
        first_event = False


def recall_timeseries_scroller(api_client, logger, query, start, end, result_size, page_size):
    """Fetch Recall time-series rows, paginating with limit/offset when needed."""
    remaining_chunk_size = result_size
    current_offset = 0
    first_event = True
    total_events = 0

    while remaining_chunk_size > 0:
        size = page_size if remaining_chunk_size >= page_size else remaining_chunk_size
        logger.debug(
            "Fetching Recall timeseries page with limit={}, offset={}, remaining={}".format(
                size, current_offset, remaining_chunk_size
            )
        )

        api_response = _normalize_recall_response(
            api_client.recall(
                query=query,
                start=start or None,
                end=end or None,
                limit=size,
                offset=current_offset,
            )
        )

        if _recall_error_response(api_response):
            message = api_response.get("message") or api_response.get("error")
            logger.info("No Recall timeseries results for query: {}, message: {}".format(str(query), str(message)))
            event = {"message": message, "query": query}
            yield event_generator.make_invalid_event("recall", event, first_event)
            exit(1)

        page_event_count = 0
        for event in _iter_recall_row_events(api_response, first_event):
            yield event
            page_event_count += 1
            total_events += 1
            first_event = False

        if page_event_count == 0:
            logger.debug("Recall timeseries returned no rows, completing the search...")
            break

        remaining_chunk_size -= page_event_count
        logger.debug(
            "Statistics: Remaining chunk size: {} : Events written: {} : Total events: {}".format(
                remaining_chunk_size, page_event_count, total_events
            )
        )

        if page_event_count < size:
            logger.debug("Last page of Recall timeseries results detected, completing the search...")
            break

        current_offset += page_event_count


def recall_stats_generator(api_client, logger, query, start, end, interval):
    """Fetch aggregated Recall stats and emit one event per bucket when present."""
    api_response = _normalize_recall_response(
        api_client.recall_stats(
            query=query,
            start=start or None,
            end=end or None,
            interval=interval,
        )
    )

    if _recall_error_response(api_response):
        message = api_response.get("message") or api_response.get("error")
        logger.info("No Recall stats results for query: {}, message: {}".format(str(query), str(message)))
        event = {"message": message, "query": query}
        yield event_generator.make_invalid_event("recall", event, True)
        exit(1)

    rows = _extract_recall_rows(api_response)
    if rows:
        first_event = True
        for row in rows:
            event_data = _attach_recall_metadata(row, api_response)
            yield event_generator.make_valid_event("recall", event_data, first_event)
            first_event = False
        return

    yield event_generator.make_valid_event("recall", api_response, True)


@Configuration(type="events")
class GNRecallCommand(BaseCommandHandler):
    """
    gnrecall - Generating Command.

    Generating command that returns GreyNoise Recall GNQL activity over time,
    using recall and recall_stats from the GreyNoise Python SDK.

    **Syntax**::
    `| gnrecall query="classification:malicious" start="-7d" end="now"`
    `| gnrecall query="classification:malicious" mode="stats" interval="day"`

    **Description**::
    The `gnrecall` command uses the GNQL query in `query` to return Recall time-series
    or aggregated stats via :method:`recall` and :method:`recall_stats` from the GreyNoise SDK.
    Use `mode="timeseries"` (default) for time-series rows, or `mode="stats"` for aggregated stats.
    Optional `start` and `end` bound the time range (RFC 3339 or supported datetime strings).
    For timeseries mode, `result_size` limits total rows and `page_size` controls API page size.
    For stats mode, `interval` sets the aggregation bucket (default `hour`).
    """

    query = Option(
        doc="""**Syntax:** **query=***<GNQL_query>*
        **Description:** GNQL query whose Recall results need to be retrieved from GreyNoise""",
        name="query",
        require=True,
    )

    mode = Option(
        doc="""**Syntax:** **mode=***timeseries|stats*
        **Description:** Recall API mode: timeseries (default) or stats""",
        default="timeseries",
        name="mode",
        require=False,
    )

    start = Option(
        doc="""**Syntax:** **start=***<datetime>*
        **Description:** Start of the Recall time range (RFC 3339 or supported datetime)""",
        default="",
        name="start",
        require=False,
    )

    end = Option(
        doc="""**Syntax:** **end=***<datetime>*
        **Description:** End of the Recall time range (RFC 3339 or supported datetime)""",
        default="",
        name="end",
        require=False,
    )

    result_size = Option(
        doc="""**Syntax:** **result_size=***<int>*
        **Description:** Total number of Recall timeseries rows to retrieve (timeseries mode only)""",
        default="50000",
        name="result_size",
        require=False,
    )

    page_size = Option(
        doc="""**Syntax:** **page_size=***<int>*
        **Description:** Number of Recall timeseries rows per API request (timeseries mode only)""",
        default="1000",
        name="page_size",
        require=False,
    )

    interval = Option(
        doc="""**Syntax:** **interval=***<interval>*
        **Description:** Aggregation interval for Recall stats (stats mode only)""",
        default="hour",
        name="interval",
        require=False,
    )

    def do_generate(self, api_key, proxy, logger):
        """
        Method to fetch the api response and process and send the response with extractions in the Splunk.

        :param api_key: GreyNoise API Key.
        :param proxy: Proxy configuration.
        :param logger: logger object.
        """
        query = self.query
        mode = self.mode
        start = self.start
        end = self.end
        result_size = self.result_size
        page_size = self.page_size
        interval = self.interval

        logger.info("Started retrieving Recall results for query: {}".format(str(query)))

        if query == "":
            logger.error("Parameter query should not be empty.")
            self.write_error("Parameter query should not be empty.")
            exit(1)

        if mode:
            mode = mode.strip().lower()
        if mode not in RECALL_MODES:
            message = "Parameter mode must be one of: {}, given value: {}".format(", ".join(RECALL_MODES), mode)
            logger.error(message)
            self.write_error(message)
            exit(1)

        if start:
            start = start.strip()
        if end:
            end = end.strip()
        if result_size:
            result_size = result_size.strip()
        if page_size:
            page_size = page_size.strip()
        if interval:
            interval = interval.strip()

        try:
            if mode == "timeseries":
                result_size = validator.Integer(option_name="result_size", minimum=1).validate(result_size)
                page_size = validator.Integer(option_name="page_size", minimum=1, maximum=10000).validate(page_size)
        except ValueError as e:
            logger.error(str(e))
            self.write_error(str(e))
            exit(1)

        if "http" in proxy:
            api_config = APIConfig(api_key=api_key, timeout=240, integration_name=INTEGRATION_NAME, proxy=proxy)
            api_client = GreyNoise(api_config)
        else:
            api_config = APIConfig(api_key=api_key, timeout=240, integration_name=INTEGRATION_NAME)
            api_client = GreyNoise(api_config)

        if mode == "timeseries":
            logger.info(
                "Fetching Recall timeseries for query: {}, requested rows: {}, page size: {}".format(
                    str(query), str(result_size), str(page_size)
                )
            )
            for event in recall_timeseries_scroller(
                api_client,
                logger,
                query,
                start,
                end,
                result_size,
                page_size,
            ):
                yield event
        else:
            logger.info("Fetching Recall stats for query: {}, interval: {}".format(str(query), str(interval)))
            for event in recall_stats_generator(api_client, logger, query, start, end, interval):
                yield event

        logger.info("Successfully retrieved Recall results for query: {}".format(str(query)))

    def __init__(self):
        """Initialize custom command class."""
        super(GNRecallCommand, self).__init__()


dispatch(GNRecallCommand, sys.argv, sys.stdin, sys.stdout, __name__)
