import re
import sys
import traceback  # noqa # pylint: disable=unused-import
from datetime import datetime, timedelta, timezone

import app_greynoise_declare  # noqa # pylint: disable=unused-import
import event_generator
from base_command_handler import BaseCommandHandler
from greynoise.api import APIConfig, GreyNoise
from greynoise_constants import INTEGRATION_NAME
from splunklib.searchcommands import Configuration, dispatch
from utility import get_conf_file

CALLBACK_LIST_ITEM_KEYS = (
    "data",
    "results",
    "items",
    "ips",
    "callback_ips",
)

CALLBACK_FEED_MAX_PAGES = 1000
CALLBACK_FEED_PAGE_SIZE = 100
CALLBACK_RELATIVE_DAYS = frozenset((1, 7, 14, 30, 45, 60, 90))
_ISO_DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
_RELATIVE_DAYS_RE = re.compile(r"^(\d+)\s*(?:d(?:ays?)?)?(?:\s+ago)?$", re.IGNORECASE)


def _parse_bool_filter(value):
    """Convert config values to optional booleans for callback_list filters."""
    if value is None:
        return None
    text = str(value).strip().lower()
    if text in ("", "any", "none", "null"):
        return None
    if text in ("1", "true", "yes", "y"):
        return True
    if text in ("0", "false", "no", "n"):
        return False
    return None


def _parse_optional_string(value):
    """Return stripped string or None when empty."""
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def _parse_relative_date_filter(value):
    """Convert a relative-days selection (or legacy YYYY-MM-DD) to YYYY-MM-DD."""
    text = _parse_optional_string(value)
    if text is None:
        return None
    lowered = text.lower()
    if lowered in ("any", "none", "null"):
        return None
    if _ISO_DATE_RE.match(text):
        return text
    match = _RELATIVE_DAYS_RE.match(text)
    if not match:
        return None
    days = int(match.group(1))
    if days not in CALLBACK_RELATIVE_DAYS:
        return None
    return (datetime.now(timezone.utc).date() - timedelta(days=days)).isoformat()


def _parse_csv_list(value):
    """Split a comma-separated config string into a list, or return None."""
    text = _parse_optional_string(value)
    if not text:
        return None
    items = [part.strip() for part in text.split(",") if part.strip()]
    return items or None


def _serialize_value(value):
    """Flatten nested values into strings suitable for KV store fields."""
    if value is None:
        return None
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (list, tuple, set)):
        parts = []
        for item in value:
            if isinstance(item, dict):
                # Prefer common identity fields when serializing dicts from arrays
                for key in ("ip", "name", "hash", "sha256", "type", "file_name", "filename"):
                    if item.get(key) is not None:
                        parts.append(str(item.get(key)))
                        break
                else:
                    parts.append(str(item))
            else:
                parts.append(str(item))
        return ",".join(parts)
    if isinstance(value, dict):
        return str(value)
    return str(value)


def _extract_callback_items(api_response):
    """Return list items from a callback_list payload."""
    if isinstance(api_response, list):
        return api_response
    if not isinstance(api_response, dict):
        return []
    for key in CALLBACK_LIST_ITEM_KEYS:
        value = api_response.get(key)
        if isinstance(value, list):
            return value
    return []


def _normalize_callback_item(item):
    """Normalize a callback list entry into a flat event dict keyed by IP."""
    if isinstance(item, str):
        return {"ip": item}

    if not isinstance(item, dict):
        return {"ip": str(item)}

    event = dict(item)
    if not event.get("ip"):
        for key in ("callback_ip", "ip_address", "address"):
            if event.get(key):
                event["ip"] = event.get(key)
                break

    # Flatten common nested collections for lookup storage
    for source_key, dest_key in (
        ("source_workspaces", "source_workspaces"),
        ("scanner_ips", "scanner_ips"),
        ("files", "file_names"),
    ):
        if source_key in event:
            event[dest_key] = _serialize_value(event.get(source_key))

    # Promote nested file metadata when present as a list of dicts
    files = item.get("files") if isinstance(item, dict) else None
    if isinstance(files, list) and files:
        file_names = []
        file_types = []
        file_hashes = []
        for file_item in files:
            if not isinstance(file_item, dict):
                file_names.append(str(file_item))
                continue
            name = file_item.get("name") or file_item.get("file_name") or file_item.get("filename")
            ftype = file_item.get("type") or file_item.get("file_type") or file_item.get("mime_type")
            fhash = file_item.get("hash") or file_item.get("sha256") or file_item.get("file_hash")
            if name:
                file_names.append(str(name))
            if ftype:
                file_types.append(str(ftype))
            if fhash:
                file_hashes.append(str(fhash))
        if file_names:
            event["file_names"] = ",".join(file_names)
        if file_types:
            event["file_types"] = ",".join(file_types)
        if file_hashes:
            event["file_hashes"] = ",".join(file_hashes)

    for key in ("is_stage_1", "is_stage_2", "has_files", "first_seen", "last_seen"):
        if key in event:
            event[key] = _serialize_value(event.get(key))

    return event


def _build_filters_from_conf(conf_data):
    """Map callback_feed_configuration stanza values to callback_list kwargs."""
    return {
        "is_stage_1": _parse_bool_filter(conf_data.get("is_stage_1")),
        "is_stage_2": _parse_bool_filter(conf_data.get("is_stage_2")),
        "has_files": _parse_bool_filter(conf_data.get("has_files")),
        "first_seen_after": _parse_relative_date_filter(conf_data.get("first_seen_after")),
        "first_seen_before": _parse_relative_date_filter(conf_data.get("first_seen_before")),
        "last_seen_after": _parse_relative_date_filter(conf_data.get("last_seen_after")),
        "last_seen_before": _parse_relative_date_filter(conf_data.get("last_seen_before")),
        "file_type": _parse_optional_string(conf_data.get("file_type")),
        "file_name": _parse_optional_string(conf_data.get("file_name")),
        "file_hash": _parse_optional_string(conf_data.get("file_hash")),
        "scanner_ips": _parse_csv_list(conf_data.get("scanner_ips")),
        "ips": _parse_csv_list(conf_data.get("ips")),
    }


def callback_list_scroller(api_client, logger, filters, page_size=CALLBACK_FEED_PAGE_SIZE):
    """Paginate callback_list results and yield normalized IP events."""
    first_event = True
    page = 0
    total_events = 0

    while page < CALLBACK_FEED_MAX_PAGES:
        logger.debug("Fetching Callback list page={} page_size={} filters={}".format(page, page_size, filters))
        api_response = api_client.callback_list(page=page, page_size=page_size, **filters)

        if isinstance(api_response, dict):
            message = api_response.get("message") or api_response.get("error")
            items = _extract_callback_items(api_response)
            if message and not items:
                logger.info("Callback list returned message with no items: {}".format(message))
                event = {"message": message}
                yield event_generator.make_invalid_event("callback_feed", event, first_event)
                return

        items = _extract_callback_items(api_response)
        if not items:
            logger.debug("No more Callback list items at page={}".format(page))
            break

        for item in items:
            event_data = _normalize_callback_item(item)
            if not event_data.get("ip"):
                continue
            yield event_generator.make_valid_event("callback_feed", event_data, first_event)
            first_event = False
            total_events += 1

        if len(items) < page_size:
            break

        if isinstance(api_response, dict):
            total = api_response.get("total")
            if total is None:
                total = api_response.get("count")
            if total is not None:
                try:
                    if (page + 1) * page_size >= int(total):
                        break
                except (TypeError, ValueError):
                    pass

        page += 1

    logger.info("Retrieved {} Callback feed indicators".format(total_events))


@Configuration(type="events")
class GNCallbackFeedCommand(BaseCommandHandler):
    """
    gncallbackfeed - Generating Command.

    Generating command that retrieves Callback IP list results using filters from the
    Callback IP Feed configuration page and method :method:`callback_list` from the
    GreyNoise Python SDK.

    **Syntax**::
    `| gncallbackfeed`

    **Description**::
    Used by the greynoise_callback_feed saved searches to populate the
    greynoise_callback_indicators KV store lookup.
    """

    def do_generate(self, api_key, proxy, logger):
        """Fetch Callback list indicators using configured filters."""
        logger.info("Started retrieving Callback feed indicators")

        session_key = self._metadata.searchinfo.session_key
        conf = get_conf_file(session_key, file="app_greynoise_settings")
        conf_data = conf.get("callback_feed_configuration", {}) or {}
        filters = _build_filters_from_conf(conf_data)
        # Drop keys that resolved to None so SDK payload stays sparse
        filters = {key: value for key, value in filters.items() if value is not None}

        if "http" in proxy:
            api_config = APIConfig(api_key=api_key, timeout=240, integration_name=INTEGRATION_NAME, proxy=proxy)
        else:
            api_config = APIConfig(api_key=api_key, timeout=240, integration_name=INTEGRATION_NAME)
        api_client = GreyNoise(api_config)

        try:
            for event in callback_list_scroller(api_client, logger, filters):
                yield event
            logger.info("Successfully retrieved Callback feed indicators")
        except Exception as e:
            logger.error("Error processing gncallbackfeed command: {}".format(e))
            if "401" in str(e):
                self.write_error("Error processing gncallbackfeed command. API Key not valid")
            elif "403" in str(e):
                self.write_error("Error processing gncallbackfeed command. API Key not authorized for this feature")
            else:
                self.write_error("Error processing gncallbackfeed command. Check greynoise_main.log for more details")
            exit(1)

    def __init__(self):
        """Initialize custom command class."""
        super(GNCallbackFeedCommand, self).__init__()


dispatch(GNCallbackFeedCommand, sys.argv, sys.stdin, sys.stdout, __name__)
