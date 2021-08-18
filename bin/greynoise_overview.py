import sys
import traceback

import app_greynoise_declare # noqa # pylint: disable=unused-import
from splunklib.searchcommands import dispatch, GeneratingCommand, Configuration
from greynoise import GreyNoise

import utility
from greynoise_constants import INTEGRATION_NAME


@Configuration(type="events")
class OverviewCommand(GeneratingCommand):
    """
    This command fetches the statistics from the greynoise for different classification values.

    **Syntax**::
    `| gnoverview`
    """

    RESULTS = list()

    TYPES = {
        "organizations": "organization",
        "classifications": "classification",
        "countries": "country",
        "tags": "tag",
        "operating_systems": "operating_system",
        "categories": "category",
        "asns": "asn",
        "actors": "actor"
    }

    def handle_stats(self, data, classification):
        """
        Transform the data returned into the format accepted by lookup.

        Stores the result in RESULTS list.
        :param data: The stats data
        :param classification: The classification for which the data is being parsed
        """
        for key, value in list(self.TYPES.items()):
            if not data[key]:
                continue
            else:
                for entry in data[key]:
                    a = {
                        "stats_field": value,
                        "stats_value": entry[value],
                        "stats_count": entry["count"],
                        "classification": classification
                    }
                    self.RESULTS.append(a)

    def generate(self):
        """Method that yields records to the Splunk processing pipeline."""
        logger = utility.setup_logger(
            session_key=self._metadata.searchinfo.session_key, log_context=self._metadata.searchinfo.command)

        # Enter the mechanism only when the Search is complete and all the events are available
        if self.search_results_info and not self.metadata.preview:

            try:
                api_key = utility.get_api_key(self._metadata.searchinfo.session_key, logger=logger)

                # Completing the search if the API key is not available.
                if not api_key:
                    logger.error("API key not found. Please configure the GreyNoise App for Splunk.")
                    exit(1)

                # Opting timout 120 seconds for the requests
                api_client = GreyNoise(api_key=api_key, timeout=240, integration_name=INTEGRATION_NAME)

                queries = {
                    "malicious": "classification:malicious last_seen:today",
                    "benign": "classification:benign last_seen:today",
                    "unknown": "classification:unknown last_seen:today"
                }

                for key, value in queries.items():
                    logger.debug("Fetching records for classification: {}".format(key))
                    stats_data = api_client.stats(value, None)
                    if stats_data.get("stats"):
                        self.handle_stats(stats_data.get("stats"), key)
                    else:
                        logger.error("Returning no results because of unexpected response in one of the query.")
                        exit(1)

                for result in self.RESULTS:
                    yield result
                logger.info("Events returned successfully to Splunk.")

            except Exception:
                logger.error("Exception: {} ".format(str(traceback.format_exc())))
                exit(1)

    def __init__(self):
        """Initialize custom command class."""
        super(OverviewCommand, self).__init__()


dispatch(OverviewCommand, sys.argv, sys.stdin, sys.stdout, __name__)
