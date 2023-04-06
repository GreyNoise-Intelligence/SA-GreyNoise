import sys
import time
import traceback  # noqa # pylint: disable=unused-import

import app_greynoise_declare  # noqa # pylint: disable=unused-import
import event_generator
import validator
from base_command_handler import BaseCommandHandler
from greynoise import GreyNoise
from greynoise_constants import INTEGRATION_NAME
from splunklib.searchcommands import Configuration, Option, dispatch


@Configuration(type="events")
class GNStatsCommand(BaseCommandHandler):
    """
    gnstats - Generating Command.

    Generating command that returns aggregate statistics for the top organizations, actors,
    tags, ASNs, countries, classifications, and operating systems of all the results of a given GNQL query.
    Data pulled from /v2/experimental/gnql/stats using GreyNoise Python SDK

    **Syntax**::
    `| gnstats query="classification: malicious" count="10"`
    `| gnquick query="classification: benign"`

    **Description**::
    The `gnstats` command uses the `GNQL query` provided in `query` to return
    top aggregate statistics using method :method:`stats` from GreyNoise Python SDK.
    The optional parameter `count` can be used to specify how many aggregators needs to be retrieved.
    """

    query = Option(
        doc="""**Syntax:** **query=***<GNQL_query>*
        **Description:** GNQL query whose top aggregate statistics needs to be retrieved from GreyNoise""",
        name="query",
        require=True,
    )

    count = Option(
        doc="""**Syntax:** **result_size=***<GNQL_query>*
        **Description:**Total number of top aggregate statistics needs to be retrieved from GreyNoise""",
        name="count",
        require=False,
    )

    def do_generate(self, api_key, proxy, logger):
        """
        Method to fetch the api response and process and send the response with extractions in the Splunk.

        :param api_key: GreyNoise API Key.
        :logger: logger object.
        """
        query = self.query
        count = self.count

        if query == "":
            logger.error("Parameter query should not be empty.")
            self.write_error("Parameter query should not be empty.")
            exit(1)

        # Strip the spaces from the parameter value if given
        if count:
            count = count.strip()
        # Validating the given parameters
        try:
            count = validator.Integer(option_name="count", minimum=1).validate(count)
        except ValueError as e:
            # Validator will throw ValueError with error message when the parameters are not proper
            logger.error(str(e))
            self.write_error(str(e))
            exit(1)

        logger.info("Fetching aggregate statistics for query: {}, count: {}".format(str(query), count))
        # Opting timeout 120 seconds for the requests
        if "http" in proxy:
            api_client = GreyNoise(api_key=api_key, timeout=240, integration_name=INTEGRATION_NAME, proxy=proxy)
        else:
            api_client = GreyNoise(api_key=api_key, timeout=240, integration_name=INTEGRATION_NAME)
        # If count is not passed explicitly to the command by the user, then it will have the value None
        stats_data = api_client.stats(query, count)
        logger.info(
            "Successfully retrieved response for the aggregate statistics for query: {}, count: {}".format(
                str(query), count
            )
        )

        if int(stats_data.get("count", -1)) >= 0:
            results = {
                "source": "greynoise",
                "sourcetype": "greynoise",
                "_time": time.time(),
                "_raw": {"results": stats_data},
            }
            yield results
        else:
            response = stats_data.get("message", None) or stats_data.get("error", None)

            if "bad count" in response or "bad query" in response:
                logger.error(
                    "Invalid response retrieved from the GreyNoise API for query: {}, response: {}".format(
                        str(query), str(response)
                    )
                )
                if "message" in response:
                    event = {"message": response}
                else:
                    event = {"error": response}
                yield event_generator.make_invalid_event("stats", event, True)

    def __init__(self):
        """Initialize custom command class."""
        super(GNStatsCommand, self).__init__()


dispatch(GNStatsCommand, sys.argv, sys.stdin, sys.stdout, __name__)
