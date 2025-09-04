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


def response_scroller(api_client, logger, ip_address, days, field, granularity):
    """Uses api_client instance of GreyNoise SDK to fetch query results and traverse them if result set is too large."""
    api_response = api_client.timeline(ip_address=ip_address, days=days, field=field, granularity=granularity)

    results = api_response.get("results", [])
    metadata = api_response.get("metadata", {})

    if results:
        for result in results:
            result.update({"metadata": metadata})
            yield event_generator.make_valid_event("timeline", result, True)
    else:
        ip = metadata.get("ip", "")
        logger.info(f"No results returned for GreyNoise IP: {ip}")
        event = {"message": "No results returned", "ip": ip}
        yield event_generator.make_invalid_event("timeline", event, True)
        exit(1)


@Configuration(type="events")
class GNIPTimelineCommand(BaseCommandHandler):
    """
    gniptimeline - Generating Command.

    Generating command that returns the results of the GreyNoise Timeline tool,
    Data pulled from /v3/timeline using GreyNoise Python SDK

    **Syntax**::
    `| gniptimeline ip_address="1.2.3.4" days="30" field="classification" granularity="1h"`
    `| gniptimeline ip_address="1.2.3.4" days="30" granularity="1h"`

    **Description**::
    The `gniptimeline` command uses the `IP Address` provided in `ip_address` parameter to return GreyNoise
    timeline results using method :method:`timeline` from GreyNoise Python SDK.
    The optional parameter `days` can be used to provide the number of days to include in the timeline
    The optional parameter `field` can be used to provide the field to use to retrieve timeline information.
    """

    ip_address = Option(
        doc="""**Syntax:** **ip_address=***<ip_address>*
        **Description:** IP Address to get Similar IPs for""",
        name="ip_address",
        require=True,
    )

    days = Option(
        doc="""**Syntax:** **days=***<days>*
        **Description:**Number of days of events to retrieve""",
        default="30",
        name="days",
        require=False,
    )

    field = Option(
        doc="""**Syntax:** **field=***<field>*
        **Description:**Field to use to retrieve timeline information""",
        default="classification",
        name="field",
        require=False,
    )

    granularity = Option(
        doc="""**Syntax:** **granularity=***<granularity>*
        **Description:**Granularity of timeline events""",
        default="1h",
        name="granularity",
        require=True,
    )

    def do_generate(self, api_key, proxy, logger):
        """
        Method to fetch the api response and process and send the response with extractions in the Splunk.

        :param api_key: GreyNoise API Key.
        :param proxy:
        :param logger:
        :logger: logger object.
        """
        ip_address = self.ip_address
        days = self.days
        field = self.field
        granularity = self.granularity

        logger.info("Started retrieving timeline results for ip: {}".format(str(ip_address)))

        if ip_address == "":
            logger.error("Parameter ip_address should not be empty.")
            self.write_error("Parameter ip_address should not be empty.")
            exit(1)

        # Strip the spaces from the parameter value if given
        if days:
            days = days.strip()

        # Validating the given parameters
        try:
            days = validator.Integer(option_name="days", minimum=1, maximum=90).validate(days)
        except ValueError as e:
            # Validator will throw ValueError with error message when the parameters are not proper
            logger.error(str(e))
            self.write_error(str(e))
            exit(1)

        # Opting timeout of 240 seconds for the request
        if "http" in proxy:
            api_config = APIConfig(api_key=api_key, timeout=240, integration_name=INTEGRATION_NAME, proxy=proxy)
            api_client = GreyNoise(api_config)
        else:
            api_config = APIConfig(api_key=api_key, timeout=240, integration_name=INTEGRATION_NAME)
            api_client = GreyNoise(api_config)

        logger.info(
            "Fetching timeline events for: {}, days: {}".format(
                str(ip_address), str(days)
            )
        )

        # Keep generating the events till result_size is not reached or all the query results are sent to Splunk
        try:
            for event in response_scroller(api_client, logger, ip_address, days, field, granularity):
                yield event

            logger.info("Successfully retrieved timeline results for the GreyNoise IP: {}".format(str(ip_address)))
        except Exception as e:
            logger.error("Error processing gniptimeline command: {}".format(e))
            if "401" in str(e):
                self.write_error("Error processing gniptimeline command.  API Key not valid")
            elif "403" in str(e):
                self.write_error("Error processing gniptimeline command.  API Key not authorized for this feature")
            else:
                self.write_error("Error processing gniptimeline command.  Check greynoise_main.log for more details")
            exit(1)

    def __init__(self):
        """Initialize custom command class."""
        super(GNIPTimelineCommand, self).__init__()


dispatch(GNIPTimelineCommand, sys.argv, sys.stdin, sys.stdout, __name__)
