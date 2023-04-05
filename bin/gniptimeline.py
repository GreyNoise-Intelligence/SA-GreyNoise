import re  # noqa # pylint: disable=unused-import
import sys
import traceback  # noqa # pylint: disable=unused-import

import app_greynoise_declare  # noqa # pylint: disable=unused-import
from splunklib.searchcommands import dispatch, Configuration, Option
from greynoise import GreyNoise

from base_command_handler import BaseCommandHandler
from greynoise_constants import INTEGRATION_NAME
import event_generator
import validator


def response_scroller(api_client, logger, ip_address, days, limit):
    """Uses api_client instance of GreyNoise SDK to fetch query results and traverse them if result set is too large."""
    event_count = 0

    api_response = api_client.timelinedaily(ip_address=ip_address, days=days, limit=limit)

    if api_response.get('activity', None):
        timeline_activity = api_response.get('activity', [])
        activity_count = len(timeline_activity)

        logger.debug("Processing {} timeline events for {}".format(activity_count, ip_address))

        for activity in timeline_activity:
            if event_count == 0:
                yield event_generator.make_valid_event('timeline', activity, True)
            else:
                yield event_generator.make_valid_event('timeline', activity, False)
            event_count = event_count + 1
    else:
        message = api_response.get('message', '')
        ip = api_response.get('ip', '')
        logger.info("No results returned for GreyNoise IP: {}, message: {}".format(str(ip), str(message)))
        event = {
            'message': message,
            'ip': ip
        }
        yield event_generator.make_invalid_event('timeline', event, True)
        exit(1)


@Configuration(type="events")
class GNIPTimelineCommand(BaseCommandHandler):
    """
    gniptimeline - Generating Command.

    Generating command that returns the results of the GreyNoise Timeline tool,
    Data pulled from /v3/timeline using GreyNoise Python SDK

    **Syntax**::
    `| gniptimeline ip_address="1.2.3.4" days="30"`
    `| gniptimeline ip_address="1.2.3.4" limit="50" days="30"`

    **Description**::
    The `gniptimeline` command uses the `IP Address` provided in `ip_address` parameter to return GreyNoise
    timeline results using method :method:`timelinedaily` from GreyNoise Python SDK.
    The optional parameter `days` can be used to provide the number of days to include in the timeline
     The optional parameter `limit` can be used to control max number of results to return.
    """

    ip_address = Option(
        doc='''**Syntax:** **ip_address=***<ip_address>*
        **Description:** IP Address to get Similar IPs for''',
        name='ip_address', require=True
    )

    days = Option(
        doc='''**Syntax:** **days=***<days>*
        **Description:**Number of days of events to retrieve''',
        default="30", name='days', require=False
    )

    limit = Option(
        doc='''**Syntax:** **limit=***<limit>*
        **Description:**Max number of timeline IPs to return''',
        default="50", name='limit', require=False
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
        limit = self.limit

        logger.info("Started retrieving timeline results for ip: {}".format(str(ip_address)))

        if ip_address == '':
            logger.error("Parameter ip_address should not be empty.")
            self.write_error("Parameter ip_address should not be empty.")
            exit(1)

        # Strip the spaces from the parameter value if given
        if days:
            min_score = days.strip()

        if limit:
            limit = limit.strip()

        # Validating the given parameters
        try:
            days = validator.Integer(option_name='days', minimum=1).validate(days)
            limit = validator.Integer(option_name='limit', minimum=1).validate(limit)
        except ValueError as e:
            # Validator will throw ValueError with error message when the parameters are not proper
            logger.error(str(e))
            self.write_error(str(e))
            exit(1)

        # Opting timeout of 240 seconds for the request
        if 'http' in proxy:
            api_client = GreyNoise(api_key=api_key, timeout=240, integration_name=INTEGRATION_NAME, proxy=proxy)
        else:
            api_client = GreyNoise(api_key=api_key, timeout=240, integration_name=INTEGRATION_NAME)

        logger.info("Fetching timeline events for: {}, requested number of results: {}, days: {}".format(
            str(ip_address), str(limit), str(days)))

        # Keep generating the events till result_size is not reached or all the query results are sent to Splunk
        try:
            for event in response_scroller(api_client, logger, ip_address, days, limit):
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
