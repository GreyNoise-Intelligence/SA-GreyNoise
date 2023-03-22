import re # noqa # pylint: disable=unused-import
import sys
import traceback # noqa # pylint: disable=unused-import

import app_greynoise_declare # noqa # pylint: disable=unused-import
from splunklib.searchcommands import dispatch, Configuration, Option
from greynoise import GreyNoise

from base_command_handler import BaseCommandHandler
from greynoise_constants import INTEGRATION_NAME
import event_generator
import validator


def response_scroller(api_client, logger, ip_address, min_score, limit):
    """Uses api_client instance of GreyNoise SDK to fetch query results and traverse them if result set is too large."""
    # This will keep the count of how many events are remaining to be sent to Splunk
    completion_flag = False

    while not completion_flag:
        event_count = 0

        api_response = api_client.similar(ip_address=ip_address, min_score=min_score, limit=limit)

        if api_response.get('total', None) != 0:
            similar_ips = api_response.get('similar_ips', [])
            sim_ip_count = api_response.get('total', None)

            for sim_ip in similar_ips:
                if event_count == 0 and remaining_chunk_size == result_size:
                    yield event_generator.make_valid_event('similar', sim_ip, True)
                else:
                    yield event_generator.make_valid_event('similar', sim_ip, False)

                event_count = event_count + 1

                if event_count == sim_ip_count:
                    completion_flag = True
                    break

            remaining_chunk_size = remaining_chunk_size - event_count
            logger.debug("Statistics: Remaining chunk size: {} : Events written:{}".format(
                remaining_chunk_size, event_count))
        else:
            message = api_response.get('message', '')
            ip = api_response.get('ip', '')
            logger.info("No results returned for GreyNoise IP: {}, message: {}".format(str(ip), str(message)))
            event = {
                'message': message,
                'ip': ip
            }
            yield event_generator.make_invalid_event('similar', event, True)
            exit(1)

        # If we are on the last page of the results, scroll will not be present.
        if scroll is None:
            logger.debug("Last page of the GreyNoise query results detected, completing the search...")
            completion_flag = True


@Configuration(type="events")
class GNIPSimilarCommand(BaseCommandHandler):
    """
    gnipsimilar - Generating Command.

    Generating command that returns the results of the GreyNoise Similarity tool,
    Data pulled from /v3/similaritl using GreyNoise Python SDK

    **Syntax**::
    `| gnipsimilar ip_address="1.2.3.4" limit="50"`
    `| gnipsimilar ip_address="1.2.3.4" limit="50" min_score="90"`

    **Description**::
    The `gnipsimilar` command uses the `IP Address` provided in `ip_address` parameter to return GreyNoise
    similarity results using method :method:`similar` from GreyNoise Python SDK.
    The optional parameter `min_score` can be used to provide the min_score for matches returned
     The optional parameter `limit` can be used to control max number of results to return.
    """

    ip_address = Option(
        doc='''**Syntax:** **ip_address=***<ip_address>*
        **Description:** IP Address to get Similar IPs for''',
        name='ip_address', require=True
    )

    min_score = Option(
        doc='''**Syntax:** **min_score=***<min_score>*
        **Description:**Only get similar IPs with a score above this value''',
        default="90", name='min_score', require=False
    )

    limit = Option(
        doc='''**Syntax:** **limit=***<limit>*
        **Description:**Max number of similar IPs to return''',
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
        min_score = self.min_score
        limit = self.limit

        logger.info("Started retrieving similarity results for ip: {}".format(str(ip_address)))

        if ip_address == '':
            logger.error("Parameter ip_address should not be empty.")
            self.write_error("Parameter ip_address should not be empty.")
            exit(1)

        # Strip the spaces from the parameter value if given
        if min_score:
            min_score = min_score.strip()

        if limit:
            limit = limit.strip()

        # Validating the given parameters
        try:
            min_score = validator.Integer(option_name='min_score', minimum=1).validate(min_score)
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

        logger.info("Fetching results for Similarity lookup: {}, requested number of results: {}, min score: {}".format(
            str(ip_address), str(limit), str(min_score)))

        # Keep generating the events till result_size is not reached or all the query results are sent to Splunk
        for event in response_scroller(api_client, logger, ip_address, min_score, limit):
            yield event

        logger.info("Successfully retrieved similarity results for the GreyNoise IP: {}".format(str(ip_address)))

    def __init__(self):
        """Initialize custom command class."""
        super(GNIPSimilarCommand, self).__init__()


dispatch(GNIPSimilarCommand, sys.argv, sys.stdin, sys.stdout, __name__)
