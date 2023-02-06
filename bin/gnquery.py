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


def response_scroller(api_client, logger, query, result_size, page_size):
    """Uses api_client instance of GreyNoise SDK to fetch query results and traverse them if result set is too large."""
    # This will keep the count of how many events are remaining to be sent to Splunk
    remaining_chunk_size = result_size
    completion_flag = False
    scroll = None

    while not completion_flag:
        event_count = 0
        size = page_size

        # Avoid the extra call if expected number of events are already retrieved
        if remaining_chunk_size == 0:
            logger.debug("No GreyNoise query results remaining to be sent, completing the search...")
            break

        # check query size and see if total results is less than requested result size
        stats_api_response = api_client.stats(query=query)
        if stats_api_response.get('count', None) < remaining_chunk_size:
            remaining_chunk_size = stats_api_response.get('count', None)
            logger.debug("Query result count is smaller than result_max, total results: {}".format(remaining_chunk_size))

        # Do not fetch a bunch of results if user does not request so many results
        # Fetch only required numbers of events to keep away if the requested size is less than 10,000
        if remaining_chunk_size < size:
            size = remaining_chunk_size
            logger.debug("Size for the GNQL query is configured to {}".format(size))

        api_response = api_client.query(query=query, size=size, scroll=scroll)

        if api_response.get('count', None):
            # If this is the last page of API response, the scroll will not be present
            scroll = api_response.get('scroll', None)
            api_data = api_response.get('data', [])

            for ip_data in api_data:
                if event_count == 0 and remaining_chunk_size == result_size:
                    yield event_generator.make_valid_event('query', ip_data, True)
                else:
                    yield event_generator.make_valid_event('query', ip_data, False)

                event_count = event_count + 1

                if event_count == remaining_chunk_size:
                    completion_flag = True
                    break

            remaining_chunk_size = remaining_chunk_size - event_count
            logger.debug("Statistics: Remaining chunk size: {} : Events written:{}".format(
                remaining_chunk_size, event_count))
        else:
            message = api_response.get('message', '')
            query = api_response.get('query', '')
            logger.info("No results returned for GreyNoise query: {}, message: {}".format(str(query), str(message)))
            event = {
                'message': message,
                'query': query
            }
            yield event_generator.make_invalid_event('query', event, True)
            exit(1)

        # If we are on the last page of the results, scroll will not be present.
        if scroll is None:
            logger.debug("Last page of the GreyNoise query results detected, completing the search...")
            completion_flag = True


@Configuration(type="events")
class GNQueryCommand(BaseCommandHandler):
    """
    gnquery - Generating Command.

    Generating command that returns the results of the GreyNoise query,
    Data pulled from /v2/experimental/gnql using GreyNoise Python SDK

    **Syntax**::
    `| gnquery query="classification:malicious" result_size="50"`
    `| gnquery query="classification:benign page_size="500"`

    **Description**::
    The `gnquery` command uses the `GNQL query` provided in `query` parameter to return GreyNoise
    query results using method :method:`query` from GreyNoise Python SDK.
    The optional parameter `result_size` can be used to limit number of the results retrieved.
     The optional parameter `page_size` can be used to control the number of results returned per API request.
    """

    query = Option(
        doc='''**Syntax:** **query=***<GNQL_query>*
        **Description:** GNQL query whose results needs to be retrieved from GreyNoise''',
        name='query', require=True
    )

    result_size = Option(
        doc='''**Syntax:** **result_size=***<GNQL_query>*
        **Description:**Total number of GNQL query results needs to be retrieved from GreyNoise''',
        default="50000", name='result_size', require=False
    )

    page_size = Option(
        doc='''**Syntax:** **page_size=***<GNQL_query>*
        **Description:**Number of results per page to return by the GNQL API''',
        default="1000", name='page_size', require=False
    )

    def do_generate(self, api_key, proxy, logger):
        """
        Method to fetch the api response and process and send the response with extractions in the Splunk.

        :param api_key: GreyNoise API Key.
        :logger: logger object.
        """
        query = self.query
        result_size = self.result_size
        page_size = self.page_size

        logger.info("Started retrieving results for query: {}".format(str(query)))

        if query == '':
            logger.error("Parameter query should not be empty.")
            self.write_error("Parameter query should not be empty.")
            exit(1)

        # Strip the spaces from the parameter value if given
        if result_size:
            result_size = result_size.strip()

        if page_size:
            page_size = page_size.strip()

        # Validating the given parameters
        try:
            result_size = validator.Integer(option_name='result_size', minimum=1).validate(result_size)
            page_size = validator.Integer(option_name='page_size', minimum=1).validate(page_size)
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

        logger.info("Fetching results for GNQL query: {}, requested number of results: {}, page size: {}".format(
            str(query), str(result_size), str(page_size)))

        # Keep generating the events till result_size is not reached or all the query results are sent to Splunk
        for event in response_scroller(api_client, logger, query, result_size, page_size):
            yield event

        logger.info("Successfully retrieved results for the GreyNoise query: {}".format(str(query)))

    def __init__(self):
        """Initialize custom command class."""
        super(GNQueryCommand, self).__init__()


dispatch(GNQueryCommand, sys.argv, sys.stdin, sys.stdout, __name__)
