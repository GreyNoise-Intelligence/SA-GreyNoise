import sys
import time  # noqa # pylint: disable=unused-import
import traceback

import app_greynoise_declare  # noqa # pylint: disable=unused-import
from splunklib.searchcommands import dispatch, EventingCommand, Configuration, Option
from splunklib.binding import HTTPError
from greynoise import GreyNoise

import event_generator
from greynoise_exceptions import APIKeyNotFoundError
from greynoise_constants import INTEGRATION_NAME
import utility
import validator


@Configuration()
class GNEnrichCommand(EventingCommand):
    """
    gnenrich - Transforming Command.

    Transforming command that enriches Splunk search events with the context information of the IP addresses
    present as values in the IP field passed in ip_field parameter.
    Data pulled from: /v2/noise/context/{ip}

    **Syntax**::
    `index=firewall | gnenrich ip_field="ip"

    **Description**::
    The `gnenrich` command uses the IP represented by IP field in `ip_field` to return
    context information using method :method:`quick` from GreyNoise Python SDK.
    """

    ip_field = Option(
        doc='''
        **Syntax:** **ip_field=***<ip_field>*
        **Description:** Name of the field representing IP address in Splunk events''',
        name='ip_field', require=True
    )

    api_validation_flag = False

    def transform(self, records):
        """Method that processes and yield event records to the Splunk events pipeline."""
        # Setup logger
        logger = utility.setup_logger(
            session_key=self._metadata.searchinfo.session_key, log_context=self._metadata.searchinfo.command)

        if self.search_results_info and not self.metadata.preview:

            EVENTS_PER_CHUNK = 1
            THREADS = 3
            USE_CACHE = False
            ip_field = self.ip_field

            logger.info("Started retrieving context information for the IP addresses present in field: {}".format(
                str(ip_field)))

            try:
                # Strip the spaces from the parameter value if given
                if ip_field:
                    ip_field = ip_field.strip()
                # Validating the given parameters
                try:
                    ip_field = validator.Fieldname(option_name='ip_field').validate(ip_field)
                except ValueError as e:
                    # Validator will throw ValueError with error message when the parameters are not proper
                    logger.error(str(e))
                    self.write_error(str(e))
                    exit(1)

                try:
                    message = ''
                    api_key = utility.get_api_key(self._metadata.searchinfo.session_key, logger=logger)
                except APIKeyNotFoundError as e:
                    message = str(e)
                except HTTPError as e:
                    message = str(e)

                if message:
                    self.write_error(message)
                    logger.error("Error occured while retrieving API key, Error: {}".format(message))
                    exit(1)

                # API key validation
                if not self.api_validation_flag:
                    api_key_validation, message = utility.validate_api_key(api_key, logger)
                    logger.debug("API validation status: {}, message: {}".format(api_key_validation, str(message)))
                    self.api_validation_flag = True
                    if not api_key_validation:
                        logger.info(message)
                        self.write_error(message)
                        exit(1)

                # divide the records in the form of dict of tuples having chunk_index as key
                # {<index>: (<records>, <All the ips in records>)}
                chunk_dict = event_generator.batch(records, ip_field, EVENTS_PER_CHUNK, logger, optimize_requests=False)
                logger.debug("Successfully divided events into chunks")

                # This means there are only 1000 or below IPs to call in the entire bunch of records
                # Use one thread with single thread with caching mechanism enabled for the chunk
                if len(chunk_dict) == 1:
                    logger.debug(
                        "Less then 1000 distinct IPs are present, optimizing the IP requests call to GreyNoise API...")
                    THREADS = 1
                    USE_CACHE = True

                # Opting timout 120 seconds for the requests
                api_client = GreyNoise(api_key=api_key, timeout=120,
                                       use_cache=USE_CACHE, integration_name=INTEGRATION_NAME)

                if len(chunk_dict) > 0:
                    for event in event_generator.get_all_events(
                            self._metadata.searchinfo.session_key, api_client, 'enrich', ip_field, chunk_dict, logger,
                            threads=THREADS):
                        yield event

                    logger.info("Successfully sent all the results to the Splunk")
                else:
                    logger.info("No events found, please increase the search timespan to have more search results.")

            except Exception:
                logger.info(
                    "Exception occured while getting context information for events events, Error: {}".format(
                        traceback.format_exc()))
                self.write_error(
                    "Exception occured while enriching events with the context information of IP addresses. "
                    "See greynoise_main.log for more details.")

    def __init__(self):
        """Initialize custom command class."""
        super(GNEnrichCommand, self).__init__()


dispatch(GNEnrichCommand, sys.argv, sys.stdin, sys.stdout, __name__)
