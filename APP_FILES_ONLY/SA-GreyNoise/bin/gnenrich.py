import sys
import time  # noqa # pylint: disable=unused-import
import traceback

import app_greynoise_declare  # noqa # pylint: disable=unused-import
import event_generator
import utility
import validator
from greynoise.api import APIConfig, GreyNoise
from greynoise_constants import INTEGRATION_NAME
from greynoise_exceptions import APIKeyNotFoundError
from splunklib.binding import HTTPError
from splunklib.searchcommands import Configuration, EventingCommand, Option, dispatch


@Configuration()
class GNEnrichCommand(EventingCommand):
    """
    gnenrich - Transforming Command.

    Transforming command that enriches Splunk search events with the context information of the IP addresses
    present as values in the IP field passed in ip_field parameter.
    Data pulled from: v3/ip

    **Syntax**::
    `index=firewall | gnenrich ip_field="ip"

    **Description**::
    The `gnenrich` command uses the IP represented by IP field in `ip_field` to return
    context information using method :method:`ip_multi` from GreyNoise Python SDK.
    """

    ip_field = Option(
        doc="""
        **Syntax:** **ip_field=***<ip_field>*
        **Description:** Name of the field representing IP address in Splunk events""",
        name="ip_field",
        require=True,
    )

    api_validation_flag = False

    def __init__(self):
        """Initialize custom command class."""
        super(GNEnrichCommand, self).__init__()
        self.api_key = None
        self.proxy = None
        self.api_client = None

    def initialize_api(self, session_key, logger):
        """Initialize API key, proxy and validate API key."""
        try:
            message = ""
            self.proxy = utility.get_proxy(session_key, logger=logger)
            self.api_key = utility.get_api_key(session_key, logger=logger)
        except APIKeyNotFoundError as e:
            message = str(e)
        except HTTPError as e:
            message = str(e)

        if message:
            logger.error("Error occurred while retrieving Proxy and/or API key details, Error: {}".format(message))
            raise Exception(message)

        # API key validation
        if not self.api_validation_flag:
            api_key_validation, message = utility.validate_api_key(self.api_key, logger, self.proxy)
            logger.debug("API validation status: {}, message: {}".format(api_key_validation, str(message)))
            self.api_validation_flag = True
            if not api_key_validation:
                logger.info(message)
                raise Exception(message)

        # Initialize API client
        if "http" in self.proxy:
            api_config = APIConfig(
                api_key=self.api_key, timeout=120, integration_name=INTEGRATION_NAME, proxy=self.proxy
            )
        else:
            api_config = APIConfig(api_key=self.api_key, timeout=120, integration_name=INTEGRATION_NAME)
        self.api_client = GreyNoise(api_config)

    def transform(self, records):
        """Method that processes and yield event records to the Splunk events pipeline."""
        logger = utility.setup_logger(
            session_key=self._metadata.searchinfo.session_key, log_context=self._metadata.searchinfo.command
        )

        # Enter the mechanism only when the Search is complete and all the events are available
        if self.search_results_info and not self.metadata.preview:
            EVENTS_PER_CHUNK = 5000
            THREADS = 3
            ip_field = self.ip_field

            logger.info("Started retrieving internet scanner data for the IP addresses present in field: {}".format(ip_field))

            try:
                # Strip the spaces from the parameter value if given
                if ip_field:
                    ip_field = ip_field.strip()
                # Validating the given parameters
                try:
                    ip_field = validator.Fieldname(option_name="ip_field").validate(ip_field)
                except ValueError as e:
                    # Validator will throw ValueError with error message when the parameters are not proper
                    logger.error(str(e))
                    self.write_error(str(e))
                    exit(1)

                # Initialize API if not already done
                if not self.api_client:
                    try:
                        self.initialize_api(self._metadata.searchinfo.session_key, logger)
                    except Exception as e:
                        self.write_error(str(e))
                        exit(1)

                # Divide all the records in the form of dict of tuples having chunk_index as a key
                # {<chunk_index>: (<records>, <All the ips present in records>)}
                chunk_dict = event_generator.batch(records, ip_field, EVENTS_PER_CHUNK, logger)
                logger.debug(f"Successfully divided events into {len(chunk_dict)} chunk(s)")

                # When no records found, batch will return {0:([],[])}
                if len(list(chunk_dict.values())[0][0]) >= 1:
                    tot_time_start = time.time()
                    for event in event_generator.get_all_events(
                        self._metadata.searchinfo.session_key,
                        self.api_client,
                        "ip_multi",
                        ip_field,
                        chunk_dict,
                        logger,
                        threads=THREADS,
                    ):
                        yield event
                    tot_time_end = time.time()
                    logger.debug("Total execution time => {}".format(tot_time_end - tot_time_start))

                    logger.info("Successfully sent all the results to the Splunk")
                else:
                    logger.info("No events found, please increase the search timespan to have more search results.")

            except Exception:
                logger.info(
                    "Exception occurred while adding the internet scanner status to the events, Error: {}".format(
                        traceback.format_exc()
                    )
                )
                self.write_error(
                    "Exception occurred while adding the internet scanner status of the "
                    "IP addresses to events. See greynoise_main.log for more details."
                )


dispatch(GNEnrichCommand, sys.argv, sys.stdin, sys.stdout, __name__)
