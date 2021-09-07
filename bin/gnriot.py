import sys
import time  # noqa # pylint: disable=unused-import
import traceback

import app_greynoise_declare  # noqa # pylint: disable=unused-import
from requests.exceptions import ConnectionError, RequestException
from splunklib.binding import HTTPError
from splunklib.searchcommands import dispatch, EventingCommand, Configuration, Option
from greynoise import GreyNoise
from greynoise.exceptions import RateLimitError, RequestFailure

import event_generator
from greynoise_exceptions import APIKeyNotFoundError
from greynoise_constants import INTEGRATION_NAME
import utility
import validator


@Configuration()
class GNRiotCommand(EventingCommand):
    """
    gnriot - Generating and Transforming Command.

    This command can be used as generating command as well as transforming command,
    When used as generating command, it returns riot information of the given IP address,
    When used as transforming command, it adds the riot information to the events that are returned from Splunk search.

    Data pulled from /v2/riot/{ip} using GreyNoise Python SDK

    **Syntax**::
    `| gnriot ip="10.0.1.254"`
    `index=_internal | gnriot ip_field="ip"`

    **Description**::
    When used as generating command, gnriot command uses the IP address provided in ip field to return riot information,
    when used as transforming command, gnriot command uses the field representing IP address presented by ip_field
    to add the riot information to each events.
    The Riot information is pulled using method :method:`riot` from GreyNoise Python SDK.
    """

    ip = Option(
        doc='''**Syntax:** **ip=***<ip_address>*
        **Description:** IP address for which riot information needs to be retrieved from GreyNoise''',
        name='ip', require=False
    )

    ip_field = Option(
        doc='''
        **Syntax:** **ip_field=***<ip_field>*
        **Description:** Name of the field representing IP address in Splunk events''',
        name='ip_field', require=False
    )

    api_validation_flag = False

    def transform(self, records):
        """Method that processes and yield event records to the Splunk events pipeline."""
        ip_address = self.ip
        ip_field = self.ip_field
        api_key = ""
        EVENTS_PER_CHUNK = 1
        THREADS = 3
        USE_CACHE = False
        logger = utility.setup_logger(
            session_key=self._metadata.searchinfo.session_key, log_context=self._metadata.searchinfo.command)

        if ip_address and ip_field:
            logger.error("Please use parameter ip to work gnriot as generating command or "
                         "use parameter ip_field to work gnriot as transforming command.")
            self.write_error("Please use parameter ip to work gnriot as generating command or "
                             "use parameter ip_field to work gnriot as transforming command")
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

        if ip_address and not ip_field:
            # This peice of code will work as generating command and will not use the Splunk events.
            # Strip the spaces from the parameter value if given
            ip_address = ip_address.strip()

            logger.info("Started retrieving results")
            try:
                logger.debug("Initiating to fetch RIOT information for IP address: {}".format(str(ip_address)))
                api_client = GreyNoise(api_key=api_key, timeout=120, integration_name=INTEGRATION_NAME)
                # Opting timout 120 seconds for the requests
                session_key = self._metadata.searchinfo.session_key
                riot_information = utility.get_response_for_generating(
                    session_key, api_client, ip_address, 'greynoise_riot', logger)
                logger.info("Retrieved results successfully")

                # Process the API response and send the riot information of IP with extractions to the Splunk
                yield event_generator.make_valid_event('riot', riot_information, True)
                logger.debug("Fetched RIOT information for ip={} from GreyNoise API".format(str(ip_address)))

            except ValueError as e:
                error_msg = str(e).split(":")
                logger.debug("Generating RIOT information for ip={} manually".format(str(ip_address)))
                event = {
                    'ip': ip_address,
                    'error': error_msg[0]
                }
                yield event_generator.make_invalid_event('riot', event, True)
                logger.warn(error_msg)
                self.write_warning(
                    "Value of IP address passed to {command_name} is either invalid or non-routable".format(
                        command_name=str(self._metadata.searchinfo.command)))
            except RateLimitError:
                logger.error("Rate limit error occured while fetching the context information for ip={}".format(
                    str(ip_address)))
                self.write_error("The Rate Limit has been exceeded. Please contact the Administrator")
            except RequestFailure as e:
                response_code, response_message = e.args
                if response_code == 401:
                    msg = "Unauthorized. Please check your API key."
                else:
                    # Need to handle this, as splunklib is unable to handle the exception with
                    # (400, {'error': 'error_reason'}) format
                    msg = ("The API call to the GreyNoise platform have been failed "
                           "with status_code: {} and error: {}").format(
                        response_code, response_message['error'] if isinstance(response_message, dict)
                        else response_message)

                logger.error("{}".format(str(msg)))
                self.write_error(msg)
            except ConnectionError:
                logger.error("Error while connecting to the Server. Please check your connection and try again.")
                self.write_error("Error while connecting to the Server. Please check your connection and try again.")
            except RequestException:
                logger.error(
                    "There was an ambiguous exception that occurred while handling your Request. Please try again.")
                self.write_error(
                    "There was an ambiguous exception that occurred while handling your Request. Please try again.")
            except Exception:
                logger.error("Exception: {} ".format(str(traceback.format_exc())))
                self.write_error("Exception occured while fetching the RIOT information of the IP address. "
                                 "See greynoise_main.log for more details.")

        elif ip_field:

            logger.info("Started retrieving RIOT information for the IP addresses present in field: {}".format(
                str(ip_field)))
            # Enter the mechanism only when the Search is complete and all the events are available
            if self.search_results_info and not self.metadata.preview:
                try:
                    # Strip the spaces from the parameter value if given
                    ip_field = ip_field.strip()
                    # Validating the given parameter
                    try:
                        ip_field = validator.Fieldname(option_name='ip_field').validate(ip_field)
                    except ValueError as e:
                        # Validator will throw ValueError with error message when the parameters are not proper
                        logger.error(str(e))
                        self.write_error(str(e))
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

                    # This piece of code will work as transforming command and will use
                    # the Splunk ingested events and field which is specified in ip_field.
                    # divide the records in the form of dict of tuples having chunk_index as key
                    # {<index>: (<records>, <All the ips in records>)}
                    chunk_dict = event_generator.batch(
                        records, ip_field, EVENTS_PER_CHUNK, logger, optimize_requests=False)
                    logger.debug("Successfully divided events into chunks")

                    # This means there are only 1000 or below IPs to call in the entire bunch of records
                    # Use one thread with single thread with caching mechanism enabled for the chunk
                    if len(chunk_dict) == 1:
                        logger.debug("Less then 1000 distinct IPs are present, "
                                     "optimizing the IP requests call to GreyNoise API...")
                        THREADS = 1
                        USE_CACHE = True

                    api_client = GreyNoise(
                        api_key=api_key, timeout=120, use_cache=USE_CACHE, integration_name=INTEGRATION_NAME)

                    # When no records found, batch will return {0:([],[])}
                    if len(chunk_dict) > 0:
                        for event in event_generator.get_all_events(
                                self._metadata.searchinfo.session_key, api_client, 'greynoise_riot', ip_field,
                                chunk_dict, logger, threads=THREADS):
                            yield event

                        logger.info("Successfully sent all the results to the Splunk")
                    else:
                        logger.info("No events found, please increase the search timespan to have more search results.")
                except Exception:
                    logger.info(
                        "Exception occured while adding the RIOT information to the events, Error: {}".format(
                            traceback.format_exc()))
                    self.write_error("Exception occured while adding the RIOT information of the IP addresses "
                                     "to events. See greynoise_main.log for more details.")

        else:
            logger.error("Please specify exactly one parameter from ip and ip_field with some value.")
            self.write_error("Please specify exactly one parameter from ip and ip_field with some value.")

    def __init__(self):
        """Initialize custom command class."""
        super(GNRiotCommand, self).__init__()


dispatch(GNRiotCommand, sys.argv, sys.stdin, sys.stdout, __name__)
