import sys
import time  # noqa # pylint: disable=unused-import
import traceback

import app_greynoise_declare  # noqa # pylint: disable=unused-import
from requests.exceptions import ConnectionError, RequestException
from splunklib.binding import HTTPError
from splunklib.searchcommands import dispatch, EventingCommand, Configuration, Option
from greynoise import GreyNoise
from greynoise.exceptions import RateLimitError, RequestFailure
from greynoise.util import validate_ip
from caching import Caching

import event_generator
from greynoise_exceptions import APIKeyNotFoundError
from greynoise_constants import INTEGRATION_NAME
import utility
import validator


@Configuration()
class GNQuickCommand(EventingCommand):
    """
    gnquick - Generating and Transforming Command.

    This command can be used as generating command as well as transforming command,
    When used as generating command, it returns noise and RIOT status of the given IP addresses,
    When used as transforming command, it adds the noise and RIOT status information to
    the events that are returned from Splunk search.
    Data pulled from /v2/noise/multi/quick?ips=<ip_address1>,<ip_address2> using GreyNoise Python SDK

    **Syntax**::
    `| gnquick ip="10.0.1.254"`
    `| gnquick ip="1.2.3.4,8.8.8.8"`
    `index=_internal | gnquick ip_field="ip"`

    **Description**::
    When used as generating command, gnquick command uses the IP address or
    IP addresses provided in ip field to return
    Noise and Riot status, when used as transforming command, gnquick command uses the field representing IP address
    presented by ip_field to add the noise and RIOT information to each events.
    The Noise and Riot status is pulled using method :method:quick from GreyNoise Python SDK.
    """

    ip = Option(
        doc='''**Syntax:** **ip=***<ip_address>*
        **Description:** IP address(es) for which noise and RIOT status needs to be retrieved from GreyNoise''',
        name='ip', require=False
    )

    ip_field = Option(
        doc='''
        **Syntax:** **ip_field=***<ip_field>*
        **Description:** Name of the field representing IP address in Splunk events''',
        name='ip_field', require=False
    )

    def transform(self, records):
        """Method that processes and yield event records to the Splunk events pipeline."""
        ip_addresses = self.ip
        ip_field = self.ip_field
        api_key = ""
        EVENTS_PER_CHUNK = 5000
        THREADS = 3
        USE_CACHE = False
        logger = utility.setup_logger(
            session_key=self._metadata.searchinfo.session_key, log_context=self._metadata.searchinfo.command)

        if ip_addresses and ip_field:
            logger.error("Please use parameter ip to work gnquick as generating command or "
                         "use parameter ip_field to work gnquick as transforming command.")
            self.write_error("Please use parameter ip to work gnquick as generating command or "
                             "use parameter ip_field to work gnquick as transforming command")
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

        if ip_addresses and not ip_field:
            # This peice of code will work as generating command and will not use the Splunk events.
            # Splitting the ip_addresses by commas and stripping spaces from both the sides for each IP address
            ip_addresses = [ip.strip() for ip in ip_addresses.split(',')]

            logger.info("Started retrieving results")
            try:
                logger.debug("Initiating to fetch noise and RIOT status for IP address(es): {}".format(
                    str(ip_addresses)))

                api_client = GreyNoise(api_key=api_key, timeout=120, integration_name=INTEGRATION_NAME)

                # CACHING START
                cache_enabled = Caching.get_cache_settings(self._metadata.searchinfo.session_key)
                if int(cache_enabled) == 1:
                    cache_client = Caching(self._metadata.searchinfo.session_key, logger, 'multi')
                    cache_start = time.time()
                    ips_not_in_cache, ips_in_cache = utility.get_ips_not_in_cache(cache_client, ip_addresses, logger)
                    try:
                        response = []
                        if len(ips_in_cache) >= 1:
                            response = cache_client.query_kv_store(ips_in_cache)
                        if response is None:
                            logger.debug("KVStore is not ready. Skipping caching mechanism.")
                            noise_status = api_client.quick(ip_addresses)
                        elif response == []:
                            noise_status = utility.fetch_response_from_api(
                                api_client.quick, cache_client, ip_addresses, logger)
                        else:
                            noise_status = utility.fetch_response_from_api(
                                api_client.quick, cache_client, ips_not_in_cache, logger)
                            noise_status.extend(response)
                    except Exception:
                        logger.debug(
                            "An exception occurred while fetching response from cache.\n{}".format(
                                traceback.format_exc()))
                    logger.debug("Generating command with caching took {} seconds.".format(time.time() - cache_start))
                else:
                    # Opting timout 120 seconds for the requests
                    noise_status = api_client.quick(ip_addresses)
                logger.info("Retrieved results successfully")
                # CACHING END

                # Process the API response and send the noise and RIOT status information of IP with extractions
                # to the Splunk, Using this flag to handle the field extraction issue in custom commands
                # Only the fields extracted from the first event of generated by custom command
                # will be extracted from all events
                first_record_flag = True

                # Flag to indicate whether erroneous IPs are present
                erroneous_ip_present = False
                for ip in ip_addresses:
                    for sample in noise_status:
                        if ip == sample['ip']:
                            yield event_generator.make_valid_event('quick', sample, first_record_flag)
                            if first_record_flag:
                                first_record_flag = False
                            logger.debug("Fetched noise and RIOT status for ip={} from GreyNoise API".format(str(ip)))
                            break
                    else:
                        erroneous_ip_present = True
                        try:
                            validate_ip(ip, strict=True)
                        except ValueError as e:
                            error_msg = str(e).split(":")
                            logger.debug("Generating noise and RIOT status for ip={} manually".format(str(ip)))
                            event = {
                                'ip': ip,
                                'error': error_msg[0]
                            }
                            yield event_generator.make_invalid_event('quick', event, first_record_flag)

                            if first_record_flag:
                                first_record_flag = False

                if erroneous_ip_present:
                    logger.warn("Value of one or more IP address(es) is either invalid or non-routable")
                    self.write_warning("Value of one or more IP address(es) passed to {command_name} "
                                       "is either invalid or non-routable".format(command_name=str(
                                           self._metadata.searchinfo.command)))

            except RateLimitError:
                logger.error(
                    "Rate limit error occured while fetching the context information for ips={}".format(
                        str(ip_addresses)))
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
                self.write_error("Exception occured while fetching the noise and RIOT status of the IP address(es). "
                                 "See greynoise_main.log for more details.")

        elif ip_field:
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
                    api_key_validation, message = utility.validate_api_key(api_key, logger)
                    logger.debug("API validation status: {}, message: {}".format(api_key_validation, str(message)))
                    if not api_key_validation:
                        logger.info(message)
                        self.write_error(message)
                        exit(1)

                    # This piece of code will work as transforming command and will use
                    # the Splunk ingested events and field which is specified in ip_field.
                    chunk_dict = event_generator.batch(records, ip_field, EVENTS_PER_CHUNK, logger)

                    # This means there are only 1000 or below IPs to call in the entire bunch of records
                    # Use one thread with single thread with caching mechanism enabled for the chunk
                    if len(chunk_dict) == 1:
                        logger.info("Less then 1000 distinct IPs are present, "
                                    "optimizing the IP requests call to GreyNoise API...")
                        THREADS = 1
                        USE_CACHE = True

                    api_client = GreyNoise(api_key=api_key, timeout=120,
                                           use_cache=USE_CACHE, integration_name=INTEGRATION_NAME)
                    # When no records found, batch will return {0:([],[])}
                    tot_time_start = time.time()
                    if len(list(chunk_dict.values())[0][0]) >= 1:
                        for event in event_generator.get_all_events(
                                self._metadata.searchinfo.session_key, api_client, 'multi', ip_field, chunk_dict,
                                logger, threads=THREADS):
                            yield event
                    else:
                        logger.info("No events found, please increase the search timespan to have more search results.")
                    tot_time_end = time.time()
                    logger.debug("Total execution time => {}".format(tot_time_end - tot_time_start))
                except Exception:
                    logger.info(
                        "Exception occured while adding the noise and RIOT status to the events, Error: {}".format(
                            traceback.format_exc()))
                    self.write_error("Exception occured while adding the noise and RIOT status of "
                                     "the IP addresses to events. See greynoise_main.log for more details.")

        else:
            logger.error("Please specify exactly one parameter from ip and ip_field with some value.")
            self.write_error("Please specify exactly one parameter from ip and ip_field with some value.")

    def __init__(self):
        """Initialize custom command class."""
        super(GNQuickCommand, self).__init__()


dispatch(GNQuickCommand, sys.argv, sys.stdin, sys.stdout, __name__)
