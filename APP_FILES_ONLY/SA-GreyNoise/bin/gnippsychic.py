import sys
import time  # noqa # pylint: disable=unused-import
import traceback

import app_greynoise_declare  # noqa # pylint: disable=unused-import
import event_generator
import utility
import validator
from greynoise.api import APIConfig, GreyNoise
from greynoise.exceptions import RateLimitError, RequestFailure
from greynoise.util import validate_ip
from greynoise_constants import INTEGRATION_NAME
from greynoise_exceptions import APIKeyNotFoundError
from requests.exceptions import ConnectionError, RequestException
from splunklib.binding import HTTPError
from splunklib.searchcommands import Configuration, EventingCommand, Option, dispatch


@Configuration()
class GNIPPsychicCommand(EventingCommand):
    """
    gnippsychic - Generating and Transforming Command.

    This command can be used as generating command as well as transforming command.
    When used as generating command, it returns Psychic lookup results for the given IP addresses.
    When used as transforming command, it adds Psychic lookup information to the events returned
    from a Splunk search.
    Data pulled using method :method:`psychic_lookup_ips` from GreyNoise Python SDK.

    **Syntax**::
    `| gnippsychic ip="10.0.1.254"`
    `| gnippsychic ip="1.2.3.4,8.8.8.8"`
    `index=_internal | gnippsychic ip_field="ip"`

    **Description**::
    When used as generating command, gnippsychic uses the IP address or IP addresses provided in
    the ip field to return Psychic lookup results. When used as transforming command, gnippsychic
    uses the field representing IP address provided by ip_field to enrich each event.
    """

    ip = Option(
        doc="""**Syntax:** **ip=***<ip_address>*
        **Description:** IP address(es) for which Psychic lookup results need to be retrieved from GreyNoise""",
        name="ip",
        require=False,
    )

    ip_field = Option(
        doc="""
        **Syntax:** **ip_field=***<ip_field>*
        **Description:** Name of the field representing IP address in Splunk events""",
        name="ip_field",
        require=False,
    )

    api_validation_flag = False

    def __init__(self):
        """Initialize custom command class."""
        super(GNIPPsychicCommand, self).__init__()
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

        if not self.api_validation_flag:
            api_key_validation, message = utility.validate_api_key(self.api_key, logger, self.proxy)
            logger.debug("API validation status: {}, message: {}".format(api_key_validation, str(message)))
            self.api_validation_flag = True
            if not api_key_validation:
                logger.info(message)
                raise Exception(message)

        if "http" in self.proxy:
            api_config = APIConfig(
                api_key=self.api_key,
                timeout=120,
                integration_name=INTEGRATION_NAME,
                proxy=self.proxy,
                psychic=True,
                psychic_model=3,
            )
        else:
            api_config = APIConfig(
                api_key=self.api_key, timeout=120, integration_name=INTEGRATION_NAME, psychic=True, psychic_model=3
            )
        self.api_client = GreyNoise(api_config)

    def transform(self, records):
        """Method that processes and yield event records to the Splunk events pipeline."""
        ip_addresses = self.ip
        ip_field = self.ip_field
        EVENTS_PER_CHUNK = 50000
        THREADS = 1
        logger = utility.setup_logger(
            session_key=self._metadata.searchinfo.session_key, log_context=self._metadata.searchinfo.command
        )

        if ip_addresses and ip_field:
            logger.error(
                "Please use parameter ip to work gnippsychic as generating command or "
                "use parameter ip_field to work gnippsychic as transforming command."
            )
            self.write_error(
                "Please use parameter ip to work gnippsychic as generating command or "
                "use parameter ip_field to work gnippsychic as transforming command"
            )
            exit(1)

        if not self.api_client:
            try:
                self.initialize_api(self._metadata.searchinfo.session_key, logger)
            except Exception as e:
                self.write_error(str(e))
                exit(1)

        if ip_addresses and not ip_field:
            ip_addresses = [ip.strip() for ip in ip_addresses.split(",")]

            logger.info("Started retrieving Psychic lookup results")
            try:
                logger.debug("Initiating Psychic lookup for IP address(es): {}".format(str(ip_addresses)))

                valid_ips = []
                invalid_events = []
                first_record_flag = True
                for ip in ip_addresses:
                    try:
                        validate_ip(ip, strict=True)
                        valid_ips.append(ip)
                    except ValueError as e:
                        error_msg = str(e).split(":")
                        logger.debug("Generating Psychic error event for ip={}".format(str(ip)))
                        invalid_events.append(
                            event_generator.make_invalid_event(
                                "psychic", {"ip": ip, "error": error_msg[0]}, first_record_flag
                            )
                        )
                        if first_record_flag:
                            first_record_flag = False

                for invalid_event in invalid_events:
                    yield invalid_event

                if valid_ips:
                    psychic_results = self.api_client.psychic_lookup_ips(valid_ips)
                    logger.info("Retrieved Psychic lookup results successfully")

                    for ip in valid_ips:
                        for sample in psychic_results:
                            if ip == sample["ip"]:
                                yield event_generator.make_valid_event("psychic", sample, first_record_flag)
                                if first_record_flag:
                                    first_record_flag = False
                                logger.debug("Fetched Psychic lookup for ip={}".format(str(ip)))
                                break

                if invalid_events:
                    logger.warning("Value of one or more IP address(es) is either invalid or non-routable")
                    self.write_warning(
                        "Value of one or more IP address(es) passed to {command_name} "
                        "is either invalid or non-routable".format(command_name=str(self._metadata.searchinfo.command))
                    )

            except RateLimitError:
                logger.error(
                    "Rate limit error occurred while fetching Psychic lookup results for ips={}".format(
                        str(ip_addresses)
                    )
                )
                self.write_error("The Rate Limit has been exceeded. Please contact the Administrator")
            except RequestFailure as e:
                response_code, response_message = e.args
                if response_code == 401:
                    msg = "Unauthorized. Please check your API key."
                else:
                    msg = (
                        "The API call to the GreyNoise platform have been failed " "with status_code: {} and error: {}"
                    ).format(
                        response_code,
                        response_message["error"] if isinstance(response_message, dict) else response_message,
                    )

                logger.error("{}".format(str(msg)))
                self.write_error(msg)
            except RuntimeError as e:
                logger.error("Psychic lookup failed: {}".format(str(e)))
                self.write_error(str(e))
            except ConnectionError:
                logger.error("Error while connecting to the Server. Please check your connection and try again.")
                self.write_error("Error while connecting to the Server. Please check your connection and try again.")
            except RequestException:
                logger.error(
                    "There was an ambiguous exception that occurred while handling your Request. Please try again."
                )
                self.write_error(
                    "There was an ambiguous exception that occurred while handling your Request. Please try again."
                )
            except Exception:
                logger.error("Exception: {} ".format(str(traceback.format_exc())))
                self.write_error(
                    "Exception occurred while fetching Psychic lookup results for the IP address(es). "
                    "See greynoise_main.log for more details."
                )

        elif ip_field:
            if self.search_results_info and not self.metadata.preview:
                try:
                    ip_field = ip_field.strip()
                    try:
                        ip_field = validator.Fieldname(option_name="ip_field").validate(ip_field)
                    except ValueError as e:
                        logger.error(str(e))
                        self.write_error(str(e))
                        exit(1)

                    chunk_dict = event_generator.batch(records, ip_field, EVENTS_PER_CHUNK, logger)
                    logger.debug("Successfully divided events into {} chunk(s)".format(len(chunk_dict)))

                    tot_time_start = time.time()
                    if len(list(chunk_dict.values())[0][0]) >= 1:
                        for event in event_generator.get_all_events(
                            self._metadata.searchinfo.session_key,
                            self.api_client,
                            "psychic_multi",
                            ip_field,
                            chunk_dict,
                            logger,
                            threads=THREADS,
                        ):
                            yield event
                    else:
                        logger.info("No events found, please increase the search timespan to have more search results.")
                    tot_time_end = time.time()
                    logger.debug("Total execution time => {}".format(tot_time_end - tot_time_start))
                except Exception:
                    logger.info(
                        "Exception occurred while adding Psychic lookup results to the events, Error: {}".format(
                            traceback.format_exc()
                        )
                    )
                    self.write_error(
                        "Exception occurred while adding Psychic lookup results to the IP addresses in "
                        "events. See greynoise_main.log for more details."
                    )

        else:
            logger.error("Please specify exactly one parameter from ip and ip_field with some value.")
            self.write_error("Please specify exactly one parameter from ip and ip_field with some value.")


dispatch(GNIPPsychicCommand, sys.argv, sys.stdin, sys.stdout, __name__)
