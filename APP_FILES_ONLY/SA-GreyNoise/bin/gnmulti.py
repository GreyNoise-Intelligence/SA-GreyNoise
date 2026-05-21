import re
import sys
import time  # noqa # pylint: disable=unused-import
import traceback

import app_greynoise_declare  # noqa # pylint: disable=unused-import
import event_generator
import requests
import utility
import validator
from greynoise.api import APIConfig, GreyNoise
from greynoise_constants import (
    INTEGRATION_NAME,
    IPV4_REGEX,
    IPV6_REGEX,
    SENDALERT_COMMAND,
    VERIFY_INTERNAL_SSL,
)
from greynoise_exceptions import APIKeyNotFoundError
from service_utils import create_service
from solnlib.splunkenv import get_splunkd_uri
from splunklib.binding import HTTPError
from splunklib.searchcommands import Configuration, EventingCommand, Option, dispatch


@Configuration()
class GNMultiCommand(EventingCommand):
    """
    gnmulti - Transforming Command.

    Transforming command that adds the Internet Scanner and Business Service Intelligence status
    information to each event. Data pulled from: /v3/ip

    **Syntax**::
    `index=firewall | gnmulti ip_field="ip"

    **Description**::
    The `gnmulti` command uses the IP represented by IP field in `ip_field` to return
    Internet Scanner and Business Service Intelligence status using method :method:`quick` from GreyNoise Python SDK.
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
        super(GNMultiCommand, self).__init__()
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

    def check_es_app_exists(self, logger):
        """Check if ES app exists."""
        try:
            logger.info("message=check_es_app_exists | started checking if ES app exists.")
            headers = {
                "Authorization": "Splunk {}".format(self._metadata.searchinfo.session_key),
                "Content-Type": "application/json",
            }
            response = requests.get(
                get_splunkd_uri() + "/servicesNS/-/SplunkEnterpriseSecuritySuite/",
                headers=headers,
                verify=VERIFY_INTERNAL_SSL,
            )
            if response.status_code != 200:
                logger.debug("message=response_returned | {} : {}".format(response.status_code, response.text))
                return False
            return True
        except Exception:
            logger.error(
                "message=failed_to_check_es_app | Failed to check ES app exists : {}".format(traceback.format_exc())
            )
            return False

    def generate_es_alert(self, event, service, classification, classification_to_score, logger):
        """Generate alert in ES."""
        try:
            risk_object = event.get("gn_ip", "")
            risk_description = f"Adjusted by the GreyNoise for {classification} classification."
            logger.info("message=generate_es_alert " f"| started generating Splunk ES alert for IP: {risk_object}")
            # Prepare SPL
            calculated_score = classification_to_score.get(classification, classification_to_score.get("unknown"))
            risk_object_type = None

            if re.search(IPV4_REGEX, risk_object):
                risk_object_type = "ipv4"
            elif re.search(IPV6_REGEX, risk_object):
                risk_object_type = "ipv6"
            else:
                logger.warning(f"message=generate_es_alert | Not a valid alert ip: {risk_object}")

            if risk_object_type:
                spl = SENDALERT_COMMAND.format(risk_object, risk_object_type, calculated_score, risk_description)
                # Run SPL as a search job
                job = service.jobs.create(spl)
                while not job.is_done():
                    time.sleep(0.2)

        except Exception as e:
            logger.error(f"message=generate_es_alert | Failed to run sendalert command: {e}")

    def transform(self, records):
        """Method that processes and yield event records to the Splunk events pipeline."""
        logger = utility.setup_logger(
            session_key=self._metadata.searchinfo.session_key, log_context=self._metadata.searchinfo.command
        )

        conf = utility.get_conf_file(self._metadata.searchinfo.session_key, file="app_greynoise_settings")
        parameters = conf.get("scan_deployment", {})
        is_update_risk_score_to_splunk_es = parameters.get("update_risk_score_to_splunk_es", 0)
        classification_to_score = {
            "malicious": parameters.get("malicious_score", 80),
            "suspicious": parameters.get("suspicious_score", 50),
            "unknown": parameters.get("unknown_score", 30),
            "benign": parameters.get("benign_score", 10),
        }

        service = None
        is_es_app_exists = None
        if bool(int(is_update_risk_score_to_splunk_es)):
            try:
                # Get session info
                session_key = self._metadata.searchinfo.session_key
                # Connect to Splunk using the SDK
                service = create_service(session_key, "nobody")

                is_es_app_exists = self.check_es_app_exists(logger)
                if is_es_app_exists:
                    logger.info("message=es_app_exists " "| ES app exists.")
                else:
                    logger.warning(
                        "message=es_app_does_not_exist " "| ES app does not exist. Skipping ES alert generation."
                    )
            except Exception:
                logger.error("message=unknown_error | Unknown error occured: {}".format(traceback.format_exc()))

        # Enter the mechanism only when the Search is complete and all the events are available
        if self.search_results_info and not self.metadata.preview:
            EVENTS_PER_CHUNK = 10000
            THREADS = 1
            ip_field = self.ip_field

            logger.info(
                "Started retrieving Internet Scanner and Business Service Intelligence status of the "
                "IP addresses present in field: {}".format(ip_field)
            )

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
                        "multi",
                        ip_field,
                        chunk_dict,
                        logger,
                        threads=THREADS,
                    ):
                        classification = event.get("greynoise_internet_scanner_intelligence_classification", None)
                        if classification and service and is_es_app_exists:
                            self.generate_es_alert(event, service, classification, classification_to_score, logger)
                        yield event
                    tot_time_end = time.time()
                    logger.debug("Total execution time => {}".format(tot_time_end - tot_time_start))

                    logger.info("Successfully sent all the results to the Splunk")
                else:
                    logger.info("No events found, please increase the search timespan to have more search results.")

            except Exception:
                logger.info(
                    "Exception occurred while adding the Internet Scanner and Business Service "
                    "Intelligence status to the events, Error: {}".format(traceback.format_exc())
                )
                self.write_error(
                    "Exception occurred while adding the Internet Scanner and Business Service Intelligence status "
                    "of the IP addresses to events. See greynoise_main.log for more details."
                )


dispatch(GNMultiCommand, sys.argv, sys.stdin, sys.stdout, __name__)
