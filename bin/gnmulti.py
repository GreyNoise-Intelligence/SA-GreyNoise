import sys
import time
import traceback

import app_greynoise_declare
from splunklib.searchcommands import dispatch, EventingCommand, Configuration, Option
from splunklib.binding import HTTPError
from greynoise import GreyNoise

import event_generator
from greynoise_exceptions import APIKeyNotFoundError
import utility
import validator

@Configuration()
class GNMultiCommand(EventingCommand):
    """
    Transforming command that adds the noise status information to each event.
    Data pulled from: /v2/noise/multi/quick

    **Syntax**::
    `index=firewall | gnmulti ip_field="ip"

    **Description**::
    The `gnmulti` command uses the IP represented by IP field in `ip_field` to return 
    Noise status using method :method:`quick` from GreyNoise Python SDK.
    """

    ip_field = Option(
        doc='''
        **Syntax:** **ip_field=***<ip_field>*
        **Description:** Name of the field representing IP address in Splunk events''',
        name='ip_field', require=True
    )

    def transform(self, records):

        logger = utility.setup_logger(session_key=self._metadata.searchinfo.session_key, log_context=self._metadata.searchinfo.command)
        
        # Enter the mechanism only when the Search is complete and all the events are available
        if self.search_results_info and not self.metadata.preview:

            EVENTS_PER_CHUNK = 1000
            THREADS = 3
            USE_CACHE = False
            ip_field = self.ip_field
            
            logger.info("Started retrieving noise status of the IP addresses present in field: {}".format(ip_field))
            
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
                api_key_validation, message = utility.validate_api_key(api_key, logger)
                logger.debug("API validation status: {}, message: {}".format(api_key_validation, str(message)))
                if not api_key_validation:
                    logger.info(message)
                    self.write_error(message)
                    exit(1)
                    
                # Divide all the records in the form of dict of tuples having chunk_index as a key
                # {<chunk_index>: (<records>, <All the ips present in records>)}
                chunk_dict = event_generator.batch(records, ip_field, EVENTS_PER_CHUNK, logger)
                logger.debug("Successfully divided events into chunks")

                # This means there are only 1000 or below IPs to call in the entire bunch of records
                # Use one thread with single thread with caching mechanism enabled for the chunk
                if len(chunk_dict) == 1:
                    logger.info("Less then 1000 distinct IPs are present, optimizing the IP requests call to GreyNoise API...")
                    THREADS = 1
                    USE_CACHE = True

                # Opting timout 120 seconds for the requests
                api_client = GreyNoise(api_key=api_key, timeout=120, use_cache=USE_CACHE, integration_name="Splunk")

                # When no records found, batch will return {0:([],[])}
                if len(list(chunk_dict.values())[0][0]) >= 1:
                    for event in event_generator.get_all_events(api_client, 'multi', ip_field, chunk_dict, logger, threads=THREADS):
                        yield event
                    
                    logger.info("Successfully sent all the results to the Splunk")
                else:
                    logger.info("No events found, please increase the search timespan to have more search results.")

            except Exception as e:
                logger.info("Exception occured while adding the noise status to the events, Error: {}".format(traceback.format_exc()))
                self.write_error("Exception occured while adding the noise status of the IP addresses to events. See greynoise_main.log for more details.")

    def __init__(self):
        super(GNMultiCommand, self).__init__()

dispatch(GNMultiCommand, sys.argv, sys.stdin, sys.stdout, __name__)
