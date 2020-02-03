import sys
import traceback

import app_greynoise_declare
from splunklib.searchcommands import dispatch, Configuration, Option
from greynoise import GreyNoise

from base_command_handler import BaseCommandHandler
import event_generator

@Configuration(type="events")
class IPContextCommand(BaseCommandHandler):
    """
    Generating command that returns the context information of an IP address,
    Data pulled from /v2/noise/context/{ip} using GreyNoise Python SDK
    This class is also used by `gncontext` command to provide backward compatibility.

    **Syntax**::
    `| gnip ip="10.0.1.254"`
    `| gncontext ip="10.0.1.254"`
    
    **Description**::
    The `gnip` and `gncontext` command uses the `IP` provided in `ip` to return GreyNoise context data
    from method :method:`ip` from GreyNoise Python SDK.
    """

    ip = Option(
        doc='''**Syntax:** **ip=***<ip_address>*
        **Description:** IP address for which context info needs to be retrieved from GreyNoise''',
        name='ip', require=True
    )
    
    def do_generate(self, api_key, logger):

        ip_address = self.ip
        
        try:
            # Strip the spaces from the parameter value if given
            if ip_address:
                ip_address = ip_address.strip()

            logger.info("Initiating to fetch context information for ip: {}".format(str(ip_address)))
            # Opting default timout 60 seconds for the request
            api_client = GreyNoise(api_key=api_key, timeout=60)
            context_info = api_client.ip(ip_address)
            logger.info("Successfully retrieved the context information for ip={}".format(str(ip_address)))

            # Process the API response and send the context information of IP with extractions in the Splunk
            results = event_generator.make_valid_event('ip', context_info, True)
            yield results

        except ValueError:
            logger.error("IP address: {} doesn\'t match the valid IP format".format(str(ip_address)))
            self.write_error("IP address doesn\'t match the valid IP format")

    def __init__(self):
        super(IPContextCommand, self).__init__()

dispatch(IPContextCommand, sys.argv, sys.stdin, sys.stdout, __name__)