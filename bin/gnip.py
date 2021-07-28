import sys
import traceback # noqa # pylint: disable=unused-import

import app_greynoise_declare # noqa # pylint: disable=unused-import
from splunklib.searchcommands import dispatch, Configuration, Option
from greynoise import GreyNoise

from base_command_handler import BaseCommandHandler
import event_generator


@Configuration(type="events")
class IPContextCommand(BaseCommandHandler):
    """
    gnip - Generating Command.

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
        """
        Method to fetch the api response and process and send the response with extractions in the Splunk.

        :param api_key: GreyNoise API Key.
        :logger: logger object.
        """
        ip_address = self.ip

        try:
            # Strip the spaces from the parameter value if given
            if ip_address:
                ip_address = ip_address.strip()

            logger.info("Initiating to fetch context information for ip: {}".format(str(ip_address)))
            # Opting default timout 60 seconds for the request
            api_client = GreyNoise(api_key=api_key, timeout=60, integration_name="Splunk")
            context_info = api_client.ip(ip_address)
            logger.info("Successfully retrieved the context information for ip={}".format(str(ip_address)))

            # Process the API response and send the context information of IP with extractions in the Splunk
            results = event_generator.make_valid_event('ip', context_info, True)
            yield results

        except ValueError as e:
            error_msg = str(e).split(":")
            logger.error(e)
            self.write_error(error_msg[0])

    def __init__(self):
        """Initialize custom command class."""
        super(IPContextCommand, self).__init__()


dispatch(IPContextCommand, sys.argv, sys.stdin, sys.stdout, __name__)
