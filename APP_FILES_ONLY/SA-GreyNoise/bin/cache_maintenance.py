import sys
import traceback  # noqa # pylint: disable=unused-import

import app_greynoise_declare  # noqa # pylint: disable=unused-import
import splunk.clilib.cli_common
import splunklib.client as client
import utility
from caching import Caching
from splunklib.searchcommands import Configuration, EventingCommand, dispatch

APP_NAME = app_greynoise_declare.ta_name


@Configuration()
class CacheMaintenance(EventingCommand):
    """
    maintaincache - Transforming command.

    Command that queries the cache kvstore and removes any records
    that are older than the configured TTL.

    **Syntax**::
    `| maintaincache`
    """

    def transform(self, records):
        """Method to clear cache kvstore via rest calls."""
        try:
            logger = utility.setup_logger(
                session_key=self._metadata.searchinfo.session_key, log_context=self._metadata.searchinfo.command
            )
            logger.info("Initiating cache maintenance")
            session_key = self._metadata.searchinfo.session_key
            multi_cache_client = Caching(session_key, logger, "multi")
            context_cache_client = Caching(session_key, logger, "context")
            riot_cache_client = Caching(session_key, logger, "greynoise_riot")
            cache_clients = [multi_cache_client, context_cache_client, riot_cache_client]
            mgmt_port = splunk.clilib.cli_common.getMgmtUri().split(":")[-1]
            service = client.connect(port=mgmt_port, token=session_key, app=APP_NAME)
            ttl = abs(int(service.get("properties/macros/greynoise_ttl/definition")["body"].read()))
        except ValueError:
            logger.warn("Invalid value found for TTL. Using a default value of '24'.")
            ttl = 24
            service.post("properties/macros/greynoise_ttl", definition=str(ttl))
        except Exception:
            logger.error("An exception occurred during cache maintenance. Exiting.\n{}".format(traceback.format_exc()))
            exit(1)
        try:
            for cache_client in cache_clients:
                if cache_client is not None:
                    cache_client.maintain_cache(ttl)
                else:
                    logger.debug("Either KVStore is disabled or not ready")
            logger.debug("Cache maintenance completed successfully")
        except Exception:
            logger.error("An exception occurred during cache maintenance.\n{}".format(traceback.format_exc()))
        yield {}

    def __init__(self):
        """Initialize custom command class."""
        super(CacheMaintenance, self).__init__()


dispatch(CacheMaintenance, sys.argv, sys.stdin, sys.stdout, __name__)
