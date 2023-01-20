"""
greynoise_context_check.py .

Python script to gather intention of IP address via GreyNoise context check endpoint.

"""
from __future__ import print_function
import json
import logging
import logging.handlers
import sys

from cim_actions import ModularAction
import app_greynoise_declare # noqa # pylint: disable=unused-import

from alert_utils import AlertBase


class GreyNoiseContextCheck(AlertBase):
    """This alert gets context info of an IP via the GreyNoise API."""

    def __init__(self, settings, logger, action_name=None):
        """Initialize ModAction Class."""
        super(GreyNoiseContextCheck, self).__init__(settings, logger, action_name)

    def fetch_context(self):
        """Fetch the context information from GreyNoise and write the events to Splunk."""
        flag = False
        for ip_address in self.ip_set:
            try:
                result_dict = self.api_client.ip(ip_address)
                self.addevent(raw=json.dumps(result_dict), sourcetype="greynoise")
                flag = True
            except ValueError:
                self.logger.error("IP address: {} doesn\'t match the valid IP format".format(str(ip_address)))
        self.writeevents(index="main", source="greynoise_context")
        if flag:
            self.message("The events are successfully written to Splunk", status='success')
        else:
            self.message("No events were returned", status='failure')


def run():
    """Execute the block."""
    try:
        if len(sys.argv) < 2 or sys.argv[1] != "--execute":
            print("FATAL Unsupported execution mode (expected --execute flag)", file=sys.stderr)
            sys.exit(1)

        logger = ModularAction.setup_logger("greynoise_context_modworkflow")

        # Initialize the alert action class
        alert_base = GreyNoiseContextCheck(sys.stdin.read(), logger, "greynoise_context_check")

        # fetch context information
        alert_base.fetch_context()

    # This is standard chrome for outer exception handling
    except Exception as error:
        # adding additional logging since adhoc search invocations do not write to stderr
        try:
            alert_base.message(str(error), status='failure', level=logging.CRITICAL)
        except Exception:
            logger.critical(error)
        print("ERROR: %s" % str(error), file=sys.stderr)

        sys.exit(3)


if __name__ == "__main__":
    run()
