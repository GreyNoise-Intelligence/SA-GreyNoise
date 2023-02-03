"""
greynoise_quick_check.py .

Python script to gather intention of IP address via GreyNoise quick check endpoint.

"""
from __future__ import print_function
import json
import logging
import logging.handlers
import sys

from cim_actions import ModularAction
import app_greynoise_declare  # noqa # pylint: disable=unused-import

from alert_utils import AlertBase


class GreyNoiseQuickCheck(AlertBase):
    """This alert checks noise status of an IP via the GreyNoise API."""

    def __init__(self, settings, logger, action_name=None):
        """Initialize ModAction Class."""
        super(GreyNoiseQuickCheck, self).__init__(settings, logger, action_name)

    def fetch_noise(self):
        """Fetch the noise information from GryNoise and write the events to Splunk."""
        bulk_response = self.api_client.quick(list(self.ip_set), True)

        flag = False
        for result_dict in bulk_response:
            self.addevent(raw=json.dumps(result_dict), sourcetype="greynoise")
            flag = True
        self.writeevents(index="main", source="greynoise_quick")
        if flag:
            self.message("The events are successfully written to Splunk", status='success')
        else:
            self.message("No events were returned", status='failure')


def run():
    """Execute the block."""
    try:
        if len(sys.argv) > 1 and sys.argv[1] != "--execute":
            print(sys.stderr, "FATAL Unsupported execution mode (expected --execute flag)")
            sys.exit(1)

        logger = ModularAction.setup_logger("greynoise_quick_modworkflow")

        # Initialize the alert action class
        alert_base = GreyNoiseQuickCheck(sys.stdin.read(), logger, "greynoise_quick_check")

        # fetch noise information
        alert_base.fetch_noise()

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
