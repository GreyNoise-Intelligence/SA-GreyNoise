import gzip
import csv
import logging
import sys
import codecs

import app_greynoise_declare
from cim_actions import ModularAction
from greynoise import GreyNoise
import six

from utility import get_log_level, get_api_key

class AlertBase(ModularAction):
    """
    Base class for modular alerts
    """
    def __init__(self, settings, logger, action_name=None):
        super(AlertBase, self).__init__(settings, logger, action_name)
        # add modaction info to the events
        self.addinfo()
        # Set the log level
        level = get_log_level(self.session_key)
        self.logger.setLevel(level)
        self.ip_field = self.get_ip_field()
        self.api_client = self.get_api_client()
        self.ip_set = self.handle_results()
    
    def get_ip_field(self):
        """
        Get ip_field parameter
        """
        ip_field = self.configuration.get("ip_field").strip()
        if not ip_field:
            self._handle_alert_exit(3)
        return ip_field
    
    def get_api_client(self):
        """
        Get api client
        """
        api_key = get_api_key(self.session_key, self.logger)
        if not api_key:
            self._handle_alert_exit(1)
        return GreyNoise(api_key=api_key, timeout=120)
    
    def handle_results(self):
        """
        Handle the events and return the ip addresses
        """
        ip_set = set()

        # Read results and append the ip fields to list
        result_handle = gzip.open(self.results_file, 'rb')
        textfile = codecs.getreader("utf-8")(result_handle)
        for num, result in enumerate(csv.DictReader(textfile)):
            # set rid to row # (0->n) if unset
            result.setdefault('rid', str(num))
            self.update(result)
            self.invoke()
            if not result.get(self.ip_field):
                self.logger.error("Specified field could not be found in event or the field is empty")
                continue
            if isinstance(result[self.ip_field],six.string_types):
                ip_set.add(result[self.ip_field])
        return ip_set
    
    def _handle_alert_exit(self, err_flag):
        """
        Exit the alert action based if the appropriate
        error flag is set
        """
        if err_flag <= 0:
            return
        # prepare meta for message in the adhoc action
        self._prepare_meta_for_cam()

        if err_flag == 3:
            self.message("ip_field is a mandatory parameter, but its value is None.",
                status="failure", level=logging.ERROR)    
        elif err_flag == 1:
            self.message("API key not found. Please configure the GreyNoise App for Splunk.", 
                status="failure", level=logging.ERROR)
        else:
            self.message("Unexpected Error Occured.", 
                status="failure", level=logging.ERROR)
        sys.exit(err_flag)
    
    def _prepare_meta_for_cam(self):
        """
        Prepare meta message when throwing the error
        to reflect in the Incident Review dashn=board
        """
        result_handle = gzip.open(self.results_file, 'rb')
        textfile = codecs.getreader("utf-8")(result_handle)
        for num, result in enumerate(csv.DictReader(textfile)):
            # set rid to row # (0->n) if unset
            result.setdefault('rid', str(num))
            self.update(result)
            self.invoke()
            break
