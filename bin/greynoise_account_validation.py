import os
import traceback  # noqa # pylint: disable=unused-import
import json
import time
import sys
import datetime

import app_greynoise_declare
from solnlib import conf_manager  # noqa # pylint: disable=unused-import
import splunk.admin as admin
import splunk.rest as rest
import splunk.clilib.cli_common
import splunklib.client as client
from splunklib.binding import HTTPError
from splunktaucclib.rest_handler.endpoint.validator import Validator
from splunktaucclib.rest_handler.endpoint import (
    validator
)

from utility import validate_api_key, get_conf_file, setup_logger, make_error_message
from saved_search_utils import is_api_configured, handle_macros, compare_parameters, DATE, TIME_MAP
from greynoise_constants import MAX_RETRIES, BACKOFF_FACTOR

APP_NAME = app_greynoise_declare.ta_name


class GetSessionKey(admin.MConfigHandler):
    """Class to get session key."""

    def __init__(self):
        """Initialize session key."""
        self.session_key = self.getSessionKey()


class EnableCachingHandler(Validator):
    """This is a handler for enable_caching checkbox on the caching page."""

    def __init__(self, *args, **kwargs):
        """Initialize the parameters."""
        super(EnableCachingHandler, self).__init__(*args, **kwargs)
        self._validator = validator
        self._args = args
        self._kwargs = kwargs
        self.path = os.path.abspath(__file__)
        self.session_key_obj = GetSessionKey()
        self.logger = setup_logger(session_key=self.session_key_obj.session_key, log_context="api_validation")

    def validate(self, value, data):
        """Method to call all enable caching helpers."""
        mgmt_port = splunk.clilib.cli_common.getMgmtUri().split(":")[-1]
        service = client.connect(port=mgmt_port, token=self.session_key_obj.session_key, app=APP_NAME)
        try:
            # Update Macro for enable caching
            service.post("properties/macros/greynoise_caching", definition=str(data['enable_caching']))
            return True
        except Exception:
            self.logger.error('Failed to update caching macro\n{} '.format(traceback.format_exc()))
            self.put_msg("Failed to toggle caching. See logs for details.")
            return False


class TtlHandler(Validator):
    """This is a handler for time to live field on the caching page."""

    def __init__(self, *args, **kwargs):
        """Initialize the parameters."""
        super(TtlHandler, self).__init__(*args, **kwargs)
        self._validator = validator
        self._args = args
        self._kwargs = kwargs
        self.path = os.path.abspath(__file__)
        self.session_key_obj = GetSessionKey()
        mgmt_port = splunk.clilib.cli_common.getMgmtUri().split(":")[-1]
        self.service = client.connect(port=mgmt_port, token=self.session_key_obj.session_key, app=APP_NAME)
        self.logger = setup_logger(session_key=self.session_key_obj.session_key, log_context="api_validation")

    def validate(self, value, data):
        """Method to call all ttl helpers."""
        try:
            # Update Macro TTL
            self.service.post("properties/macros/greynoise_ttl", definition=str(data['ttl']))
            return True
        except Exception:
            self.logger.error('Failed to update caching macro\n{} '.format(traceback.format_exc()))
            self.put_msg("Failed to save TTL for cache. See logs for details.")
            return False


class PurgeHandler(Validator):
    """This is a handler for purge_cache checkbox on the caching page."""

    def __init__(self, *args, **kwargs):
        """Initialize the parameters."""
        super(PurgeHandler, self).__init__(*args, **kwargs)
        self._validator = validator
        self._args = args
        self._kwargs = kwargs
        self.path = os.path.abspath(__file__)
        self.session_key_obj = GetSessionKey()
        self.logger = setup_logger(session_key=self.session_key_obj.session_key, log_context="api_validation")

    # Decorator
    def retry(method):
        """Retry mechanism to avoid connection errors."""

        def wrapper(self, *args, **kwargs):
            retry_count = 0
            while True:
                try:
                    response = method(self, *args, **kwargs)
                    break
                except Exception as ex:
                    if retry_count >= MAX_RETRIES:
                        raise ex

                    retry_count += 1
                    if retry_count == 1:
                        self.logger.warning('Method="{}()" Args="{}" Kwargs="{}" Error="{}"'.format(
                            method.__name__, args, kwargs, ex))

                    # Exponential backoff
                    delay = (BACKOFF_FACTOR) * (2 ** retry_count - 1)
                    time.sleep(delay)

                    self.logger.info('RetryCount={} RetryAfterSecond={}'.format(retry_count, delay))

            return response
        return wrapper

    @retry
    def cache_purge_helper(self):
        """Method to purge all caches."""
        caches = ['multi', 'context', 'riot']
        for each in caches:
            response_status, response_content = rest.simpleRequest(
                "/servicesNS/nobody/" + str(APP_NAME) + "/storage/collections/data/" + each,
                sessionKey=self.session_key_obj.session_key, method='DELETE', getargs={"output_mode": "json"},
                raiseAllErrors=True, timeout=180)

    def validate(self, value, data):
        """Method to call all purge helpers."""
        try:
            if data['purge_cache'] == '1':
                self.logger.debug("Purging cache and unchecking the Purge Cache checkbox.")
                self.cache_purge_helper()
                data['purge_cache'] = '0'
                self.logger.info("Cache purged successfully.")
            else:
                self.logger.debug("Purge Cache is Disabled")
            return True
        except Exception:
            self.logger.debug("Failed to purge cache.\n{}".format(traceback.format_exc()))
            self.put_msg("Failed to purge cache. See logs for details.")
            return False


class GreyNoiseAPIValidation(Validator):
    """Validate the api key of the GreyNoise account."""

    def __init__(self, *args, **kwargs):
        """Initialize the parameters."""
        super(GreyNoiseAPIValidation, self).__init__(*args, **kwargs)
        self._validator = validator
        self._args = args
        self._kwargs = kwargs
        self.path = os.path.abspath(__file__)
        self.session_key_obj = GetSessionKey()
        self.logger = setup_logger(session_key=self.session_key_obj.session_key, log_context="api_validation")

    def validate(self, value, data):
        """Validate the api key entered by user on the Configuration Page and enable the saved search."""
        try:
            # Get Conf file for obtaining parameters
            conf = get_conf_file(self.session_key_obj.session_key, file='app_greynoise_settings', app=APP_NAME)

            # maybe put in new field in webconf page or use .conf
            # - ENV is not passed to user runnig splunk
            # - ENV not good for cluser/distributed
            parameters = conf.get("parameters", {})
            proxy_conf = parameters.get('proxy', None)

            # favor conf file
            proxy = proxy_conf or os.environ.get('GREYNOISE_PROXY', None)

            conf.update("parameters", {'proxy': proxy})
            self.logger.info(f'proxy: {proxy}')

            # Validate API Key
            self.logger.debug("Validating API key.")
            status, msg = validate_api_key(data.get('api_key'), self.logger, proxy)
            if not status:
                raise Exception(msg)
            self.logger.info("API key validated.")

            # Retrieve job_id_overview
            parameters = conf.get("scan_deployment", {})
            job_id_overview = parameters.get("job_id_overview", None)

            # Creating client for connecting to server
            self.logger.debug("Creating Splunk Client object.")
            mgmt_port = splunk.clilib.cli_common.getMgmtUri().split(":")[-1]
            service = client.connect(port=mgmt_port, token=self.session_key_obj.session_key)

            # Retrive saved search
            overview_savedsearch = service.saved_searches["greynoise_overview"]

            # Enable and execute saved search when setting app for first time
            if not job_id_overview:
                self.logger.debug("Setting up the saved search for the first time in absence of job_id.")
                # Update the API key in the conf file so that the custom commands can execute
                conf.update("parameters", {'api_key': data.get('api_key')}, ['api_key'])

                # Retrive saved search
                overview_savedsearch_once = service.saved_searches["greynoise_overview_once"]

                # Run the saved search when the app is first set-up
                # Saved job_id_overview to indicate the search is not first time
                job = overview_savedsearch_once.dispatch()
                job_sid = job["sid"]
                conf.update("scan_deployment", {'job_id_overview': job_sid})

                # Enable the saved search to execute on cron schedule
                overview_savedsearch.enable()
                self.logger.info("Overview saved search dispatched and enabled. Setup for first time completed.")
            else:
                overview_savedsearch.enable()
                self.logger.debug("Re-enabled the Overview saved search.")
        except HTTPError:
            self.logger.error("Error while retrieving Saved Search. Please "
                              "check if the saved searches {} and {} exists.".format(
                                  "greynoise_overview_once", "greynoise_overview"))
            self.put_msg("Error while retrieving Saved Search. Kindly check greynoise_main.log for more details.")
            return False
        except Exception as e:
            try:
                msg
            except Exception:
                msg = "Unrecognized error: {}".format(str(e))
            self.logger.error(msg)
            self.put_msg(msg)
            return False
        else:
            return True


class GreyNoiseScanDeployment(Validator):
    """Class to enable the scan deployment."""

    def __init__(self, *args, **kwargs):
        """Initialize the parameters."""
        super(GreyNoiseScanDeployment, self).__init__(*args, **kwargs)
        self._validator = validator
        self._args = args
        self._kwargs = kwargs
        self.path = os.path.abspath(__file__)
        self.session_key_obj = GetSessionKey()
        self.logger = setup_logger(session_key=self.session_key_obj.session_key, log_context="scan_deployment")

    def get_kvstore_status(self):
        """Get kv store status."""
        _, content = rest.simpleRequest("/services/kvstore/status",
                                        sessionKey=self.session_key_obj.session_key,
                                        method="GET",
                                        getargs={"output_mode": "json"},
                                        raiseAllErrors=True)
        data = json.loads(content)["entry"]
        return data[0]["content"]["current"].get("status")

    def validate(self, value, data):
        """Method to enable/disable the scan deployment saved search based on the input in Scan Deployment Page."""
        # Retrieve App Name
        try:
            # Get Conf object of apps settings
            conf = get_conf_file(self.session_key_obj.session_key, file='app_greynoise_settings')

            try:
                if not is_api_configured(conf):
                    msg = "Configure the API key to use this feature"
                    raise Exception(msg)
            except HTTPError as e:
                self.logger.error(str(e))
                self.put_msg(str(e))
                return False

            parameters = conf.get("scan_deployment", {})
            enable_ss = data.get('enable_ss', 0)
            force_enable_ss = data.get('force_enable_ss', 0)
            job_id_scan_deployment = parameters.get("job_id_scan_deployment", None)

            # Creating client for connecting server
            self.logger.debug("Creating Splunk Client object.")
            mgmt_port = splunk.clilib.cli_common.getMgmtUri().split(":")[-1]
            service = client.connect(port=mgmt_port, token=self.session_key_obj.session_key, app=APP_NAME)

            if bool(int(enable_ss)):
                try:
                    self.logger.info("Retrieving the KV store status.")
                    status = self.get_kvstore_status()
                    if status != "ready":
                        message = "KV store is not in ready state. Make sure it is enabled."
                        make_error_message(message, self.session_key_obj.session_key, self.logger)
                except Exception:
                    self.logger.error("Could not retrieve the status of KV store.")
                # Enable the scheduled saved search
                self.logger.debug("Initiating user action to enable the saved search.")
                scan_deployment_savedsearch = service.saved_searches["greynoise_scan_deployment"]

                if job_id_scan_deployment:
                    self.logger.debug("Job ID present. Handling macros.")
                    # Update macros
                    try:
                        handle_macros(data, service)
                    except ValueError:
                        msg = ("The field names in \"Other fields\" parameter "
                               "only supports underscore, digits, alphabets, and hyphen")
                        raise Exception(msg)

                    self.logger.info("Enabling saved search.")
                    # Enable the scheduled saved search
                    scan_deployment_savedsearch.enable()

                    dispatch_again = compare_parameters(data, conf.get("scan_deployment", {}))

                    if bool(int(force_enable_ss)) or dispatch_again:
                        self.logger.debug("Dispatching a new saved search.")
                        try:
                            job_details = service.job(job_id_scan_deployment)
                            job_details.delete()
                        except Exception:
                            pass
                        # Modify properties and run the saved search in case of job_id_scan_deployment
                        # is not present in conf file.
                        start_time = data.get("scan_start_time", "NOW")
                        if start_time != "NOW":
                            scan_deployment_savedsearch_once = service.saved_searches["greynoise_scan_deployment_once"]
                            kwargs = {
                                "dispatch.earliest_time": TIME_MAP[DATE[start_time]],
                                "dispatch.latest_time": "now"
                            }
                            scan_deployment_savedsearch_once.update(**kwargs).refresh()
                            job = scan_deployment_savedsearch_once.dispatch()
                            job_sid = job["sid"]
                            conf.update("scan_deployment", {'job_id_scan_deployment': job_sid})
                            self.logger.info("Saved search dispatched successfully.")
                            return True
                    else:
                        try:
                            self.logger.debug("Dispatching a new search if the current one is expired.")
                            job_details = service.job(job_id_scan_deployment)
                            status = job_details.state().content['dispatchState']

                            if status == 'PAUSED':
                                # unpause the search in case of savedsearch job is paused by someone
                                job_details.unpause()
                                return True
                            if status in ['QUEUED', 'PARSING', 'RUNNING']:
                                return True
                        except Exception:
                            pass

                        # Modify properties and run the saved search in case of job_id_scan_deployment
                        # is not present in conf file.
                        start_time = data.get("scan_start_time", "NOW")
                        if start_time != "NOW":
                            scan_deployment_savedsearch_once = service.saved_searches["greynoise_scan_deployment_once"]
                            kwargs = {
                                "dispatch.earliest_time": TIME_MAP[DATE[start_time]],
                                "dispatch.latest_time": "now"
                            }
                            scan_deployment_savedsearch_once.update(**kwargs).refresh()
                            job = scan_deployment_savedsearch_once.dispatch()
                            job_sid = job["sid"]
                            conf.update("scan_deployment", {'job_id_scan_deployment': job_sid})
                            self.logger.info("Saved search dispatched successfully.")
                            return True
                else:
                    self.logger.debug("Job ID not present. Handling macros.")
                    # Update macros
                    try:
                        handle_macros(data, service)
                    except ValueError:
                        msg = ("The field names in \"Other fields\" parameter "
                               "only supports underscore, digits, alphabets, and hyphen")
                        raise Exception(msg)

                    # Enable the scheduled saved search
                    scan_deployment_savedsearch.enable()

                    # Modify properties and run the saved search in case of job_id_scan_deployment
                    # is not present in conf file.
                    start_time = data.get("scan_start_time", "NOW")
                    if start_time != "NOW":
                        scan_deployment_savedsearch_once = service.saved_searches["greynoise_scan_deployment_once"]
                        kwargs = {
                            "dispatch.earliest_time": TIME_MAP[DATE[start_time]],
                            "dispatch.latest_time": "now"
                        }
                        scan_deployment_savedsearch_once.update(**kwargs).refresh()
                        job = scan_deployment_savedsearch_once.dispatch()
                        job_sid = job["sid"]
                        self.logger.info("Dispatched the search successfully.")
                        conf.update("scan_deployment", {'job_id_scan_deployment': job_sid})
            else:
                self.logger.debug("Initiating user action to disable the saved search.")
                # Retrive and disable scheduled saved search
                scan_deployment_savedsearch = service.saved_searches["greynoise_scan_deployment"]
                scan_deployment_savedsearch.disable()

                if job_id_scan_deployment:
                    try:
                        job_details = service.job(job_id_scan_deployment)
                        status = job_details.state().content['dispatchState']
                        if status in ['QUEUED', 'PARSING', 'RUNNING', 'FINALIZING', 'PAUSED']:
                            job_details.cancel()
                    except Exception:
                        pass
                self.logger.info("Saved search disabled successfully.")
        except HTTPError:
            self.logger.error("Error while retrieving Saved Search. Please "
                              "check if the saved searches {} and {} exists.".format(
                                  "greynoise_scan_deployment_once", "greynoise_scan_deployment"))
            self.put_msg("Error while retrieving Saved Search. Kindly check greynoise_main.log for more details.")
            return False
        except Exception as e:
            try:
                msg
            except Exception:
                msg = "Unrecognized error: {}".format(str(e))
            self.logger.error(msg)
            self.put_msg(msg)
            return False
        else:
            return True


class GreyNoiseFeedConfiguration(Validator):
    """Class to enable the feed configuration."""

    def __init__(self, *args, **kwargs):
        """Initialize the parameters."""
        super(GreyNoiseFeedConfiguration, self).__init__(*args, **kwargs)
        self._validator = validator
        self._args = args
        self._kwargs = kwargs
        self.path = os.path.abspath(__file__)
        self.session_key_obj = GetSessionKey()
        self.mgmt_port = splunk.clilib.cli_common.getMgmtUri().split(":")[-1]
        self.session_key = self.session_key_obj.session_key
        self.collection_name = "gn_feed_collection"
        self.logger = setup_logger(session_key=self.session_key_obj.session_key, log_context="feed_configuration")

        try:
            service = client.connect(
                port=self.mgmt_port, token=self.session_key, app=APP_NAME)
            if self.collection_name in service.kvstore:
                self.collection = service.kvstore[self.collection_name]
                self.collection.data.query_by_id("item1")
            else:
                self.logger.error(
                    "Collection {} does not exist. Please define one in collections.conf.".format(self.collection_name))
                raise CachingException("Collection {} does not exist.".format(self.collection_name))
        except HTTPError as e:
            if e.status == 404:
                # self.collection.data.query_by_id("item1") purpose is to raise an error when kvstore is disabled.
                # So, handling 404 error caused by it when kvstore is enabled.
                pass
            else:
                raise e
        except Exception as e:
            raise e

    def get_kvstore_status(self):
        """Get kv store status."""
        _, content = rest.simpleRequest("/services/kvstore/status",
                                        sessionKey=self.session_key_obj.session_key,
                                        method="GET",
                                        getargs={"output_mode": "json"},
                                        raiseAllErrors=True)
        data = json.loads(content)["entry"]
        return data[0]["content"]["current"].get("status")

    def validate(self, value, data):
        """Method to enable/disable the feed saved search based on the input in Feed Configuration Page."""
        # Retrieve App Name
        try:
            # Get Conf object of apps settings
            conf = get_conf_file(self.session_key_obj.session_key, file='app_greynoise_settings')

            try:
                if not is_api_configured(conf):
                    msg = "Configure the API key to use this feature"
                    raise Exception(msg)
            except HTTPError as e:
                self.logger.error(str(e))
                self.put_msg(str(e))
                return False

            parameters = conf.get("feed_configuration", {})
            enable_feed_import = data.get('enable_feed_import', 0)
            force_enable_ss = data.get('force_enable_ss', 0)
            job_id_feed = parameters.get("job_id_feed", None)
            feed_selection = data.get("feed_selection", "BENIGN")
            if feed_selection == "ALL":
                query = "last_seen:1d"
            elif feed_selection == "MALICIOUS":
                query = "last_seen:1d classification:malicious"
            elif feed_selection == "MALICIOUS_BENIGN":
                query = "last_seen:1d (classification:benign OR classification:malicious)"
            else:
                query = "last_seen:1d classification:benign"

            # Creating client for connecting server
            self.logger.debug("Creating Splunk Client object.")
            mgmt_port = splunk.clilib.cli_common.getMgmtUri().split(":")[-1]
            service = client.connect(port=mgmt_port, token=self.session_key_obj.session_key, app=APP_NAME)

            if bool(int(enable_feed_import)):
                try:
                    self.logger.info("Retrieving the KV store status.")
                    status = self.get_kvstore_status()
                    if status != "ready":
                        message = "KV store is not in ready state. Make sure it is enabled."
                        make_error_message(message, self.session_key_obj.session_key, self.logger)
                except Exception:
                    self.logger.error("Could not retrieve the status of KV store.")

                self.logger.info("Saving query to KVStore: {}".format(query))
                timestamp = int(datetime.datetime.now().timestamp() * 1000)
                self.collection.data.insert({'created': timestamp, 'query': query})

                # Enable the scheduled saved search
                self.logger.debug("Initiating user action to enable the saved search: Feed Configuration.")
                feed_savedsearch = service.saved_searches["greynoise_feed"]

                if job_id_feed:
                    self.logger.debug("Job ID present.")

                    self.logger.info("Enabling saved search.")
                    # Enable the scheduled saved search
                    feed_savedsearch.enable()

                    dispatch_again = compare_parameters(data, conf.get("feed_configuration", {}))

                    if bool(int(force_enable_ss)) or dispatch_again:
                        self.logger.debug("Dispatching a new saved search.")
                        try:
                            job_details = service.job(job_id_feed)
                            job_details.delete()
                        except Exception:
                            pass
                        # Modify properties and run the saved search in case of job_id_scan_deployment
                        # is not present in conf file.
                        feed_once_savedsearch = service.saved_searches["greynoise_feed_once"]
                        job = feed_once_savedsearch.dispatch()
                        job_sid = job["sid"]
                        conf.update("feed_configuration", {'job_id_feed': job_sid})
                        self.logger.info("Saved search for FEED dispatched successfully.")
                        return True
                    else:
                        try:
                            self.logger.debug("Dispatching a new search if the current one is expired.")
                            job_details = service.job(job_id_feed)
                            status = job_details.state().content['dispatchState']

                            if status == 'PAUSED':
                                # unpause the search in case of savedsearch job is paused by someone
                                job_details.unpause()
                                return True
                            if status in ['QUEUED', 'PARSING', 'RUNNING']:
                                return True
                        except Exception:
                            pass

                        # Modify properties and run the saved search in case of job_id_scan_deployment
                        # is not present in conf file.
                        feed_savedsearch = service.saved_searches["greynoise_feed"]
                        job = feed_savedsearch.dispatch()
                        job_sid = job["sid"]
                        conf.update("feed_configuration", {'job_id_feed': job_sid})
                        self.logger.info("Saved search for FEED dispatched successfully.")
                        return True
                else:
                    self.logger.debug("Job ID not present.")

                    # Enable the scheduled saved search
                    self.logger.debug("Enabling Saved Search Feed")
                    feed_savedsearch.enable()

                    # Modify properties and run the saved search in case of job_id_scan_deployment
                    # is not present in conf file.
                    feed_savedsearch = service.saved_searches["greynoise_feed"]
                    job = feed_savedsearch.dispatch()
                    job_sid = job["sid"]
                    conf.update("feed_configuration", {'job_id_feed': job_sid})
                    self.logger.info("Saved search for FEED dispatched successfully.")
            else:
                self.logger.debug("Initiating user action to disable the saved search.")
                # Retrive and disable scheduled saved search
                feed_savedsearch = service.saved_searches["greynoise_feed"]
                feed_savedsearch.disable()

                if job_id_feed:
                    try:
                        job_details = service.job(job_id_feed)
                        status = job_details.state().content['dispatchState']
                        if status in ['QUEUED', 'PARSING', 'RUNNING', 'FINALIZING', 'PAUSED']:
                            job_details.cancel()
                    except Exception:
                        pass
                self.logger.info("Saved search FEED disabled successfully.")
        except HTTPError:
            self.logger.error("Error while retrieving Saved Search. Please "
                              "check if the saved searches {} and {} exists.".format(
                                  "greynoise_feed_once", "greynoise_feed"))
            self.put_msg("Error while retrieving Saved Search. Kindly check greynoise_main.log for more details.")
            return False
        except Exception as e:
            try:
                msg
            except Exception:
                msg = "Unrecognized error: {}".format(str(e))
            self.logger.error(msg)
            self.put_msg(msg)
            return False
        else:
            return True
