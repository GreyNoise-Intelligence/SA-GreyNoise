import json
import traceback
import datetime
from functools import partial

import app_greynoise_declare
import splunk.clilib.cli_common
import splunklib.client as client
import splunk.rest as rest
from splunklib.binding import HTTPError
from greynoise_exceptions import CachingException
from six.moves import range

APP_NAME = app_greynoise_declare.ta_name
EPOCH = datetime.datetime.utcfromtimestamp(0)


class Caching(object):
    """This class provides a KVStore client for caching GN API responses."""

    def __init__(self, ssnkey, logger, command):
        """
        Caching class init method.

        :param ssnkey: Splunk session key.
        :param logger: logger object from calling method.
        :param command: A string representing the calling command.
        """
        command_map = {
            "greynoise_riot": "riot",
            "enrich": "context",
            "context": "context",
            "ip": "context",
            "multi": "multi",
            "quick": "multi",
            "ip_multi": "context"
        }
        self.mgmt_port = splunk.clilib.cli_common.getMgmtUri().split(":")[-1]
        self.session_key = ssnkey
        self.collection_name = command_map[command]
        self.logger = logger
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
                raise CachingException(str(e))
        except Exception as e:
            raise CachingException(str(e))

    def _get_age(self):
        now = datetime.datetime.utcnow()
        return int((now - EPOCH).total_seconds())

    def _groom(self, data):
        """
        Method to groom data before sending it to cache.

        :param data: response object from GreyNoise API call in json format
        :returns: list of response(s) to be stored in the cache
        {
            "_key": ip_address,
            "response": response
            "age": current UTC time.
        }
        """
        if type(data) == dict:
            data = [data]
        dict_array = []
        temp_dict = {}
        try:
            for each in data:
                temp_dict["_key"] = each["ip"]
                temp_dict["response"] = each
                temp_dict["age"] = self._get_age()
                dict_array.append(temp_dict)
                temp_dict = {}
        except Exception:
            self.logger.error("An excpetion occurred while grooming data for cache {}".format(traceback.format_exc()))
        return dict_array

    def _get_kvstore_status(self):
        """Get kv store status."""
        _, content = rest.simpleRequest("/services/kvstore/status",
                                        sessionKey=self.session_key,
                                        method="GET",
                                        getargs={"output_mode": "json"},
                                        raiseAllErrors=True)
        data = json.loads(content)["entry"]
        return data[0]["content"]["current"].get("status")

    @staticmethod
    def get_cache_settings(session_key):
        """Method to get cache_enabled flag from configuration."""
        mgmt_port = splunk.clilib.cli_common.getMgmtUri().split(":")[-1]
        service = client.connect(port=mgmt_port, token=session_key, app=APP_NAME)
        cache_settings = service.get('properties/macros/greynoise_caching/definition').body.read()
        return cache_settings

    def _chunk_data(self, data, chunk_size=1000):
        """
        Method for chunking data for kvstore insertion.

        :param data: data dictionary to be chunked.
        :param chunk_size:
        :yields chunks:
        """
        for i in range(0, len(data), chunk_size):
            yield data[i:i + chunk_size]

    def kvstore_insert(self, data):
        """
        Method to cache response objects into the corresponding kvstore collection.

        :param data: GreyNoise response object in json format.
        """
        groomed_data = self._groom(data)
        chunked_data = (list(self._chunk_data(groomed_data)))
        inserted_ips = []
        for chunk in chunked_data:
            inserted_ips.extend(self.collection.data.batch_save(*chunk))
        self.logger.debug("Inserted {} ips to cache successfully.".format(len(inserted_ips)))

    def maintain_cache(self, ttl):
        """
        Method to remove responses older than the configured Time To Live from cache.

        :param ttl: Time to live.
        """
        try:
            current_epoch = self._get_age()
            expiry_time = current_epoch - (ttl * 3600)
            query = json.dumps({"age": {"$lt": expiry_time}})
            self.collection.data.delete(query=query)
        except Exception:
            self.logger.error("Failed to clear expired records from cache.\n{}".format(traceback.format_exc()))

    def query_kv_store(self, ips, fetch_ips_only=False):
        """
        Method to query responses present in the cache.

        :param ips: list of ip addresses.
        :returns: All querired response objects if present in the cache.
        """
        query_list = []
        temp = {}
        for each in ips:
            temp["_key"] = each
            query_list.append(temp)
            temp = {}
        response = []
        try:
            query = json.dumps({"$or": query_list})
            partial_call = partial(self.collection.data.query, query=query)
            if fetch_ips_only:
                res = partial_call(fields="_key")
                for each in res:
                    response.append(each['_key'])
            else:
                res = partial_call()
                for each in res:
                    response.append(each['response'])
                self.logger.debug("Fetched {} ips from cache successfully.".format(len(response)))
        except Exception:
            self.logger.error("An exception occurred while querying KVStore: {}".format(traceback.format_exc()))
        return response
