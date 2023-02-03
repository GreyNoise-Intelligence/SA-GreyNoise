"""This file helps custom commands generate events by passing simple API responses to it."""
from app_greynoise_declare import ta_name as APP_NAME, ta_lib_name as APP_LIB_NAME  # noqa # pylint: disable=unused-import
from functools import partial
from six.moves import zip
import threading  # noqa # pylint: disable=unused-import
import time
import traceback

from concurrent.futures import ThreadPoolExecutor

import six

from requests.exceptions import ConnectionError, RequestException
from greynoise.exceptions import RateLimitError, RequestFailure
from greynoise.util import validate_ip

from utility import get_dict, nested_dict_iter, get_ips_not_in_cache, fetch_response_from_api, get_caching

GENERATING_COMMAND_METHODS = ['ip', 'quick', 'query', 'stats', 'riot']


def exception_handler(method):
    """Decorator method for handling exceptions in Greynoise API calls."""

    def wrapper(*args, **kwargs):
        try:
            response = method(*args, **kwargs)
            return response
        except ValueError as e:
            kwargs['logger'].debug(
                "Either the event doesn't have ip_field or value of IP address present in event is "
                "either invalid or non-routable.")
            msg = str(e).split(":")
            return {
                'message': 'error',
                'response': msg[0]
            }
        except RateLimitError as e:
            kwargs['logger'].error("Rate limit error occurred. Exception: {}".format(str(e)))
            return {
                'message': 'error',
                'response': 'Rate-limit error occurred while retrieving information from GreyNoise API'
            }
        except RequestFailure as e:
            response_code, response_message = e.args
            # Need to handle this, as splunklib is unable to handle the exception with
            # (400, {'error': 'error_reason'}) format
            msg = ("The API call to the GreyNoise platform have been failed "
                   "with status_code: {} and error: {}").format(
                response_code, response_message['error'] if isinstance(response_message, dict)
                else response_message)
            kwargs['logger'].error("{}".format(str(msg)))
            return {
                'message': 'error',
                'response': 'Request failure occurred while retrieving information from GreyNoise API'
            }
        except ConnectionError as e:
            kwargs['logger'].error(
                "Error while connecting to the Server. Please check your connection and try again. Exception: {}"
                            .format(str(e)))
            return {
                'message': 'error',
                'response': 'Connection error occurred while retrieving information from GreyNoise API'
            }
        except RequestException as e:
            kwargs['logger'].error(
                "There was an ambiguous exception that occurred while handling your Request. Please try again. "
                "Exception: {}".format(str(e)))
            return {
                'message': 'error',
                'response': 'Request exception occurred while retrieving information from GreyNoise API'
            }
        except Exception:
            kwargs['logger'].error("Exception: {} ".format(str(traceback.format_exc())))
            return {
                'message': 'error',
                'response': 'Exception occurred while retrieving information from GreyNoise API'
            }

    return wrapper


@exception_handler
def pull_data_from_api_other(fetch_method, cache_enabled, cache, ip, logger, params, api_sleep_timer=3):
    """
    Pull the data from the GreyNoise SDK and return it.

    :param fetch_method: API method to be called with the given params
    :param logger: logger instance
    :param params: parameters that needs to be passed with the GreyNoise SDK call
    :param api_sleep_timer: Wait time in seconds before actual API call to avoid ConnectionError with GreyNoise server
    :return: dict having `message` denoting the API response status,
    `response` denoting  the API response or exception in case.
    """
    time.sleep(api_sleep_timer)
    if int(cache_enabled) == 1 and cache is not None:
        if ip in params:
            response = fetch_response_from_api(fetch_method, cache, ip, logger)
        else:
            response = cache.query_kv_store([ip]) if ip != '' else None
            if response is None or response == []:
                # Handles the scenario where cache is cleared or disabled during the code execution
                response = fetch_method(ip)
    else:
        response = fetch_method(ip)

    return {
        'message': 'ok',
        'response': response
    }


@exception_handler
def pull_data_from_api_multi(fetch_method, cache_enabled, cache, params, logger, api_sleep_timer=3):
    """
    Pull the data from the GreyNoise SDK and return it.

    :param fetch_method: API method to be called with the given params
    :param logger: logger instance
    :param params: parameters that needs to be passed with the GreyNoise SDK call
    :param api_sleep_timer: Wait time in seconds before actual API call to avoid ConnectionError with GreyNoise server
    :return: dict having `message` denoting the API response status,
    `response` denoting  the API response or exception in case.
    """
    # Putting the sleep time before the request to avoid connection errors from the GreyNoise Server
    time.sleep(api_sleep_timer)
    if int(cache_enabled) == 1 and cache is not None:
        # CACHING START
        try:
            cached = []
            if len(params) >= 1:
                cached = cache.query_kv_store(params)
            ips_from_cache = []
            if cached is None:
                logger.debug("Either KVStore is not ready or cache is empty. Skipping caching mechanism.")
                response = fetch_method(params)
            else:
                for each in cached:
                    ips_from_cache.append(each['ip'])
                final_ips = [each for each in params if each not in ips_from_cache]
                response = []
                # When the cache does not have response for every ip address
                if len(params) > len(ips_from_cache):
                    response = fetch_response_from_api(fetch_method, cache, final_ips, logger)
                response.extend(cached)
        except Exception:
            logger.error("An exception occurred while caching: {}".format(traceback.format_exc()))
            response = fetch_method(params)
        # CACHING END
    else:
        response = fetch_method(params)
    return {
        'message': 'ok',
        'response': response
    }


def get_all_events(session_key, api_client, method, ip_field, chunk_dict, logger, threads=3):
    """
    Driver method for the transforming commands that use the threading mechanism to retrieve data from GreyNoise SDK.

    :param api_client: API client instance
    :param method: method from which threading driver is invoked
    :param ip_field: Field representing the IP address
    :param chunk_dict: dict used to manage the records in the chunks
    :param logger: logger instance
    :param threads: number of threads to use
    :return: dict
    """
    cache_enabled, cache = get_caching(session_key, method, logger)

    if method in ['ip', 'enrich']:
        fetch_method = api_client.ip
    elif method == 'greynoise_riot':
        fetch_method = api_client.riot
    else:
        # For 'multi' and 'filter' commands
        fetch_method = api_client.quick

    logger.info("Fetching noise/RIOT status for {} chunk(s) with {} thread(s)".format(len(chunk_dict), threads))

    with ThreadPoolExecutor(max_workers=threads) as executor:
        # Doing this to pass the multiple arguments to method used in map method
        if method == 'enrich' or method == 'greynoise_riot':
            ips = []
            ips_not_in_cache = []
            if int(cache_enabled) == 1 and cache is not None:
                for ip_list in list(chunk_dict.values()):
                    try:
                        ips.append(ip_list[1][0])
                    except IndexError:
                        # That means the particular record does not have any IP address or has blank IP address
                        # It will not instantiate the unnecessary API call as this will not match with the regex itself.
                        ips.append('')
                ips_not_in_cache, ips_in_cache = get_ips_not_in_cache(cache, ips, logger)
            else:
                for ip_list in list(chunk_dict.values()):
                    try:
                        ips_not_in_cache.append(ip_list[1][0])
                    except IndexError:
                        # That means the particular record does not have any IP address or has blank IP address
                        # It will not instantiate the unnecessary API call as this will not match with the regex itself.
                        ips_not_in_cache.append('')
                ips = ips_not_in_cache

            # Setting the API sleep timer to 0 as context endpoint does not return Connection Errors after some requests
            pull_data = partial(pull_data_from_api_other, fetch_method, cache_enabled, cache,
                                logger=logger, params=ips_not_in_cache, api_sleep_timer=0)
            results = executor.map(pull_data, ips)
        else:
            pull_data = partial(pull_data_from_api_multi, fetch_method, cache_enabled, cache, logger=logger)
            # Default API sleep timer will be of 3 seconds for each request here
            results = executor.map(pull_data, [ip_list[1] for ip_list in list(chunk_dict.values())])

        logger.debug("Method used by the threader: {}".format(method))

        # Implementing the filter mechanism in the common code may increase time
        # and cognitive complexity that is not required for other transforming commands
        # Separating the logic for the filter method
        if method == 'filter':
            for index, result in zip(list(chunk_dict.keys()), results):
                logger.debug("Successfully retrieved response for chunk {}".format(index + 1))
                yield index, result
        else:
            for index, result in zip(list(chunk_dict.keys()), results):
                logger.debug("Successfully retrieved response for chunk {}".format(index + 1))
                for event in event_processor(chunk_dict[index], result, method, ip_field, logger):
                    yield event

                # Deleting the chunk records which have been already sent to Splunk
                del chunk_dict[index]


def method_response_mapper(method, result, logger):
    """
    Update the API response to the proper form to be consumable by the event_processor method.

    :param method: method used for the API invocation
    :param result: Response returned from the pull_data_from_api method
    :return: tuple with the flag to generate missing events and the updated result
    """
    generate_missing_events = False

    if method in ['enrich', 'greynoise_riot']:
        # Response from the ip and riot method used for enrich and riot will have single dict in response
        # but the event_processor will expect a list of dicts
        # Therefore masking the response to the list if the API response is proper and intact
        if result['message'] == 'ok':
            result['response'] = [
                result['response']
            ]
    elif method == 'multi':
        # quick method from GreyNoise SDK will not return the response for invalid IP
        # This flag is to indicate the event generation for missing IPs
        generate_missing_events = True
    else:
        logger.warn("Unexpected method type encountered, method name: {}".format(str(method)))
        raise Exception(
            "Unexpected method type encountered while processing the API response, method name: {}".format(str(method)))

    return (generate_missing_events, result)


def event_processor(records_dict, result, method, ip_field, logger):
    """
    Process on each chunk, format response retrieved from API and Send the results of transforming command to Splunk.

    :param records_dict: Tuple having all the records of the chunk and all the IP addresses present in the ip_field
    :param method: method used for the API invocation
    :param ip_field: name of the field representing the IP address in Splunk events
    :param logger: logger instance
    :return: dict denoting the event to send to Splunk
    """
    generate_missing_events, result = method_response_mapper(method, result, logger)

    # Loading the response to avoid loading it each time
    # This will either have API response for the chunk or
    # the exception message denoting exception occurred while fetching the data
    if result['response']:
        if type(result['response'][0]) == list:
            api_results = []
            for each in result['response'][0]:
                api_results.append(each)
        else:
            api_results = result['response']
    else:
        api_results = result['response']
    error_flag = True
    # Before yielding events, make the ip lookup dict which will have the following format:
    # {<ip-address>: <API response for that IP address>}
    ip_lookup = {}
    if result['message'] == 'ok':
        error_flag = False
        for event in api_results:
            ip_lookup[event['ip']] = event

    # This will be called per chunk to yield the events as per the objective of transforming command
    for record in records_dict[0]:

        if error_flag:
            # Exception has occurred while fetching the data
            if ip_field in record and record[ip_field]:
                event = {
                    'ip': record[ip_field],
                    'error': api_results
                }
                yield make_invalid_event(method, event, True, record)
            else:
                # Either the record is not having IP field or the value of the IP field is ''
                # send the record as it is as it doesn't have any IP address, after appending all fields
                yield make_invalid_event(method, {}, True, record)
        else:
            # Successful execution of the API call
            if ip_field in record and record[ip_field]:

                # Check if the IP field is not an iterable to avoid any error while referencing ip in ip_lookup
                if isinstance(record[ip_field], six.string_types) and record[ip_field] in ip_lookup:

                    # Deleting the raw_data from the response when the request method is enrich
                    if method == 'enrich' and 'raw_data' in ip_lookup[record[ip_field]]:
                        del ip_lookup[record[ip_field]]['raw_data']

                    yield make_valid_event(method, ip_lookup[record[ip_field]], True, record)
                else:
                    # Meaning ip is either invalid or not returned by the API,
                    # happens when quick method is used while retrieving data
                    if generate_missing_events:
                        try:
                            validate_ip(record[ip_field], strict=True)
                        except ValueError as e:
                            error_msg = str(e).split(":")
                            event = {
                                'ip': record[ip_field],
                                'error': error_msg[0]
                            }
                            yield make_invalid_event(method, event, True, record)
            else:
                # Either the record is not having IP field or the value of the IP field is ''
                # send the record as it is as it doesn't have any IP address, after appending all fields
                yield make_invalid_event(method, {}, True, record)


def make_valid_event(method, data, first_event=False, record=None):
    """
    Returns the event in the JSON format from the data passed to the method.

    :param method: method of the GreyNoise API used
    :param data: response retrieved from the response of the GreyNoise API
    :param first_event: flag specifying whether the expected event is first or not
    :param record: greynoise API information will be updated with the fields of event and will be sent to Splunk
    """
    if record is None:
        record = {}
    # Add these fields only when command is generating command
    if method in GENERATING_COMMAND_METHODS:

        if first_event:
            results = dict(get_dict(method))
            results.update(nested_dict_iter(data))
        else:
            # Get the fields from the response json and put them into json
            # so that Splunk can get the values of the fields from it
            results = nested_dict_iter(data)

        results['source'] = 'greynoise'
        results['sourcetype'] = 'greynoise'
        results['_time'] = time.time()
        results['_raw'] = {
            'results': data
        }

        return results
    else:
        # Irrespective of first_record_flag, we will always retrieve the default dictionary for the generating commands
        results = dict(get_dict(method))
        results.update(nested_dict_iter(data, prefix='greynoise_'))

        record.update(results)

        return record


def make_invalid_event(method, data, first_event=False, record=None):
    """
    Generates the event for the invalid/empty response based on the dictionary given in the data parameter.

    :param method: method of the GreyNoise API used
    :param data: response retrieved from the response of the GreyNoise API
    :param first_event: flag specifying whether the expected event is first or not
    :param record: greynoise API information will be updated with the fields of event and will be sent to Splunk
    """
    if record is None:
        record = {}

    # Add these fields only when command is generating command
    if method in GENERATING_COMMAND_METHODS:

        if first_event:
            event = dict(get_dict(method))
        else:
            event = {}

        event.update(data)

        event['source'] = 'greynoise'
        event['sourcetype'] = 'greynoise'
        event['_time'] = time.time()
        event['_raw'] = {
            'results': data
        }

        return event
    else:
        # Irrespective of first_record_flag, we will always retrieve the default dictionary for the generating commands
        event = dict(get_dict(method))

        for field, value in list(data.items()):
            event['greynoise_' + field] = value

        record.update(event)

        return record


def batch(iterable, ip_field, events_per_chunk, logger, optimize_requests=True):
    """
    Divide all the records into chunk and return them into the dict having following format.

    {<chunk_index>: ([<event-1>, <event-2>, ... , <event-N>], [<ip-1>, <ip-2>, <ip-4>, ... , <ip-1000>])}
    :param iterable: Records sent to the command by Splunk
    :param ip_field: Field representing the IP address
    :param events_per_chunk: Size of each chunk
    :param optimize_requests: Specify whether to reduce the chunk to one when distinct IPs are below 1000,
    :return: dict
    """
    logger.debug("Fetching the events from Splunk, all at once...")
    iterable_list = list(iterable)
    del iterable
    logger.debug("Successfully retrieved all the events from the Splunk, creating chunks..")

    chunk_dict = {}
    chunk_index = 0
    records = []
    ip_set = set()

    all_unique_ips = set()

    for record in iterable_list:

        records.append(record)

        if ip_field in record and record[ip_field] and isinstance(record[ip_field], six.string_types):
            ip_set.add(record[ip_field])

        if len(ip_set) == events_per_chunk:
            chunk_dict[chunk_index] = (
                records,
                list(ip_set)
            )

            if not len(all_unique_ips) > 5001:
                all_unique_ips.update(ip_set)

            chunk_index = chunk_index + 1
            records = []
            ip_set = set()

    # When the remaining records are not enough to have length save as events_per_chunk
    if len(records) > 0:
        chunk_dict[chunk_index] = (records, list(ip_set))

        if not len(all_unique_ips) > 5000:
            all_unique_ips.update(ip_set)

    if optimize_requests and len(all_unique_ips) <= 5000:
        all_records = []
        # Return records in only one chunk if the deployment less than 1000 unique IP addresses
        for records, _ in list(chunk_dict.values()):
            for event in records:
                all_records.append(event)
        return {
            0: (
                all_records,
                list(all_unique_ips)
            )
        }

    return chunk_dict
