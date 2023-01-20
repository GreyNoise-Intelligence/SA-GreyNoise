"""
utility.py .

Helper file containing useful methods
"""
import collections
import logging
import traceback

import splunk.rest
from splunk.clilib.bundle_paths import make_splunkhome_path
import app_greynoise_declare
from requests.exceptions import ConnectionError, RequestException
from solnlib import conf_manager

from greynoise import GreyNoise
from greynoise.exceptions import RateLimitError, RequestFailure

import fields
from greynoise_exceptions import APIKeyNotFoundError, CachingException
from greynoise_constants import INTEGRATION_NAME
from caching import Caching
from six.moves import range

APP_NAME = app_greynoise_declare.ta_name


def get_conf_file(
    session_key,
    file,
    app=APP_NAME,
    realm="__REST_CREDENTIAL__#{app_name}#configs/conf-app_greynoise_settings".format(app_name=APP_NAME)
):
    """
    Returns the conf object of the file.

    :param session_key:
    :param file:
    :param app:
    :param realm:
    :return: Conf File Object
    """
    cfm = conf_manager.ConfManager(session_key, app, realm=realm)
    return cfm.get_conf(file)


def get_log_level(session_key):
    """
    Returns the log level from the GreyNoise config.

    :param session_key:
    :return: level
    """
    # Get configuration file from the helper method defined in utility
    conf = get_conf_file(session_key, 'app_greynoise_settings')

    # Get logging stanza from the settings
    logging_config = conf.get("logging", {})
    logging_level = logging_config.get("loglevel", 'INFO')
    if logging_level == 'INFO':
        level = logging.INFO
    elif logging_level == 'DEBUG':
        level = logging.DEBUG
    elif logging_level == 'WARNING':
        level = logging.WARNING
    elif logging_level == 'ERROR':
        level = logging.ERROR
    elif logging_level == 'CRITICAL':
        level = logging.CRITICAL

    return level


def setup_logger(
    logger=None,
    log_format=('%(asctime)s log_level=%(levelname)s, pid=%(process)d, '
                'tid=%(threadName)s, func_name=%(funcName)s, code_line_no=%(lineno)d | '),
    logger_name="greynoise_main",
    session_key=None,
    log_context='GreyNoise App'
):
    """Get a logger object with specified log level."""
    if logger is None:
        logger = logging.getLogger(logger_name)

    # Get the logging level
    level = get_log_level(session_key)

    # Prevent the log messages from being duplicated in the python.log file
    logger.propagate = False
    logger.setLevel(level)

    log_name = logger_name + '.log'
    file_handler = logging.handlers.RotatingFileHandler(make_splunkhome_path(
        ['var', 'log', 'splunk', log_name]), maxBytes=2500000, backupCount=5)

    # Adding the source of the logs to the log format
    log_format = log_format + '[{log_context}] %(message)s'.format(log_context=log_context)
    formatter = logging.Formatter(log_format)
    file_handler.setFormatter(formatter)

    logger.handlers = []
    logger.addHandler(file_handler)

    return logger


def get_api_key(session_key, logger):
    """
    Returns the API key configured by the user from the Splunk endpoint, returns blank when no API key is found.

    :param session_key:
    :return: API Key
    """
    # Get configuration file from the helper method defined in utility
    conf = get_conf_file(session_key, 'app_greynoise_settings')

    api_key_stanza = conf.get("parameters", {})
    api_key = api_key_stanza.get("api_key", '')

    if not api_key:
        message = "API key not found. Please configure the GreyNoise App for Splunk."
        make_error_message(message, session_key, logger)
        raise APIKeyNotFoundError(message)

    return api_key


def get_proxy(session_key, logger):
    """
    Returns the proxy configured by the user from the Splunk enpoint, returns blank when no proxy is found.

    :param session_key:
    :return: proxy url
    """
    # Get configuration file from the helper method defined in utility
    conf = get_conf_file(session_key, 'app_greynoise_settings')

    param_stanza = conf.get("parameters", {})
    proxy = param_stanza.get("proxy", '')

    return proxy


def make_error_message(message, session_key, logger):
    """
    Generates Splunk Error Message.

    :param message:
    :param session_key:
    :param filename:
    :return: error message
    """
    try:
        splunk.rest.simpleRequest(
            '/services/messages/new',
            postargs={'name': APP_NAME, 'value': '%s' % (message),
                      'severity': 'error'}, method='POST', sessionKey=session_key
        )
    except Exception:
        logger.error("Error occurred while generating error message for Splunk, Error: {}".format(
            str(traceback.format_exc())))


def get_dict(method):
    """Returns dict having all fields as key that may take place while calling method with None as default value."""
    dict_hash = {
        'ip': fields.IP_FIELDS,
        'quick': fields.QUICK_FIELDS,
        'query': fields.QUERY_FIELDS,
        'multi': fields.MULTI_FIELDS,
        'filter': fields.FILTER_FIELDS,
        'enrich': fields.ENRICH_FIELDS,
        'riot': fields.RIOT_FIELDS,
        'greynoise_riot': fields.GREYNOISE_RIOT_FIELDS
    }
    return dict_hash.get(method, fields.DEFAULT_FIELDS)


def nested_dict_iter(nested, prefix=''):
    """
    This is a dict inside a list so we assume something like.

        [{port : <port_1>, proto : <proto_1}, {port : <port_2>, proto : <proto_2}]
    We want something like this for Splunk:
        [{port : [<port_1>, <port_2>]},{proto : [<proto_1>, <proto_2>]}]
    :param nested:
    :return: dict
    """
    parsed_dict = {}
    api_response = dict(nested)

    def nester_method(api_response, prefix):
        for key, value in list(api_response.items()):
            if isinstance(value, collections.Mapping):  # it's a Dictionary
                # This will update the contents of the value dictionary into parsed_dict itself
                nester_method(value, prefix)
            if isinstance(value, list):  # it's a list
                _list = value
                for item in _list:
                    if isinstance(item, collections.Mapping):  # it's a dict inside a list
                        dict_length = int(len(list(item.keys())))
                        for n in range(0, dict_length):
                            current_key = list(item.keys())[n]
                            if current_key in parsed_dict:
                                parsed_dict[prefix + current_key].append(list(item.values())[n])
                            else:
                                parsed_dict[prefix + current_key] = [list(item.values())[n]]
                    else:
                        parsed_dict[prefix + key] = value
            else:
                parsed_dict[prefix + key] = value
        return parsed_dict

    return nester_method(api_response, prefix)


def validate_api_key(api_key, logger=None, proxy=None):
    """
    Validate the API key using the actual lightweight call to the GreyNoise API.

    Returns false only when 401 code is thrown, indicating the unauthorised access.
    :param api_key:
    :param logger:
    """
    if logger:
        logger.debug("Validating the api key...")

    try:
        if 'http' in proxy:
            api_client = GreyNoise(api_key=api_key, timeout=120, integration_name=INTEGRATION_NAME, proxy=proxy)
        else:
            api_client = GreyNoise(api_key=api_key, timeout=120, integration_name=INTEGRATION_NAME)
        api_client.test_connection()
        return (True, 'API key is valid')

    except RateLimitError:
        msg = "RateLimitError occurred, please contact the Administrator"
        return (False, 'API key not validated, Error: {}'.format(msg))
    except RequestFailure as e:
        response_code, response_message = e.args
        if response_code == 401:
            return (False, 'Unauthorized. Please check your API key.')
        else:
            # Need to handle this, as splunklib is unable to handle the exception with
            # (400, {'error': 'error_reason'}) format
            msg = ("The API call to the GreyNoise API has failed "
                   "with status_code: {} and error: {}").format(
                response_code, response_message['error'] if isinstance(response_message, dict)
                else response_message)
            return (False, 'API key not validated, Error: {}'.format(msg))
    except ConnectionError:
        msg = "ConnectionError occurred, please check your connection and try again."
        return (False, 'API key not validated, Error: {}'.format(msg))
    except RequestException:
        msg = "An ambiguous exception occurred, please try again."
        return (False, 'API key not validated, Error: {}'.format(msg))
    except Exception as e:
        return (False, 'API key not validated, Error: {}'.format(str(e)))


def chunkgen(iterable, chunk_size=1000):
    """
    Method to split an iterable into n-sized chunks.

    :return: chunk generator
    """
    iterable = iter(iterable)
    while True:
        result = []
        for i in range(chunk_size):
            try:
                a = next(iterable)
            except StopIteration:
                break
            else:
                result.append(a)
        if result:
            yield result
        else:
            break


def send_data_to_cache(cache, data, logger):
    """
    Utility method to send data from GreyNoise API to cache.

    :param cache: object of class Caching.
    :param data: dictionary of responses.
    :param logger: logger object.
    :return: result.
    """
    try:
        res = cache.kvstore_insert(data)
        return res
    except Exception:
        logger.error("An exception occurred while inserting data to cache {}".format(traceback.format_exc()))
        return None


def get_caching(session_key, method, logger):
    """
    Method to check cache is enabled or not and return cache object.

    :param session_key: Splunk session key.
    :param method: GreyNoise method name.
    :param logger: logger object from calling method.

    :returns: cache_enabled flag,cache object.
    """
    if method == 'filter':
        cache_enabled = 0
        cache = None
    else:
        cache_enabled = Caching.get_cache_settings(session_key)
        try:
            if int(cache_enabled) == 1:
                cache = Caching(session_key, logger, method)
            else:
                cache = None
        except CachingException as e:
            logger.debug("An exception occurred while fetching/ looking up/ creating KVStore"
                         " or while trying to create service object : {}".format(e))
            cache = None
            cache_enabled = 0
    return cache_enabled, cache


def get_response_for_generating(session_key, api_client, ip, method, logger):
    """
    Method to fetch response from Cache or from GreyNoise API.

    :param session_key:
    :param api_client:
    :param ip:
    :param method:
    :param logger:
    :return: resposne
    """
    cache_enabled, cache = get_caching(session_key, method, logger)
    if method == 'ip':
        fetch_method = api_client.ip
    else:
        fetch_method = api_client.riot
    if int(cache_enabled) == 1 and cache is not None:
        response = cache.query_kv_store([ip])
        if response is None:
            logger.debug("KVStore is not ready. Skipping caching mechanism.")
            response = [fetch_method(ip)]
        elif not response:
            response = [fetch_method(ip)]
            send_data_to_cache(cache, response, logger)
    else:
        response = [fetch_method(ip)]
    return response[0]


def get_ips_not_in_cache(cache, ips, logger):
    """
    Method to fetch ips from cache and return the ips which are not present.

    :param cache: Cache client object.
    :param ips: List of ips to fetch response from cache.
    :return: list of response(s), ips not in cache.
    """
    try:
        ips_not_in_cache = []
        for ipz in list(chunkgen(ips)):
            cached = cache.query_kv_store(ipz, fetch_ips_only=True)
            ips_from_cache = []
            if cached is not None and len(cached) >= 1:
                ips_from_cache.extend(cached)
            ips_not_in_cache.extend(list(set(ipz) - set(ips_from_cache)))
        return ips_not_in_cache, ips_from_cache
    except Exception:
        logger.debug("Couldn't fetch ips from cache.\n{}".format(traceback.format_exc()))
        return [], []


def fetch_response_from_api(fetch_method, cache, params, logger):
    """
    Method to fetch response from greynoise api and send responses to cache.

    :param fetch_method: fetch method corresponding api endpoint
    :param cache: cache object
    :param params: ip(s) for which response is to be fetched
    :param logger: logger object
    :return: response from api
    """
    response = fetch_method(params)
    send_data_to_cache(cache, response, logger)
    return response
