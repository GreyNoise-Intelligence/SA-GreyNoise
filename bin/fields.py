# Dictionary of the default fields in Splunk
DEFAULT_FIELDS = {
    '_raw': None,
    '_time': None,
    'source': None,
    'sourcetype': None
}

# Dictionary of all the fields that are available in context of IP address
# fetched using ip method of the GreyNoise Python SDK
IP_FIELDS = {
    '_raw': None,
    '_time': None,
    'source': None,
    'sourcetype': None,
    'ip': None,
    'seen': None,
    'classification': None,
    'first_seen': None,
    'last_seen': None,
    'actor': None,
    'tags': None,
    'spoofable': None,
    'cve': None,
    'vpn': None,
    'vpn_service': None,
    'metadata': None,
    'raw_data': None,
    'country': None,
    'country_code': None,
    'city': None,
    'region': None,
    'organization': None,
    'rdns': None,
    'asn': None,
    'tor': None,
    'category': None,
    'os': None,
    'port': None,
    'protocol': None,
    'web': None,
    'scan': None,
    'ja3': None,
    'hassh': None,
    'paths': None,
    'useragents': None,
    'fingerprint': None,
    'error': None
}

# Dictionary of all the fields that are available in noise status of IP address
# fetched using quick method of the GreyNoise Python SDK
QUICK_FIELDS = {
    '_raw': None,
    '_time': None,
    'source': None,
    'sourcetype': None,
    'ip': None,
    'code': None,
    'code_message': None,
    'noise': None,
    'riot': None,
    'error': None
}

# Dictionary of all the fields that are available in the events returned by query method of the GreyNoise Python SDK
QUERY_FIELDS = {
    '_raw': None,
    '_time': None,
    'source': None,
    'sourcetype': None,
    "ip": None,
    "seen": None,
    "classification": None,
    "first_seen": None,
    "last_seen": None,
    "actor": None,
    "tags": None,
    "spoofable": None,
    "cve": None,
    "vpn": None,
    "vpn_service": None,
    "metadata": None,
    "country": None,
    "country_code": None,
    "city": None,
    "region": None,
    "organization": None,
    "rdns": None,
    "asn": None,
    "tor": None,
    "category": None,
    "os": None,
    "raw_data": None,
    "port": None,
    "protocol": None,
    "web": None,
    'scan': None,
    'ja3': None,
    'hassh': None,
    "paths": None,
    "useragents": None,
    "fingerprint": None
}

MULTI_FIELDS = {
    'greynoise_ip': None,
    'greynoise_code': None,
    'greynoise_code_message': None,
    'greynoise_noise': None,
    'greynoise_riot': None,
    'greynoise_error': None
}

FILTER_FIELDS = {
    'greynoise_ip': None,
    'greynoise_code': None,
    'greynoise_code_message': None,
    'greynoise_noise': None,
    'greynoise_riot': None,
    'greynoise_error': None
}

ENRICH_FIELDS = {
    'greynoise_ip': None,
    'greynoise_seen': None,
    'greynoise_classification': None,
    'greynoise_first_seen': None,
    'greynoise_last_seen': None,
    'greynoise_actor': None,
    'greynoise_tags': None,
    'greynoise_spoofable': None,
    'greynoise_cve': None,
    'greynoise_vpn': None,
    'greynoise_vpn_service': None,
    'greynoise_metadata': None,
    'greynoise_country': None,
    'greynoise_country_code': None,
    'greynoise_city': None,
    'greynoise_region': None,
    'greynoise_organization': None,
    'greynoise_rdns': None,
    'greynoise_asn': None,
    'greynoise_tor': None,
    'greynoise_category': None,
    'greynoise_os': None,
    'greynoise_error': None
}

# Dictionary of all the fields that are available in riot information of IP address
# fetched using riot method of the GreyNoise Python SDK
RIOT_FIELDS = {
    'ip': None,
    'riot': None,
    'category': None,
    'name': None,
    'description': None,
    'explanation': None,
    'last_updated': None,
    'logo_url': None,
    'reference': None,
    'trust_level': None,
    'error': None
}

GREYNOISE_RIOT_FIELDS = {
    'greynoise_ip': None,
    'greynoise_riot': None,
    'greynoise_category': None,
    'greynoise_name': None,
    'greynoise_description': None,
    'greynoise_explanation': None,
    'greynoise_last_updated': None,
    'greynoise_logo_url': None,
    'greynoise_reference': None,
    'greynoise_trust_level': None,
    'greynoise_error': None
}
