INTEGRATION_NAME = "greynoise-splunk-app-v3.0.1"
BACKOFF_FACTOR = 30
MAX_RETRIES = 3
SENDALERT_COMMAND = '| makeresults | eval risk_object="{}", risk_object_type="{}", risk_score="{}", description="{}" | sendalert risk param.risk_object="$risk_object$" param.risk_object_type="$risk_object_type$" param.risk_score="$risk_score$"'
IPV4_REGEX = r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
IPV6_REGEX = r"^(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$|^(?:[0-9a-fA-F]{1,4}:){6}(?::[0-9a-fA-F]{1,4}|:)$|^(?:[0-9a-fA-F]{1,4})?::(?:[0-9a-fA-F]{1,4}:){5}[0-9a-fA-F]{1,4}$|^(?:[0-9a-fA-F]{1,4}:(?::[0-9a-fA-F]{1,4}){0,2})?::(?:[0-9a-fA-F]{1,4}:){4}[0-9a-fA-F]{1,4}$|^(?:[0-9a-fA-F]{1,4}:(?::[0-9a-fA-F]{1,4}){0,3})?::(?:[0-9a-fA-F]{1,4}:){3}[0-9a-fA-F]{1,4}$|^(?:[0-9a-fA-F]{1,4}:(?::[0-9a-fA-F]{1,4}){0,4})?::(?:[0-9a-fA-F]{1,4}:){2}[0-9a-fA-F]{1,4}$|^(?:[0-9a-fA-F]{1,4}:(?::[0-9a-fA-F]{1,4}){0,5})?::[0-9a-fA-F]{1,4}$"
VERIFY_INTERNAL_SSL = False