
import app_greynoise_declare

from splunktaucclib.rest_handler.endpoint import (
    field,
    validator,
    RestModel,
    MultipleModel,
)
import splunk.rest as rest
from splunktaucclib.rest_handler import admin_external, util
from splunk_aoblib.rest_migration import ConfigMigrationHandler

from greynoise_account_validation import GreyNoiseAPIValidation, GreyNoiseScanDeployment, PurgeHandler, EnableCachingHandler, TtlHandler

util.remove_http_proxy_env_vars()

fields_logging = [
    field.RestField(
        'loglevel',
        required=False,
        encrypted=False,
        default='INFO',
        validator=None
    )
]
model_logging = RestModel(fields_logging, name='logging')


fields_parameters = [
    field.RestField(
        'api_key',
        required=True,
        encrypted=True,
        default=None,
        validator=GreyNoiseAPIValidation()
    )
]
model_parameters = RestModel(fields_parameters, name='parameters')

fields_caching = [
    field.RestField(
        'enable_caching',
        required=False,
        encrypted=False,
        validator=EnableCachingHandler()
    ),
    field.RestField(
        'ttl',
        required=False,
        encrypted=False,
        default='24',
        validator=TtlHandler()
    ),
    field.RestField(
        'purge_cache',
        required=False,
        encrypted=False,
        validator=PurgeHandler()
    ),
]
model_caching = RestModel(fields_caching, name='caching')

fields_scan_deployment = [
    field.RestField(
        'ip_indexes',
        required=True,
        encrypted=False,
        default='main',
        validator=validator.String(
            min_len=1, 
            max_len=8192, 
        )
    ),
    field.RestField(
        'cim_ip_fields',
        required=True,
        encrypted=False,
        default=None,
        validator=validator.String(
            min_len=1, 
            max_len=8192, 
        )
    ),
    field.RestField(
        'enable_ss',
        required=False,
        encrypted=False,
        default=None,
        validator=GreyNoiseScanDeployment()
    ),
    field.RestField(
        'other_ip_fields',
        required=False,
        encrypted=False,
        default=None,
        validator=None
    ),
    field.RestField(
        'scan_start_time',
        required=True,
        encrypted=False,
        default=None,
        validator=None
    ),
    field.RestField(
        'force_enable_ss',
        required=False,
        encrypted=False,
        default=None,
        validator=None
    )
]
model_scan_deployment = RestModel(fields_scan_deployment, name='scan_deployment')

endpoint = MultipleModel(
    'app_greynoise_settings',
    models=[
        model_logging, 
        model_parameters,
        model_scan_deployment,
        model_caching
    ],
)


if __name__ == '__main__':
    admin_external.handle(
        endpoint,
        handler=ConfigMigrationHandler,
    )
