import validator

DATE = {
    "NOW": "1",
    "LAST_FIVE_MINS": "2",
    "LAST_SIXTY_MINS": "3",
    "LAST_TWENTY_FOUR_HOURS": "4",
    "LAST_SEVEN_DAYS": "5",
    "LAST_THIRTY_DAYS": "6",
    "LAST_SIXTY_DAYS": "7",
}

TIME_MAP = {"1": "0", "2": "-5m", "3": "-60m", "4": "-24h", "5": "-7d", "6": "-30d", "7": "-60d"}

CIM_IP_FIELDS = [
    "dest",
    "dvc",
    "src",
    "dest_ip",
    "src_ip",
    "dvc_ip",
    "orig_src",
    "orig_dest",
    "host",
    "source",
    "dest_translated_ip",
    "src_translated_ip",
]


def is_api_configured(conf):
    """
    Checks whether API key is configured.

    :param conf:
    :return string:
    """
    parameters = conf.get("parameters", {})
    return parameters.get("api_key", None)


def compare_parameters(data, conf_data):
    """
    Compare current inputs with existing inputs.

    :param data:
    :param conf_data:
    :return boolean:
    """
    # Compare indexes
    if not conf_data.get("ip_indexes", None):
        return True
    data_index = get_unique_set(data.get("ip_indexes"))
    conf_index = get_unique_set(conf_data.get("ip_indexes"))
    if data_index > conf_index:
        return True

    # Compare fields
    if not conf_data.get("cim_ip_fields", None):
        return True
    data_all_fields = get_unique_set(data.get("cim_ip_fields"))
    if "all" in data_all_fields:
        data_all_fields = set(CIM_IP_FIELDS)
    conf_all_fields = get_unique_set(conf_data.get("cim_ip_fields"))
    if "all" in conf_all_fields:
        conf_all_fields = set(CIM_IP_FIELDS)

    # If no other fields are present cim fields will be all fields itself
    if data.get("other_ip_fields", None):
        data_other_ip_fields = get_unique_set(data.get("other_ip_fields"))
        data_all_fields = data_other_ip_fields.union(data_all_fields)
    if conf_data.get("other_ip_fields", None):
        conf_other_ip_fields = get_unique_set(conf_data.get("other_ip_fields"))
        conf_all_fields = conf_other_ip_fields.union(conf_all_fields)

    if data_all_fields > conf_all_fields:
        return True

    # Compare time
    if not conf_data.get("scan_start_time", None):
        return True
    if int(DATE[conf_data.get("scan_start_time")]) < int(DATE[data.get("scan_start_time")]):
        return True

    # Return False as all the fields are subset
    return False


def get_unique_set(data):
    """
    Returns set of csv values.

    :param data:
    :return set:
    """
    return set([_f for _f in [x.strip() for x in data.split(",")] if _f])


def get_macro_string(data):
    """
    Returns csv formatted String from data.

    :param data:
    :return string:
    """
    return ",".join(str(s) for s in data)


def get_macro_string_with_quotes(data):
    """
    Returns formatted String from data.

    :param data:
    :return string:
    """
    return ",".join("'{0}'".format(s) for s in data)


def handle_macros(data, service):
    """
    Gets the parameters and updates the corresponding macros.

    :param data:
    :param service:
    :return:
    """
    # Update index macro
    indexes = get_unique_set(data.get("ip_indexes"))
    indexes_string = get_macro_string(indexes)
    service.post("properties/macros/greynoise_indexes", definition=indexes_string)

    # update all_fields macro
    all_fields = get_unique_set(data.get("cim_ip_fields"))
    if "all" in all_fields:
        all_fields = set(CIM_IP_FIELDS)

    all_cim_fields_string = get_macro_string(all_fields)
    # If no other fields are present cim fields will be all fields itself
    if data.get("other_ip_fields"):
        other_ip_fields = get_unique_set(data.get("other_ip_fields"))
        field_name_validator = validator.Fieldname()
        for field in other_ip_fields:
            field_name_validator.validate(field)
        all_fields = other_ip_fields.union(all_fields)
        other_ip_fields_string = get_macro_string_with_quotes(other_ip_fields)
        all_cim_fields_string = f"{all_cim_fields_string},{other_ip_fields_string}"

    all_fields_string = get_macro_string(all_fields)
    service.post("properties/macros/greynoise_fields", definition=all_fields_string)
    service.post("properties/macros/greynoise_other_fields", definition=all_cim_fields_string)
