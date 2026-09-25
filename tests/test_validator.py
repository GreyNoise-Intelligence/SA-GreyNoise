"""Tests for custom command option validators."""

import pytest
import validator


def test_boolean_accepts_common_truth_values():
    boolean = validator.Boolean(option_name="noise_events")
    assert boolean.validate("true") is True
    assert boolean.validate("0") is False
    assert boolean.validate(True) is True


def test_boolean_rejects_empty_and_unknown_values():
    boolean = validator.Boolean(option_name="noise_events")
    with pytest.raises(ValueError, match="should not be empty"):
        boolean.validate("")
    with pytest.raises(ValueError, match="boolean value"):
        boolean.validate("maybe")


def test_fieldname_accepts_splunk_style_names():
    fieldname = validator.Fieldname(option_name="ip_field")
    assert fieldname.validate("src_ip") == "src_ip"
    assert fieldname.validate("_key") == "_key"
    assert fieldname.validate("gn-ip") == "gn-ip"


def test_fieldname_rejects_invalid_names():
    fieldname = validator.Fieldname(option_name="ip_field")
    with pytest.raises(ValueError, match="valid Splunk field pattern"):
        fieldname.validate("1src")
    with pytest.raises(ValueError, match="should not be empty"):
        fieldname.validate("")


def test_integer_enforces_minimum_and_maximum():
    integer = validator.Integer(option_name="page_size", minimum=1, maximum=10000)
    assert integer.validate("500") == 500
    with pytest.raises(ValueError, match="between"):
        integer.validate("0")
    with pytest.raises(ValueError, match="between"):
        integer.validate("10001")
    with pytest.raises(ValueError, match="integer value"):
        integer.validate("ten")
