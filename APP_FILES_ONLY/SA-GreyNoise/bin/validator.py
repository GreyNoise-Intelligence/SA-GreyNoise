"""This file contains classes that can be used for validation of the parameters given to the Custom commands by user."""
import re

import app_greynoise_declare  # noqa # pylint: disable=unused-import
import six


class Validator(object):
    """Base class for the validators of the custom command options."""

    # This method needs to get defined for each class inheriting this class
    def validate(self):
        """Method used to validate values passed to custom commands."""
        raise NotImplementedError()


class Boolean(Validator):
    """
    Validates boolean option values.

    :param option_name: name of the option from custom command whose value is validated
    :param truth_values: Dict having the mapping of values to accept for the boolean option
    :return: Boolean object as per user inputs
    :raises: ValueError when the value of the given Option is not acceptable
    """

    truth_values = {
        "1": True,
        "0": False,
        "t": True,
        "f": False,
        "true": True,
        "false": False,
        "y": True,
        "n": False,
        "yes": True,
        "no": False,
    }

    def __init__(self, option_name=""):
        """Initialize option name."""
        self.option_name = option_name

    def validate(self, value=None):
        """Validates boolean value passed to custom commands."""
        # For both optional and required options
        if value == "":
            raise ValueError("Parameter {} should not be empty.".format(self.option_name))

        # This will only occur in the case of optional parameters
        # Sending the values as it is if it is None
        if value is not None and not isinstance(value, bool):
            value = six.text_type(value).lower()
            if value not in Boolean.truth_values:
                raise ValueError(
                    "Please specify boolean value for parameter: {0}, given value: {1}".format(self.option_name, value)
                )
            value = self.truth_values[value]

        return value


class Fieldname(Validator):
    """
    Validates fieldname option values.

    :param option_name: name of the option from custom command whose value is validated
    :param pattern: Regular expression to match against the user input
    :return: Field name as per user inputs
    :raises: ValueError when the value of the given Option is not acceptable
    """

    pattern = re.compile(r"""^[_.a-zA-Z-][_.a-zA-Z0-9-]*$""")

    def __init__(self, option_name=""):
        """Initialize option name."""
        self.option_name = option_name

    def validate(self, value=None):
        """Validates field name passed to custom commands."""
        # For both optional and required options
        if value == "":
            raise ValueError("Parameter {} should not be empty.".format(self.option_name))

        # This will only occur in the case of optional parameters
        # Sending the values as it is if it is None
        if value is not None:
            value = six.text_type(value)
            if self.pattern.match(value) is None:
                raise ValueError(
                    "Given value: '{0}' for parameter: {1} does not match the valid Splunk field pattern".format(
                        value, self.option_name
                    )
                )
        return value


class Integer(Validator):
    """
    Validates integer option values.

    :param option_name: name of the option from custom command whose value is validated
    :param minimum: Minimum integer value that this option can have
    :param maximum: Maximum integer value that this option can have
    :return: Integer number as per user inputs
    :raises: ValueError when the value of the given Option is not acceptable
    """

    def __init__(self, option_name=None, minimum=None, maximum=None):
        """Initialize option name and raise ValueError when value of the given option is not acceptable."""
        self.option_name = option_name

        if minimum is not None and maximum is not None:

            def check_range(value):
                if not (minimum <= value <= maximum):
                    raise ValueError(
                        "Value of parameter {0} should be between {1} and {2}, given value: {3}".format(
                            self.option_name, minimum, maximum, value
                        )
                    )
                return

        elif minimum is not None:

            def check_range(value):
                if value < minimum:
                    raise ValueError(
                        "Value of parameter {0} should be greater than {1}, given value: {2}".format(
                            self.option_name, minimum, value
                        )
                    )
                return

        elif maximum is not None:

            def check_range(value):
                if value > maximum:
                    raise ValueError(
                        "Value of parameter {0} should be lesser than {1}, given value: {2}".format(
                            self.option_name, maximum, value
                        )
                    )
                return

        else:

            def check_range(value):
                return

        self.check_range = check_range
        return

    def validate(self, value=None):
        """Validates integer value passed to custom commands."""
        # For both optional and required options
        if value == "":
            raise ValueError("Parameter {} should not be empty.".format(self.option_name))

        # This will only occur in the case of optional parameters
        # Sending the values as it is if it is None
        if value is not None:
            try:
                if six.PY2:
                    value = long(value)  # noqa: F821
                else:
                    value = int(value)
            except ValueError:
                raise ValueError(
                    "Please specify integer value for parameter: {0}, given value: {1}".format(self.option_name, value)
                )

            self.check_range(value)
        return value
