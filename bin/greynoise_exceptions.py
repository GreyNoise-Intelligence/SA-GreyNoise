"""This file contains custom exceptions used in the GreyNoise App."""


class APIKeyNotFoundError(Exception):
    """This exception is raised when API key is not configured in GreyNoise Splunk App."""

    pass


class CachingException(Exception):
    """This exception is raised when some error occurs in Caching."""

    pass
