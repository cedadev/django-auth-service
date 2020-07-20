""" OAuth2 exceptions. """

__author__ = "William Tucker"
__date__ = "2020-07-16"
__copyright__ = "Copyright 2020 United Kingdom Research and Innovation"
__license__ = "BSD - see LICENSE file in top-level package directory"


class CookieParsingError(Exception):
    """ Generic exception raised when a cookie cannot be parsed. """
