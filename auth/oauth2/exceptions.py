""" OAuth2 exceptions. """

__author__ = "William Tucker"
__date__ = "2020-03-25"
__copyright__ = "Copyright 2020 United Kingdom Research and Innovation"
__license__ = "BSD - see LICENSE file in top-level package directory"


class BadAccessTokenError(Exception):
    """ Generic exception raised when an access token cannot be parsed. """
