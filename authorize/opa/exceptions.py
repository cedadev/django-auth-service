""" OPA Authorization related exceptions. """

__author__ = "William Tucker"
__date__ = "2020-02-14"
__copyright__ = "Copyright 2020 United Kingdom Research and Innovation"
__license__ = "BSD - see LICENSE file in top-level package directory"


class OPAAuthorizationError(Exception):
    """ Generic exception raised when a problem occurs when querying the
    OPA Authorization service.
    """
