""" Utility functions for the app. """

__author__ = "William Tucker"
__date__ = "2020-05-27"
__copyright__ = "Copyright 2020 United Kingdom Research and Innovation"
__license__ = "BSD - see LICENSE file in top-level package directory"


import logging

from collections import namedtuple
from django.conf import settings


LOG = logging.getLogger(__name__)

USER_SESSION_KEY = "authenticated_user"
USER_PROPERTIES = [
    "username",
    "groups",
]

DEFAULT_RESOURCE_URI_QUERY_KEY = "next"
DEFAULT_RESOURCE_URI_HEADER_KEY = "HTTP_X_ORIGINAL_URI"

DEFAULT_REQUEST_METHOD_QUERY_KEY = "method"
DEFAULT_REQUEST_METHOD_HEADER_KEY = "HTTP_X_ORIGINAL_METHOD"

DEFAULT_RESOURCE_URI_SESSION_KEY = "resource_uri"


User = namedtuple("User", USER_PROPERTIES)


def login(request, user):
    """ Stores a user's data in the request session. """

    request.session[USER_SESSION_KEY] = user._asdict()


def get_user(request):
    """ Gets the stored user from the request session. """

    user_data = request.session.get(USER_SESSION_KEY)
    if user_data:
        return User(**user_data)


def is_authenticated(request):
    """ Checks if a request is associated with an authenticate user.
    Returns True if authenticated.
    """

    return bool(get_user(request))


def get_requested_resource(request):
    """ Return a reverse-proxy-originating resource URL from the request.
    """

    # Attempt to get the URL from the request query
    query_key = getattr(settings, "RESOURCE_URI_QUERY_KEY",
        DEFAULT_RESOURCE_URI_QUERY_KEY)
    resource_uri = request.GET.get(query_key, None)

    if resource_uri:
        LOG.debug(f"Found resource URI from query '{query_key}': '{resource_uri}'")

    else:
        LOG.debug(f"No resource URI from query '{query_key}', checking headers...")

        # Attempt to get the resource URL from the request header
        header_key = getattr(settings, "RESOURCE_URI_HEADER_KEY",
            DEFAULT_RESOURCE_URI_HEADER_KEY)
        resource_uri = request.META.get(header_key, None)

        if resource_uri:
            LOG.debug(f"Found resource URI from header '{header_key}': '{resource_uri}'")
        else:
            LOG.debug(f"No resource URI from header '{header_key}'")

    request_method = "GET"

    return resource_uri, request_method


def get_stored_resource(request):
    """ Return a stored resource URL from the session.
    """

    # Attempt to get the resource URL from the session
    session_key = getattr(settings, "RESOURCE_URI_SESSION_KEY",
        DEFAULT_RESOURCE_URI_SESSION_KEY)
    resource_uri = request.session.get(session_key, None)

    return resource_uri


def save_resource(request, resource_uri):
    """ Save the reverse-proxy-originating resource URL.
    """

    # Save next URL to session to be picked up by the callback
    session_key = getattr(settings, "RESOURCE_URI_SESSION_KEY",
        DEFAULT_RESOURCE_URI_SESSION_KEY)
    request.session[session_key] = resource_uri
