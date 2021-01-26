""" Utility functions for the app. """

__author__ = "William Tucker"
__date__ = "2020-05-27"
__copyright__ = "Copyright 2020 United Kingdom Research and Innovation"
__license__ = "BSD - see LICENSE file in top-level package directory"


from django.conf import settings


USER_SESSION_KEY = "authenticated_user"

DEFAULT_RESOURCE_URL_QUERY_KEY = "next"
DEFAULT_RESOURCE_URL_HEADER_KEY = "HTTP_X_ORIGIN_URI"
DEFAULT_RESOURCE_URL_SESSION_KEY = "resource_url"


def login(request, user_identifier):
    """ Stores a user's identifier in the request session. """

    request.session[USER_SESSION_KEY] = user_identifier


def get_user_identifier(request):
    """ Gets the stored user identifier from the request session. """

    user_identifier = request.session.get(USER_SESSION_KEY)
    return user_identifier


def is_authenticated(request):
    """ Checks if a request is associated with an authenticate user.
    Returns True if authenticated.
    """

    return bool(get_user_identifier(request))


def get_requested_resource(request):
    """ Return a reverse-proxy-originating resource URL from the request.
    """

    # Attempt to get the URL from the request query
    query_key = getattr(settings, "RESOURCE_URL_QUERY_KEY",
        DEFAULT_RESOURCE_URL_QUERY_KEY)
    resource_url = request.GET.get(query_key, None)

    if not resource_url:

        # Attempt to get the resource URL from the request header
        header_key = getattr(settings, "RESOURCE_URL_HEADER_KEY",
            DEFAULT_RESOURCE_URL_HEADER_KEY)
        resource_url = request.META.get(header_key, None)

    return resource_url


def get_stored_resource(request):
    """ Return a stored resource URL from the session.
    """

    # Attempt to get the resource URL from the session
    session_key = getattr(settings, "RESOURCE_URL_SESSION_KEY",
        DEFAULT_RESOURCE_URL_SESSION_KEY)
    resource_url = request.session.get(session_key, None)

    return resource_url


def save_resource_url(request, resource_url):
    """ Save the reverse-proxy-originating resource URL.
    """

    # Save next URL to session to be picked up by the callback
    session_key = getattr(settings, "RESOURCE_URL_SESSION_KEY",
        DEFAULT_RESOURCE_URL_SESSION_KEY)
    request.session[session_key] = resource_url
