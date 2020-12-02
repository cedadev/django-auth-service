""" Utility functions for the app. """

__author__ = "William Tucker"
__date__ = "2020-05-27"
__copyright__ = "Copyright 2020 United Kingdom Research and Innovation"
__license__ = "BSD - see LICENSE file in top-level package directory"


USER_SESSION_KEY = "authenticated_user"

RESOURCE_URL_QUERY_KEY = "next"
RESOURCE_URL_HEADER_KEY = "X-Origin-URI"
RESOURCE_URL_SESSION_KEY = "resource_url"


def is_authenticated(request):
    """ Checks if a request is associated with an authenticate user.
    Returns True if authenticated.
    """

    user_identifier = request.session.get(USER_SESSION_KEY)
    return bool(user_identifier)


def get_resource_url(request):
    """ Return the reverse-proxy-originating resource URL from the session.
    """

    resource_url = request.META.get(RESOURCE_URL_HEADER_KEY, None)
    if not resource_url:
        resource_url = request.GET.get(RESOURCE_URL_QUERY_KEY)
    if not resource_url:
        resource_url = request.session.get(RESOURCE_URL_SESSION_KEY, None)

    return resource_url


def save_resource_url(request):
    """ Save the reverse-proxy-originating resource URL.
    """

    resource_url = get_resource_url(request)
    if resource_url:
        # Save next URL to session to be picked up by the callback
        request.session[RESOURCE_URL_SESSION_KEY] = resource_url


def login(request, user_identifier):
    """ Stores a user's identifier in the request session. """

    request.session[USER_SESSION_KEY] = user_identifier
