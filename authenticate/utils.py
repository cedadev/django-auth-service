""" Utility functions for the app. """

__author__ = "William Tucker"
__date__ = "2020-05-27"
__copyright__ = "Copyright 2020 United Kingdom Research and Innovation"
__license__ = "BSD - see LICENSE file in top-level package directory"


USER_SESSION_KEY = "authenticated_user"


def is_authenticated(request):
    """ Checks if a request is associated with an authenticate user.
    Returns True if authenticated.
    """

    user_identifier = request.session.get(USER_SESSION_KEY)
    return bool(user_identifier)


def login(request, user_identifier):
    """ Stores a user's identifier in the request session. """

    request.session[USER_SESSION_KEY] = user_identifier
