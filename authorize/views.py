""" Views for the authorize app. """

__author__ = "William Tucker"
__date__ = "2020-12-10"
__copyright__ = "Copyright 2020 United Kingdom Research and Innovation"
__license__ = "BSD - see LICENSE file in top-level directory"


import logging

from django.conf import settings
from django.http import HttpResponse
from django.views.generic import View

from authenticate.utils import get_user


LOG = logging.getLogger(__name__)

DEFAULT_REMOTE_USER_RESPONSE_HEADER_KEY = "X-Remote-User"


class VerifyView(View):
    """ View for checking the authorizing of a request.
    The response will vary depending on the middleware used to intercept the
    request and the resource being requested (if any).
    """

    def get(self, request):
        """ HTTP GET request handler for this view. """

        # If this line is reached, we can assume that the request has passed
        # all configured authorization checks.
        response = HttpResponse("Authorized", status=200)

        # Attach username to response if user is authenticated
        user = get_user(request)
        if user:

            header_key = getattr(settings, "REMOTE_USER_RESPONSE_HEADER_KEY",
                DEFAULT_REMOTE_USER_RESPONSE_HEADER_KEY)
            LOG.debug(f"Saving user {user.username} to response: {header_key}")
            response[header_key] = user.username

        return response
