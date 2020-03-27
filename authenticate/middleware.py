""" General auth middleware. """

__author__ = "William Tucker"
__date__ = "2020-03-26"
__copyright__ = "Copyright 2020 United Kingdom Research and Innovation"
__license__ = "BSD - see LICENSE file in top-level package directory"


import logging

from django.contrib.auth import authenticate, login


LOG = logging.getLogger(__name__)


class AuthenticationMiddleware:
    """ Authentication middleware which relies on a request object only. """

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):

        # Attempt to authenticate the request with available middleware
        user = authenticate(request)
        if user:
            login(request, user)

        response = self.get_response(request)
        return response
