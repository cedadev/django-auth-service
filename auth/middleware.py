""" General auth middleware. """

__author__ = "William Tucker"
__date__ = "2020-03-26"
__copyright__ = "Copyright 2020 United Kingdom Research and Innovation"
__license__ = "BSD - see LICENSE file in top-level package directory"


from django.contrib.auth import authenticate, login


class AuthenticationMiddleware:

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):

        user = authenticate(request)
        if user:
            login(request, user)

        response = self.get_response(request)
        return response


class AuthorizationMiddleware:

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):

        # SAML Stuff

        response = self.get_response(request)
        return response
