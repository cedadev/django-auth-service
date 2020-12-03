""" General auth middleware. """

__author__ = "William Tucker"
__date__ = "2020-03-26"
__copyright__ = "Copyright 2020 United Kingdom Research and Innovation"
__license__ = "BSD - see LICENSE file in top-level package directory"


import logging

from django.conf import settings
from django.http import HttpResponse
from django.urls import resolve

from authenticate.utils import is_authenticated, get_resource_url, \
    save_resource_url


LOG = logging.getLogger(__name__)


class AuthorizationMiddleware:
    """ Middleware for handling authorization of authenticated requests """

    EXEMPT_URLS = ["login", "callback"]

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):

        exempt = False
        url_name = resolve(request.path_info).url_name
        if url_name in self.EXEMPT_URLS:
            exempt = True

        if hasattr(settings, "CUSTOM_AUTHORIZATION"):
            exempt = settings.CUSTOM_AUTHORIZATION(request)

        # Construct a URI for the requested resource
        resource = get_resource_url(request)

        if not exempt and resource:

            save_resource_url(request)

            if not self._is_authorized(request, resource):
                if is_authenticated(request):
                    # Logged in but cannot access the resource
                    return HttpResponse("Unauthorized", status=403)
                else:
                    # Cannot access the resource but not logged in yet
                    return HttpResponse("Unauthenticated", status=401)

            LOG.debug("Request authorised")

        response = self.get_response(request)
        return response

    def _is_authorized(self, request, resource):
        raise NotImplementedError()


class LoginAuthorizationMiddleware(AuthorizationMiddleware):
    """ Simple middleware that authorizes any authenticated user. """

    def _is_authorized(self, request, resource):
        return is_authenticated(request)
