""" General auth middleware. """

__author__ = "William Tucker"
__date__ = "2020-03-26"
__copyright__ = "Copyright 2020 United Kingdom Research and Innovation"
__license__ = "BSD - see LICENSE file in top-level package directory"


import logging

from django.conf import settings
from django.contrib.auth import authenticate, login
from django.http import HttpResponse

from auth.saml import SAMLAuthorizer
from auth.saml.exceptions import SamlAuthorizationError


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


class SAMLAuthorizationMiddleware:
    """ Middleware for handling authorization of authenticated requests """

    RESOURCE_HEADER = "HTTP_X_ORIGIN_URI"

    def __init__(self, get_response):

        self.get_response = get_response
        self._saml_authorizer = SAMLAuthorizer(
            service_uri=settings.AUTHORIZATION_SERVICE_URL
        )

    def __call__(self, request):

        if request.user.is_authenticated:

            # Get OpenID from session
            # TODO: get openid from user object
            openid = request.session.get("openid")

            is_authorized = self._is_authorized(request, openid)

            if not is_authorized:
                return HttpResponse("Unauthorized", status=403)

        # If user is not authenticated or is authorized, continue
        response = self.get_response(request)
        return response

    def _is_authorized(self, request, openid):

        # Construct a URI for the requested resource
        resource = self._construct_resource_uri(request)
        LOG.error(f"Querying authorization for resource: {resource}")

        # Check authorization for resource
        is_authorized = False
        try:
            # Get an authorization decision from the authorization service
            is_authorized = self._saml_authorizer.is_authorized(
                resource=resource,
                openid=openid
            )

        except SamlAuthorizationError as e:
            LOG.error(f"Authorization failed for user: {openid}")
            raise e

        return is_authorized

    @classmethod
    def _construct_resource_uri(cls, request):
        """ Constructs a URI for a requested resource. """

        resource_parts = [
            settings.RESOURCE_SERVER_URI.strip("/"),
            request.META[cls.RESOURCE_HEADER].strip("/"),
        ]
        return "/".join(resource_parts)
