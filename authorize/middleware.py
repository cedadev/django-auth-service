""" General auth middleware. """

__author__ = "William Tucker"
__date__ = "2020-03-26"
__copyright__ = "Copyright 2020 United Kingdom Research and Innovation"
__license__ = "BSD - see LICENSE file in top-level package directory"


import logging

from django.conf import settings
from django.http import HttpResponse

from authenticate.utils import is_authenticated
from authorize.saml import SAMLAuthorizer
from authorize.saml.exceptions import SamlAuthorizationError


LOG = logging.getLogger(__name__)


class SAMLAuthorizationMiddleware:
    """ Middleware for handling authorization of authenticated requests """

    RESOURCE_QUERY_KEY = "next"
    RESOURCE_HEADER_KEY = "HTTP_X_ORIGIN_URI"

    def __init__(self, get_response):

        self.get_response = get_response
        self._saml_authorizer = SAMLAuthorizer(
            service_uri=settings.AUTHORIZATION_SERVICE_URL
        )

    def __call__(self, request):

        openid = None
        if is_authenticated(request):

            # Get OpenID from session
            # TODO: get openid from user object
            openid = request.session.get("openid")

        # Construct a URI for the requested resource
        resource = self._construct_resource_uri(request)
        if resource:

            is_authorized = self._is_authorized(request, resource, openid)

            # If user is logged in but cannoy access the resource then respond
            # with a 403.
            if is_authenticated(request) and not is_authorized:
                return HttpResponse("Unauthorized", status=403)

        # If user is not authenticated or is authorized, continue
        response = self.get_response(request)
        return response

    def _is_authorized(self, request, resource, openid=None):

        LOG.debug(f"Querying authorization for resource: {resource}")

        # Check authorization for resource
        is_authorized = False
        try:

            # Get an authorization decision from the authorization service
            is_authorized = self._saml_authorizer.is_authorized(
                resource=resource,
                openid=openid
            )

        except SamlAuthorizationError as e:

            LOG.info(f"Authorization failed for user: {openid}")
            raise e

        return is_authorized

    @classmethod
    def _construct_resource_uri(cls, request):
        """ Constructs a URI for a requested resource. """

        resource = None

        # Check for resource in the HTTP header
        if cls.RESOURCE_HEADER_KEY in request.META:

            resource_parts = [
                settings.RESOURCE_SERVER_URI.strip("/"),
                request.META[cls.RESOURCE_HEADER_KEY].strip("/"),
            ]
            resource = "/".join(resource_parts)

        return resource
