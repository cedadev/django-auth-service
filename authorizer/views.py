""" Views for the authorizer app. """

__author__ = "William Tucker"
__date__ = "2020-02-05"
__copyright__ = "Copyright 2020 United Kingdom Research and Innovation"
__license__ = "BSD - see LICENSE file in top-level directory"


import logging

from authlib.integrations.django_client import OAuth
from django.conf import settings
from django.http import HttpResponse
from django.views.generic import View

from authorizer.saml import SAMLAuthorizer
from authorizer.oauth.utils import parse_access_token
from authorizer.exceptions import BadAccessTokenError


LOG = logging.getLogger(__name__)


class OpenIDConnectMixin(View):
    """ A Django View Mixin which provides an OpenIDConnect client and
    helper functions. """

    def __init__(self, *args, **kwargs):

        super().__init__(*args, **kwargs)
        self._build_client()

    def _authorize_redirect(self, request):

        redirect_uri = request.META.get("HTTP_REFERER")
        return self.oidc_client.authorize_redirect(request, redirect_uri)

    def _get_user_info(self, request):

        token = self.oidc_client.authorize_access_token(request)
        return self.oidc_client.parse_id_token(request, token)

    def _build_client(self):

        oauth = OAuth()
        oauth.register("ceda")
        self.oidc_client = oauth.ceda


class BaseAuthorizeView(OpenIDConnectMixin, View):
    """ Base class for Authorization views """

    @staticmethod
    def _construct_resource_uri(request):
        """ Constructs a URI for a requested resource. """

        resource_parts = [
            settings.RESOURCE_SERVER_URI.strip("/"),
            request.META["HTTP_X_ORIGINAL_URI"].strip("/"),
        ]
        return "/".join(resource_parts)


class AuthorizeView(BaseAuthorizeView):
    """ View for authorizing a request. """

    def __init__(self, *args, **kwargs):

        super().__init__(*args, **kwargs)
        self.saml_authorizer = SAMLAuthorizer(
            service_uri=settings.AUTHORIZATION_SERVICE_URL
        )

    def get(self, request):
        """ HTTP GET request handler for this view. """

        openid = None
        is_cli = False

        # Check for CLI user
        authorization_header = request.META.get("HTTP_AUTHORIZATION")
        if authorization_header:

            is_cli = True

            access_token = authorization_header.strip("Bearer").strip()
            LOG.debug(f"Found access token: {access_token}")

            # Attempt to retrieve OpenID from OAuth2 access token
            user_data = None
            try:
                user_data = parse_access_token(access_token)
            except BadAccessTokenError:
                LOG.warn("Failed to parse access token for request.")

            if not user_data or "openid" not in user_data:
                return HttpResponse("Unauthorized", status=401)

            openid = user_data["openid"]

            LOG.debug(f"Parsed openid from access token: {openid}")

        if not is_cli:

            # TODO: OpenIDConnect auth
            pass

        # Get an authorization decision from the authorization service
        decision = self._check_authorization(request, openid)
        LOG.debug(f"Got decision: {decision}")

        if decision != "Permit":
            return HttpResponse("Forbidden", status=403)

        return HttpResponse("Permit", status=200)

    def _check_authorization(self, request, openid=None):
        """ Queries the SAML Authorization service to determine whether or not
        the requested resource can be accessed. """

        # Construct a URI for the requested resource
        resource = self._construct_resource_uri(request)

        # Return an authorization decision
        return self.saml_authorizer.get_decision(
            openid=openid,
            resource=resource
        )


class OidcAuthenticateView(BaseAuthorizeView):
    """ View for handling OpenIDConnect authentication. """

    def get(self, request):
        """ HTTP GET request handler for this view. """

        return self._redirect(request)

    def _redirect(self, request):
        """ Redirects a request to the OAuth server for authentication. """

        redirect_uri = self._construct_resource_uri(request)
        return self.oidc_client.authorize_redirect(request, redirect_uri)
