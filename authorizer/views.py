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
from django.urls import reverse
from django.shortcuts import redirect

from authorizer.saml import SAMLAuthorizer
from authorizer.oauth.utils import parse_access_token
from authorizer.exceptions import BadAccessTokenError, SamlAuthorizationError


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
            request.META["HTTP_X_ORIGIN_URI"].strip("/"),
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

        openid = request.session.get("openid")

        if not openid:
            # Try to retrieve openid with an access token if one is present
            openid = self._openid_from_access_token(request)

        is_authenticated = openid != None

        # Construct a URI for the requested resource
        resource = self._construct_resource_uri(request)
        LOG.error(f"Querying authorization for resource: {resource}")

        # Check authorization for resource
        is_authorized = False
        try:
            # Get an authorization decision from the authorization service
            is_authorized = self.saml_authorizer.is_authorized(
                resource=resource,
                openid=openid
            )

        except SamlAuthorizationError as e:
            LOG.error(f"Authorization failed for user: {openid}")
            raise e

        if not is_authorized:

            if is_authenticated:
                return HttpResponse("Unauthorized", status=403)

            return HttpResponse("Unauthenticated", status=401)

        return HttpResponse("Authorized", status=200)

    def _openid_from_access_token(self, request):
        """ Checks for OAuth2 access token in the request.
        Returns an OpenID associated with the token or None. """

        authorization_header = request.META.get("HTTP_AUTHORIZATION")
        if authorization_header and authorization_header.startswith("Bearer"):

            access_token = authorization_header.strip("Bearer").strip()
            LOG.debug(f"Found access token: {access_token}")

            # Attempt to retrieve OpenID from OAuth2 access token
            user_data = None
            try:
                user_data = parse_access_token(access_token)
            except BadAccessTokenError:
                LOG.warn("Failed to parse access token for request.")

            if user_data and "openid" in user_data:
                return user_data["openid"]

            else:
                LOG.debug(f"Couldn't get openid from request.")


class CallbackView(BaseAuthorizeView):
    """ View for handling OpenIDConnect authentication callbacks. """

    def get(self, request):
        """ HTTP GET request handler for this view. """

        token = self.oidc_client.authorize_access_token(request)
        userinfo = self.oidc_client.parse_id_token(request, token)

        if userinfo:
            request.session["openid"] = settings.TMP_TEST_OPENID

        return redirect(request.GET["next"])


class LoginView(BaseAuthorizeView):
    """ View for handling OpenIDConnect authentication. """

    def get(self, request):
        """ HTTP GET request handler for this view. """

        return self._redirect(request)

    def _redirect(self, request):
        """ Redirects a request to the OAuth server for authentication. """

        redirect_uri = request.build_absolute_uri(reverse("callback"))
        resource_uri = request.GET.get("next")
        redirect_uri = f"{redirect_uri}?next={resource_uri}"
        return self.oidc_client.authorize_redirect(request, redirect_uri)
