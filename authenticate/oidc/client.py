""" OpenID Connect client utilities. """

__author__ = "William Tucker"
__date__ = "2020-03-26"
__copyright__ = "Copyright 2020 United Kingdom Research and Innovation"
__license__ = "BSD - see LICENSE file in top-level package directory"


import logging

from authlib.integrations.base_client import OAuthError
from authlib.integrations.django_client import OAuth
from django.conf import settings


LOG = logging.getLogger(__name__)


class OpenIDConnectClient:
    """ A simple OpenIDConnect client wrapper. """

    @property
    def oidc_client(self):
        return self._oidc_client

    def __init__(self, *args, **kwargs):

        super().__init__(*args, **kwargs)

        self._client_name = settings.OIDC_BACKEND_CLIENT_NAME

        oauth = OAuth()
        oauth.register(self._client_name)
        self._oidc_client = getattr(oauth, self._client_name)

    def authorize_redirect(self, request, redirect_uri):

        return self._oidc_client.authorize_redirect(request, redirect_uri)

    def get_user_info(self, request):

        try:
            token = self._oidc_client.authorize_access_token(request)
            return self._oidc_client.parse_id_token(request, token)

        except OAuthError as e:
            LOG.error(f"Failed to retrieve user info: {e}")
