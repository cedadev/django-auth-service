""" Authentication middleware for OpenID Connect. """

__author__ = "William Tucker"
__date__ = "2020-03-26"
__copyright__ = "Copyright 2020 United Kingdom Research and Innovation"
__license__ = "BSD - see LICENSE file in top-level package directory"


import logging

from authlib.integrations.base_client.errors import MismatchingStateError
from authlib.common.errors import AuthlibBaseError

from authenticate.middleware import AuthenticationMiddleware
from authenticate.oidc.client import OpenIDConnectClient


LOG = logging.getLogger(__name__)


class OpenIDConnectAuthenticationMiddleware(AuthenticationMiddleware):
    """ View for handling OpenIDConnect authentication callbacks. """

    TOKEN_IDENTIFIER_KEY = "preferred_username"

    def __init__(self, *args, **kwargs):

        super().__init__(*args, **kwargs)
        self._client = OpenIDConnectClient()

    def _authenticate(self, request):
        """ Checks for OpenID Connect login credentials in the request.
        Returns a User object or None. """

        try:
            user_info = self._client.get_user_info(request)

        except MismatchingStateError:

            LOG.warn("Mismatching state while parsing OIDC credentials.")
            return None

        except AuthlibBaseError as e:

            LOG.exception("Error parsing OIDC credentials.")
            return None

        if user_info:
            return user_info.get(self.TOKEN_IDENTIFIER_KEY)
