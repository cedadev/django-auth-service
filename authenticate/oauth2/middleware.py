""" Authentication backends for OAuth2. """

__author__ = "William Tucker"
__date__ = "2020-03-25"
__copyright__ = "Copyright 2020 United Kingdom Research and Innovation"
__license__ = "BSD - see LICENSE file in top-level package directory"


import logging

from django.conf import settings

from authenticate.middleware import AuthenticationMiddleware
from authenticate.oauth2.token import parse_access_token
from authenticate.oauth2.exceptions import BadAccessTokenError


LOG = logging.getLogger(__name__)


class BearerTokenAuthenticationMiddleware(AuthenticationMiddleware):

    AUTHORIZATION_HEADER_KEY = "HTTP_AUTHORIZATION"
    TOKEN_IDENTIFIER_KEY = "username"

    def _authenticate(self, request):
        """ Checks for OAuth2 access token in the request.
        Returns User associated with the token or None. """

        # Try to retrieve openid with an access token if one is present
        authorization_header = request.META.get(self.AUTHORIZATION_HEADER_KEY)
        if authorization_header and authorization_header.startswith("Bearer"):

            access_token = authorization_header[6:].strip()
            LOG.debug(f"Found access token: {access_token}")

            # Attempt to retrieve OpenID from OAuth2 access token
            user_data = None
            try:
                user_data = parse_access_token(access_token)

            except BadAccessTokenError:

                LOG.warn("Failed to parse access token for request.")
                return None

            if user_data:
                return user_data.get(self.TOKEN_IDENTIFIER_KEY)
