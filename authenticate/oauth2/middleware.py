""" Authentication middleware for OAuth2. """

__author__ = "William Tucker"
__date__ = "2020-03-25"
__copyright__ = "Copyright 2020 United Kingdom Research and Innovation"
__license__ = "BSD - see LICENSE file in top-level package directory"


import logging

from authenticate.middleware import AuthenticationMiddleware
from authenticate.oauth2.token import parse_access_token
from authenticate.oauth2.exceptions import BadAccessTokenError


LOG = logging.getLogger(__name__)


class BearerTokenAuthenticationMiddleware(AuthenticationMiddleware):

    AUTHORIZATION_HEADER_KEY = "HTTP_AUTHORIZATION"

    USERNAME_KEY = "preferred_username"
    GROUPS_KEY = "groups"

    def _parse_token_data(self, token_data):
        """ Parses an OIDC user info dictionary for relevant info. """

        return {
            "username": token_data.get(self.USERNAME_KEY),
            "groups": token_data.get(self.GROUPS_KEY),
        }

    def _authenticate(self, request):
        """ Checks for OAuth2 access token in the request.
        Returns User associated with the token or None. """

        # Try to retrieve the user id with an access token if one is present
        authorization_header = request.META.get(self.AUTHORIZATION_HEADER_KEY)
        if authorization_header and authorization_header.startswith("Bearer"):

            access_token = authorization_header[6:].strip()
            LOG.debug(f"Found access token: {access_token}")

            # Attempt to retrieve OpenID from OAuth2 access token
            token_data = None
            try:
                token_data = parse_access_token(access_token)

            except BadAccessTokenError:

                LOG.warn(f"Failed to parse access token for request.")
                return None

            if token_data:
                return self._parse_token_data(token_data)
