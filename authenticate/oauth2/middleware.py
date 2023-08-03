""" Authentication middleware for OAuth2. """

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
    """ Middleware for OAuth2 Bearer Token authentication. """

    AUTHORIZATION_HEADER_KEY = "HTTP_AUTHORIZATION"

    USERNAME_KEY = "preferred_username"
    GROUPS_KEY = "groups"
    OPENID_KEY = "openid"

    def _parse_token_data(self, token_data):
        """ Parses an OIDC user info dictionary for relevant info. """

        username_key = getattr(settings, "OAUTH2_USERNAME_KEY",
            self.USERNAME_KEY)
        groups_key = getattr(settings, "OAUTH2_GROUPS_KEY",
            self.GROUPS_KEY)
        openid_key = getattr(settings, "OAUTH2_OPENID_KEY",
            self.OPENID_KEY)

        LOG.debug((f"Checking token for username key '{username_key}'"
            f", groups key '{groups_key}' and openid key '{openid_key}."))

        username = token_data.get(username_key)
        groups = token_data.get(groups_key)
        openid = token_data.get(openid_key)
        if not openid:
            openid = username

        return {
            "username": username,
            "groups": groups,
            "openid": openid,
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
