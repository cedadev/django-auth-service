""" Authentication backends for OAuth2. """

__author__ = "William Tucker"
__date__ = "2020-03-25"
__copyright__ = "Copyright 2020 United Kingdom Research and Innovation"
__license__ = "BSD - see LICENSE file in top-level package directory"


import logging

from django.conf import settings
from django.contrib.auth.backends import BaseBackend
from django.contrib.auth.models import User

from authenticate.oauth2.token import parse_access_token
from authenticate.oauth2.exceptions import BadAccessTokenError


LOG = logging.getLogger(__name__)


class BearerTokenBackend(BaseBackend):

    AUTHORIZATION_HEADER = "HTTP_AUTHORIZATION"

    def authenticate(self, request, **kwargs):
        """ Checks for OAuth2 access token in the request.
        Returns User associated with the token or None. """

        if request.user.is_authenticated:
            return None

        # Try to retrieve openid with an access token if one is present
        authorization_header = request.META.get(self.AUTHORIZATION_HEADER)
        if authorization_header and authorization_header.startswith("Bearer"):

            access_token = authorization_header.strip("Bearer").strip()
            LOG.debug(f"Found access token: {access_token}")

            # Attempt to retrieve OpenID from OAuth2 access token
            user_data = None
            try:
                user_data = parse_access_token(access_token)

            except BadAccessTokenError:

                LOG.warn("Failed to parse access token for request.")
                return None

            user, _ = User.objects.get_or_create(username=user_data["username"])

            if user_data:

                # Store openid in session
                # TODO: OpenID should be retrieved from the token
                request.session["openid"] = settings.TMP_TEST_OPENID

            return user
