""" Authentication backends for OpenID Connect. """

__author__ = "William Tucker"
__date__ = "2020-03-26"
__copyright__ = "Copyright 2020 United Kingdom Research and Innovation"
__license__ = "BSD - see LICENSE file in top-level package directory"


import logging

from authlib.integrations._client.errors import MismatchingStateError
from django.conf import settings
from django.contrib.auth.backends import BaseBackend
from django.contrib.auth.models import User

from auth.oidc.client import OpenIDConnectClient


LOG = logging.getLogger(__name__)


class OpenIDConnectBackend(BaseBackend):
    """ View for handling OpenIDConnect authentication callbacks. """

    def __init__(self, *args, **kwargs):

        super().__init__(*args, **kwargs)
        self.client = OpenIDConnectClient()

    def authenticate(self, request, **kwargs):
        """ Checks for OpenID Connect login credentials in the request.
        Returns a User object or None. """

        if request.user.is_authenticated:
            return None

        try:
            userinfo = self.client.get_user_info(request)

            # Store openid in session
            # TODO: get openid from user info
            request.session["openid"] = settings.TMP_TEST_OPENID

        except MismatchingStateError:

            LOG.warn("Failed to parse OIDC credentials for request.")
            return None

        username = userinfo["preferred_username"]
        user, _ = User.objects.get_or_create(username=username)
        return user
