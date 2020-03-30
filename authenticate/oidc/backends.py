""" Authentication backends for OpenID Connect. """

__author__ = "William Tucker"
__date__ = "2020-03-26"
__copyright__ = "Copyright 2020 United Kingdom Research and Innovation"
__license__ = "BSD - see LICENSE file in top-level package directory"


import logging

from authlib.client.errors import MismatchingStateError
from authlib.common.errors import AuthlibBaseError
from django.conf import settings
from django.contrib.auth.backends import BaseBackend
from django.contrib.auth.models import User

from authenticate.oidc.client import OpenIDConnectClient


LOG = logging.getLogger(__name__)


class OpenIDConnectBackend(BaseBackend):
    """ View for handling OpenIDConnect authentication callbacks. """

    def __init__(self, *args, **kwargs):

        super().__init__(*args, **kwargs)
        self._client = OpenIDConnectClient()

    def authenticate(self, request, **kwargs):
        """ Checks for OpenID Connect login credentials in the request.
        Returns a User object or None. """

        try:
            userinfo = self._client.get_user_info(request)

            # Store openid in session
            # TODO: get openid from user info
            request.session["openid"] = settings.TMP_TEST_OPENID

        except MismatchingStateError:
            return None

        except AuthlibBaseError as e:

            LOG.exception("Failed to parse OIDC credentials for request.")
            return None

        username = userinfo["preferred_username"]
        user, _ = User.objects.get_or_create(username=username)
        return user
