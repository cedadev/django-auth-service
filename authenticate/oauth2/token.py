""" OAuth2 utility functions. """

__author__ = "William Tucker"
__date__ = "2020-02-14"
__copyright__ = "Copyright 2020 United Kingdom Research and Innovation"
__license__ = "BSD - see LICENSE file in top-level package directory"


import logging
import json
import requests

from django.conf import settings

from authenticate.oauth2.exceptions import BadAccessTokenError


LOG = logging.getLogger(__name__)


def parse_access_token(access_token):
    """ Checks an access token against a token introspection endpoint and
    returns data associated with it.
    """

    headers = {
        "content-type": "application/x-www-form-urlencoded",
        "cache-control": "no-cache",
    }
    payload = (
        f"client_id={settings.OAUTH_CLIENT_ID}"
        f"&client_secret={settings.OAUTH_CLIENT_SECRET}"
        f"&token={access_token}"
    )

    response = requests.request(
        "POST",
        settings.OAUTH_TOKEN_INTROSPECT_URL,
        data=payload,
        headers=headers
    )
    user_data = json.loads(response.text)

    if response.status_code == 200:

        if not user_data["active"]:
            raise BadAccessTokenError

        return user_data
