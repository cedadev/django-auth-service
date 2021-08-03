""" Middleware for encrypted cookie authentication. """

__author__ = "William Tucker"
__date__ = "2020-07-16"
__copyright__ = "Copyright 2020 United Kingdom Research and Innovation"
__license__ = "BSD - see LICENSE file in top-level package directory"


import codecs
import logging

from crypto_cookie.exceptions import BadTicket
from crypto_cookie.auth_tkt import SecureCookie
from crypto_cookie.signature import VerificationError
from django.conf import settings

from authenticate.middleware import AuthenticationMiddleware
from authenticate.cookie.exceptions import CookieParsingError


LOG = logging.getLogger(__name__)


class CookieAuthenticationMiddleware(AuthenticationMiddleware):
    """ Middleware for authentication using an encrypted cookie. """

    USERNAME_INDEX = 1
    OPENID_INDEX = 1

    def _parse_cookies(self, account_cookie_value, openid_cookie_value):
        """ Parses user information from an encrypted cookie """

        shared_secret = codecs.decode(
            settings.SECURITY_SHAREDSECRET.encode(), "base64")
        try:
            username = SecureCookie.parse_ticket(
                shared_secret,
                account_cookie_value,
                None,
                None
            )[self.USERNAME_INDEX]
            openid = SecureCookie.parse_ticket(
                shared_secret,
                openid_cookie_value,
                None,
                None
            )[self.OPENID_INDEX]

            return {
                "username": username,
                "groups": [],
                "openid": openid,
            }

        except BadTicket as e:
            LOG.warning("Error decoding cookie.")
            raise CookieParsingError(e)
        except VerificationError as e:
            LOG.warning("Cookie signature verification error.")
            raise CookieParsingError(e)
        except IndexError as e:
            LOG.warning("Index not in cookie.")
            raise CookieParsingError(e)

    def _authenticate(self, request):
        """ Checks for the presence of a valid account cookie in the request.
        Returns User associated with the token or None. """

        cookie_names = [
            settings.ACCOUNT_COOKIE_NAME, settings.OPENID_COOKIE_NAME]
        cookie_values = []

        for cookie_name in cookie_names:

            if cookie_name in request.COOKIES:
                cookie_values.append(request.COOKIES[cookie_name])
            else:
                LOG.debug(f"Missing cookie '{cookie_name}'")

        try:
            return self._parse_cookies(*cookie_values)

        except CookieParsingError:

            LOG.warning("Failed to parse cookie for request.")
            return None
