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

    def _authenticate(self, request):
        """ Checks for the presence of a valid account cookie in the request.
        Returns User associated with the token or None. """

        cookie_name = settings.ACCOUNT_COOKIE_NAME
        if cookie_name in request.COOKIES:
            try:
                _, userid = self._parse_cookie_value(
                    request.COOKIES[cookie_name])[:2]
                return userid

            except CookieParsingError:

                LOG.warning("Failed to parse cookie for request.")
                return None

        else:
            LOG.debug(f"Missing cookie '{cookie_name}'")

    @staticmethod
    def _parse_cookie_value(cookie_value, index=None):
        """Verifies the presence and validity of a secure paste cookie.
        If the cookie is present then the decrypted content is returned.
        
        :param cookie: An instance of SecureCookie.
        :param index: Index of a desired value from the cookie.
        :returns: The parsed cookie (a tuple) or the value at index.
        :raises: CookieParsingError
        """

        shared_secret = codecs.decode(
            settings.SECURITY_SHAREDSECRET.encode(), "base64")
        try:
            parsed_cookie_items = SecureCookie.parse_ticket(
                shared_secret,
                cookie_value,
                None,
                None
            )
            if index is not None:
                return parsed_cookie_items[index]
            else:
                return parsed_cookie_items

        except BadTicket as e:
            LOG.warning("Error decoding cookie.")
            raise CookieParsingError(e)
        except VerificationError as e:
            LOG.warning("Cookie signature verification error.")
            raise CookieParsingError(e)
        except IndexError:
            LOG.warning("Index not in cookie.")
            raise CookieParsingError(e)
