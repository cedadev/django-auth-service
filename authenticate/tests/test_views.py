""" Test module for views. """

__author__ = "William Tucker"
__date__ = "2020-03-27"
__copyright__ = "Copyright 2020 United Kingdom Research and Innovation"
__license__ = "BSD - see LICENSE file in top-level package directory"


from django.urls import reverse
from django.test import TestCase

from authenticate.oauth2.middleware import BearerTokenAuthenticationMiddleware


class VerifyViewTests(TestCase):

    def test_unauthenticated(self):
        """ Test without authentication. """

        url = reverse("verify")
        response = self.client.get(url)
        self.assertEqual(response.status_code, 401)

    def test_bad_token(self):
        """ Test with a useless bearer token in the request. """

        url = reverse("verify")
        headers = {
            BearerTokenAuthenticationMiddleware.AUTHORIZATION_HEADER_KEY: \
                "invalid token string"
        }
        response = self.client.get(url, **headers)
        self.assertEqual(response.status_code, 401)


class LoginViewTests(TestCase):

    def test_unknown_user_agent(self):
        """ Test login with an unknown user agent in the request header. """

        url = reverse("login")
        response = self.client.get(url)
        self.assertEqual(response.status_code, 401)

    def test_known_user_agent(self):
        """ Test with a standard browser user agent in the request header. """

        url = reverse("login")
        headers = {
            "HTTP_USER_AGENT": ("Mozilla/5.0 (Windows NT 6.1; Win64; x64;"
                                " rv:47.0) Gecko/20100101 Firefox/47.0")
        }
        response = self.client.get(url, **headers)
        self.assertEqual(response.status_code, 302)


class CallbackViewTests(TestCase):

    def test_unauthenticated(self):
        """ Test without authentication. """

        url = reverse("callback")
        response = self.client.get(url)
        self.assertEqual(response.status_code, 401)
