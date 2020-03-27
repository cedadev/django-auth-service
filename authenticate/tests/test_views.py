""" Test module for views. """

__author__ = "William Tucker"
__date__ = "2020-03-27"
__copyright__ = "Copyright 2020 United Kingdom Research and Innovation"
__license__ = "BSD - see LICENSE file in top-level package directory"


from django.urls import reverse
from django.test import TestCase

from authenticate.oauth2.backends import BearerTokenBackend


class AuthViewTests(TestCase):

    def test_unauthenticated(self):
        """ Test without authentication. """

        url = reverse("auth")
        response = self.client.get(url)
        self.assertEqual(response.status_code, 401)

    def test_bad_token(self):
        """ Test with a useless bearer token in the request. """

        url = reverse("auth")
        HEADERS = {
            BearerTokenBackend.AUTHORIZATION_HEADER: "bad token"
        }
        response = self.client.get(url, extra=HEADERS)
        self.assertEqual(response.status_code, 401)
