""" Views for the auth app. """

__author__ = "William Tucker"
__date__ = "2020-02-05"
__copyright__ = "Copyright 2020 United Kingdom Research and Innovation"
__license__ = "BSD - see LICENSE file in top-level directory"


import logging

from django.http import HttpResponse
from django.views.generic import View
from django.urls import reverse
from django.shortcuts import redirect
from user_agents import parse

from authenticate.oidc.client import OpenIDConnectClient
from authenticate.utils import is_authenticated


LOG = logging.getLogger(__name__)


class AuthView(View):
    """ View for authorizing an nginx_auth request.
    Response depends on the middleware used to intercept the request.
    """

    def get(self, request):
        """ HTTP GET request handler for this view. """

        if is_authenticated(request):
            return HttpResponse("Authorized", status=200)
        else:
            return HttpResponse("Unauthenticated", status=401)


class LoginView(View):
    """ View for handling OpenIDConnect authentication. """

    def __init__(self, *args, **kwargs):

        super().__init__(*args, **kwargs)
        self._client = OpenIDConnectClient()

    def get(self, request):
        """ HTTP GET request handler for this view. """

        if is_authenticated(request):
            return redirect(request.GET["next"])

        user_agent_string = request.META.get("HTTP_USER_AGENT")
        user_agent = parse(user_agent_string)

        if user_agent.browser.family == "Other":

            # Unrecognised Browser, send 401 response
            return HttpResponse("Browser not supported", status=401)

        else:

            # Direct user to OIDC server login
            return self._redirect(request)

    def _redirect(self, request):
        """ Redirects a request to the OIDC server for authentication. """

        redirect_uri = request.META.get("HTTP_REFERER")
        redirect_uri = request.build_absolute_uri(reverse("callback"))
        resource_uri = request.GET.get("next")
        redirect_uri = f"{redirect_uri}?next={resource_uri}"
        return self._client.authorize_redirect(request, redirect_uri)


class CallbackView(View):
    """ View for handling OpenIDConnect authentication callbacks. """

    def get(self, request):
        """ HTTP GET request handler for this view. """

        if is_authenticated(request):
            return redirect(request.GET["next"])
