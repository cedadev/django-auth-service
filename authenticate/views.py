""" Views for the authenticate app. """

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
from authenticate.utils import is_authenticated, get_requested_resource, \
    get_stored_resource, save_resource


LOG = logging.getLogger(__name__)


class LoginView(View):
    """ View for handling OpenIDConnect authentication. """

    def __init__(self, *args, **kwargs):

        super().__init__(*args, **kwargs)
        self._client = OpenIDConnectClient()

    def get(self, request):
        """ HTTP GET request handler for this view. """

        # Get the URL of the requested resource
        next_url = get_requested_resource(request)
        if is_authenticated(request):
            # Send the logged in user to their requested URL
            return redirect(next_url)

        else:
            # Save the resource URL in the session for the login callback
            save_resource(request, next_url)

        user_agent_string = request.META.get("HTTP_USER_AGENT", "")
        user_agent = parse(user_agent_string)

        if user_agent.browser.family == "Other":

            # Unrecognised Browser, send 401 response
            return HttpResponse("Browser not supported", status=401)

        else:

            # Direct user to OIDC server login
            return self._redirect(request)

    def _redirect(self, request):
        """ Redirects a request to the OIDC server for authentication. """

        redirect_uri = request.build_absolute_uri(reverse("callback"))
        return self._client.authorize_redirect(request, redirect_uri)


class CallbackView(View):
    """ View for handling OpenIDConnect authentication callbacks. """

    def get(self, request):
        """ HTTP GET request handler for this view. """

        resource_uri = get_stored_resource(request)
        LOG.debug(f"Attempting redirect to resource URI '{resource_uri}'")

        if is_authenticated(request):
            return redirect(resource_uri)

        # Failed to authenticate on callback, return error response
        return HttpResponse("Failed to authenticate", status=401)
