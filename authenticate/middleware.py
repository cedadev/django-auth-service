""" General auth middleware. """

__author__ = "William Tucker"
__date__ = "2020-03-26"
__copyright__ = "Copyright 2020 United Kingdom Research and Innovation"
__license__ = "BSD - see LICENSE file in top-level package directory"


import logging

from django.contrib.auth import authenticate, login, get_user
from django.contrib.auth.models import User
from django.contrib.sessions.models import Session


LOG = logging.getLogger(__name__)


class AuthenticationMiddleware:
    """ Authentication middleware which relies on a request object only. """

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):

        # Login from custom backends does not persist in the request so a
        # workaround is used to grab the user, if available, from the session.
        # This is not an optimal solution.
        user = None
        backend = None
        session_key = request.session._session_key
        if session_key:

            session = Session.objects.get(session_key=session_key)
            session_data = session.get_decoded()
            user_id = session_data.get('_auth_user_id')
            backend = session_data.get('_auth_user_backend')
            if user_id:
                user = User.objects.get(id=user_id)

        # Attempt to authenticate the request with available middleware
        if not user:
            user = authenticate(request)

        if user:

            if not hasattr(user, "backend"):
                user.backend = backend

            request.user = user
            login(request, user)

        response = self.get_response(request)
        return response
