""" Views for the authorize app. """

__author__ = "William Tucker"
__date__ = "2020-12-10"
__copyright__ = "Copyright 2020 United Kingdom Research and Innovation"
__license__ = "BSD - see LICENSE file in top-level directory"


from django.http import HttpResponse
from django.views.generic import View


class VerifyView(View):
    """ View for checking the authorizing of a request.
    The response will vary depending on the middleware used to intercept the
    request and the resource being requested (if any).
    """

    def get(self, request):
        """ HTTP GET request handler for this view. """

        # If this line is reached, we can assume that the request has passed
        # all configured authorization checks.
        return HttpResponse("Authorized", status=200)
