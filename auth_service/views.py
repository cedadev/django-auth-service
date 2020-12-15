""" General service views not related to individual apps. """

__author__ = "William Tucker"
__date__ = "2020-12-15"
__copyright__ = "Copyright 2020 United Kingdom Research and Innovation"
__license__ = "BSD - see LICENSE file in top-level directory"


from django.http import HttpResponse
from django.views.generic import View


class HomeView(View):
    """ Simple view to confirm that the server is running. """

    def get(self, request):
        return HttpResponse("The auth service is running", status=200)
