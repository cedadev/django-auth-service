""" URL configuration for the authorizer app. """

__author__ = "William Tucker"
__date__ = "2020-02-05"
__copyright__ = "Copyright 2020 United Kingdom Research and Innovation"
__license__ = "BSD - see LICENSE file in top-level directory"


from django.urls import path

from authorizer.views import AuthorizeView, OidcAuthenticateView


urlpatterns = [
    path("authorize/", AuthorizeView.as_view(), name="authorize"),
    path("login/", OidcAuthenticateView.as_view(), name="login"),
]
