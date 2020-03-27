""" URL configuration for the auth app. """

__author__ = "William Tucker"
__date__ = "2020-02-05"
__copyright__ = "Copyright 2020 United Kingdom Research and Innovation"
__license__ = "BSD - see LICENSE file in top-level directory"


from django.urls import path

from authenticate.views import AuthView, CallbackView, LoginView


urlpatterns = [
    path("auth/", AuthView.as_view(), name="auth"),
    path("login/callback/", CallbackView.as_view(), name="callback"),
    path("login/", LoginView.as_view(), name="login")
]
