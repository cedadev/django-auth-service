""" URL configuration for the site. """

__author__ = "William Tucker"
__date__ = "2020-02-05"
__copyright__ = "Copyright 2020 United Kingdom Research and Innovation"
__license__ = "BSD - see LICENSE file in top-level package directory"


from django.urls import path

from authorize.views import VerifyView
from authenticate.views import LoginView, CallbackView


urlpatterns = [
    path("verify/", VerifyView.as_view(), name="verify"),
    path("login/", LoginView.as_view(), name="login"),
    path("login/callback/", CallbackView.as_view(), name="callback")
]
