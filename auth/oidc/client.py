""" OpenID Connect client utilities. """

__author__ = "William Tucker"
__date__ = "2020-03-26"
__copyright__ = "Copyright 2020 United Kingdom Research and Innovation"
__license__ = "BSD - see LICENSE file in top-level package directory"


from authlib.integrations.django_client import OAuth


class OpenIDConnectClient:
    """ A simple OpenIDConnect client wrapper. """

    @property
    def oidc_client(self):
        return self._oidc_client

    def __init__(self, *args, **kwargs):

        super().__init__(*args, **kwargs)

        oauth = OAuth()
        oauth.register("ceda")
        self._oidc_client = oauth.ceda

    def authorize_redirect(self, request):

        redirect_uri = request.META.get("HTTP_REFERER")
        return self._oidc_client.authorize_redirect(request, redirect_uri)

    def get_user_info(self, request):

        token = self._oidc_client.authorize_access_token(request)
        return self._oidc_client.parse_id_token(request, token)
