""" General auth middleware. """

__author__ = "William Tucker"
__date__ = "2020-03-26"
__copyright__ = "Copyright 2020 United Kingdom Research and Innovation"
__license__ = "BSD - see LICENSE file in top-level package directory"


import logging

from django.conf import settings

from authorize.middleware import AuthorizationMiddleware
from authorize.saml import SAMLAuthorizer
from authorize.saml.exceptions import SamlAuthorizationError
from authenticate.utils import get_user


LOG = logging.getLogger(__name__)


class SAMLAuthorizationMiddleware(AuthorizationMiddleware):
    """ Middleware for handling authorization via a SAML query. """

    def __init__(self, *args):
        super().__init__(*args)

        self._saml_authorizer = SAMLAuthorizer(
            service_uri=settings.AUTHORIZATION_SERVICE_URL
        )

    def _is_authorized(self, request, resource):

        user = get_user(request)

        LOG.debug(f"Querying authorization for resource: {resource}")

        # Check authorization for resource
        is_authorized = False
        try:

            # Get an authorization decision from the authorization service
            is_authorized = self._saml_authorizer.is_authorized(
                resource=resource,
                user_identifier=user.username,
                groups = user.groups
            )

        except SamlAuthorizationError as e:

            LOG.info(f"Authorization failed for user: {user.username}")
            raise e

        return is_authorized
