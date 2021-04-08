""" OPA authorization middleware. """

__author__ = "William Tucker"
__date__ = "2021-01-18"
__copyright__ = "Copyright 2020 United Kingdom Research and Innovation"
__license__ = "BSD - see LICENSE file in top-level package directory"


import logging

from django.conf import settings
from opa_client.opa import OpaClient

from authorize.middleware import AuthorizationMiddleware
from authenticate.utils import get_user
from .exceptions import OPAAuthorizationError


LOG = logging.getLogger(__name__)


class OPAAuthorizationMiddleware(AuthorizationMiddleware):
    """ Middleware for handling authorization via an OPA server. """

    def __init__(self, *args):
        super().__init__(*args)

        opa_settings = getattr(settings, "OPA_SERVER", {})
        self._client = OpaClient(**opa_settings)
        self._package_path = opa_settings.get("package_path")
        self._rule_name = opa_settings.get("rule_name")

    def _is_authorized(self, request, resource):

        user = get_user(request)

        action_map = {
            "GET": "Read",
            "POST": "Write",
        }
        action = action_map[request.method]

        LOG.debug(f"Querying OPA authz server for resource: {resource}")

        subject = None
        if user:
            subject = {
                "user": user.username,
                "groups": user.groups
            }

        check_data = {
            "input": {
                "resource": resource,
                "subject": subject,
                "action": action
            }
        }

        # Check authorization for resource
        is_authorized = False
        try:
            permission = self._client.check_policy_rule(
                input_data=check_data,
                package_path=self._package_path,
                rule_name=self._rule_name
            )
            is_authorized = permission.get("result", False)

        except OPAAuthorizationError as e:

            username = user.username if user else "anonymous"
            LOG.info(f"Authorization failed for user: {username}")
            raise e

        return is_authorized
