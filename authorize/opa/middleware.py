""" OPA authorization middleware. """

__author__ = "William Tucker"
__date__ = "2021-01-18"
__copyright__ = "Copyright 2020 United Kingdom Research and Innovation"
__license__ = "BSD - see LICENSE file in top-level package directory"


import logging

from django.conf import settings
from opa_client.opa import OpaClient

from authorize.middleware import AuthorizationMiddleware
from authenticate.utils import get_user_identifier
from .exceptions import OPAAuthorizationError


LOG = logging.getLogger(__name__)


class OPAAuthorizationMiddleware(AuthorizationMiddleware):
    """ Middleware for handling authorization via an OPA server. """

    def __init__(self, *args):
        super().__init__(*args)

        opa_settings = getattr(settings, "OPA_SERVER", {})
        self._client = OpaClient(**opa_settings)

    def _is_authorized(self, request, resource):

        user_identifier = get_user_identifier(request)
        user_groups = [] # TODO

        action = None
        if request.method == "GET":
            action = "Read"
        elif request.method == "POST":
            action = "Write"

        LOG.debug(f"Querying OPA authz server for resource: {resource}")

        check_data = {
            "input": {
                "resource": resource,
                "subject": {
                    "user": user_identifier,
                    "groups": user_groups
                },
                "action": action
            }
        }

        # Check authorization for resource
        is_authorized = False
        try:
            permission = self._client.check_permission(input_data=check_data, policy_name="policies/esgf_policies_local.rego", rule_name="allow")
            is_authorized = permission.get("result", False)

        except OPAAuthorizationError as e:

            LOG.info(f"Authorization failed for user: {user_identifier}")
            raise e

        return is_authorized
