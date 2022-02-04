""" Modules for. """

__author__ = "William Tucker"
__date__ = "2020-02-14"
__copyright__ = "Copyright 2020 United Kingdom Research and Innovation"
__license__ = "BSD - see LICENSE file in top-level package directory"


import logging

from ndg.saml.saml2.binding.soap.client.requestbase import RequestResponseError
from ndg.saml.saml2.binding.soap.client.authzdecisionquery import \
    AuthzDecisionQuerySslSOAPBinding
from ndg.saml.saml2.core import AuthzDecisionQuery, DecisionType
from OpenSSL.SSL import Error as OpenSSLError

from authorize.saml.query_builder import QueryBuilder
from authorize.saml.exceptions import SamlAuthorizationError


LOG = logging.getLogger(__name__)

CLOCK_SKEW_TOLERANCE = 1000


class SAMLAuthorizer:
    """ Sends and parses SAML Authorization decision queries. """

    def __init__(self, service_uri):

        self.service_uri = service_uri

        client_binding = AuthzDecisionQuerySslSOAPBinding()
        client_binding.clockSkewTolerance = CLOCK_SKEW_TOLERANCE
        self.client_binding = client_binding

    def _parse_authorization_response(self, response):
        """ Parse an authorization decision response. """

        decisions = []
        for assertion in response.assertions:
            for statement in assertion.authzDecisionStatements:
                decisions.append(statement.decision.value)

        return decisions[0]

    def is_authorized(self, resource, user_identifier, groups=None):
        """ Get an authorization decision for a resource. """

        if not resource:
            return True

        query = QueryBuilder.build_query(AuthzDecisionQuery, user_identifier)
        query.resource = resource

        decision = None
        try:

            response = self.client_binding.send(query, uri=self.service_uri)
            decision = self._parse_authorization_response(response)

        except (RequestResponseError, OpenSSLError) as e:

            LOG.error(f"SOAP query error for {user_identifier}: {e}")
            raise SamlAuthorizationError("Error when querying the \
                authorization service.")

        if decision == DecisionType.INDETERMINATE:
            raise SamlAuthorizationError("Received indeterminate decision"
                " from the authorization service.")

        return decision == DecisionType.PERMIT
