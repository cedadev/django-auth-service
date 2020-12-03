""" Helper classes for handling SAML queries. """

__author__ = "William Tucker"
__date__ = "2020-02-05"
__copyright__ = "Copyright 2020 United Kingdom Research and Innovation"
__license__ = "BSD - see LICENSE file in top-level directory"


from datetime import datetime
from uuid import uuid4

from ndg.saml.saml2.core import SAMLVersion, Issuer, Subject, NameID, Action


ISSUER = '/O=STFC/OU=SPBU/CN=test'
NAMEID_FORMAT = 'urn:esg:openid'

ATTRIBUTE_NAME_FORMAT = 'http://www.w3.org/2001/XMLSchema#string'


class QueryBuilder(object):
    """ Helper class for building SAML queries. """

    @staticmethod
    def build_query(query_class, user_identifier=None):
        """ Builds a SAML query. """

        query = query_class()

        query.version = SAMLVersion(SAMLVersion.VERSION_20)
        query.id = str(uuid4())
        query.issueInstant = datetime.utcnow()

        query.issuer = Issuer()
        query.issuer.format = Issuer.X509_SUBJECT
        query.issuer.value = ISSUER

        query.subject = Subject()
        query.subject.nameID = NameID()
        query.subject.nameID.format = NAMEID_FORMAT

        action = Action()
        action.value = Action.READ_ACTION
        query.actions.append(action)

        if user_identifier:
            query.subject.nameID.value = user_identifier

        return query
