
import unittest
from catharsis.disjoint_sets import *
from catharsis.typedefs import *
import json

class TestStringMethods(unittest.TestCase):

    def test_user_principal_can_be_serialized_and_deserialized(self):
        user = Principal(
            id='1-2-3-4',
            displayName='John Doe',
            accountEnabled=True,
            raw=None,
            usertype=PrincipalType.User,
            userDetails=UserPrincipalDetails(upn='john.doe@domain.com')
        )

        serialized = json.dumps(user, cls=CatharsisEncoder)
        deserialized = json.loads(serialized, object_hook=catharsis_decoder)

        for attribute in ['id', 'displayName', 'accountEnabled', 'raw', 'usertype', 'userDetails']:
            self.assertEqual(getattr(user, attribute), getattr(deserialized, attribute))

