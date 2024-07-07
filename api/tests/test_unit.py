from django.test import TestCase
from django.contrib.auth import get_user_model
from rest_framework_simplejwt.tokens import RefreshToken
from django.utils import timezone
from datetime import timedelta
from ..models import Organisation
from ..serializers import UserSerializer
from django.conf import settings
from ..utils import generate_token, get_user_from_token
import jwt


User = get_user_model()

class TokenGenerationTestCase(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(
            email='victor@gmail.com',
            password='password123',
            firstName='Victor',
            lastName='Ibor',
            id = 4
        )

    def test_token_expiration(self):
        token = generate_token(self.user)
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.JWT_ALGORITHM])

        # Check that the token expires at the correct time
        expected_expiration = timezone.now() + timedelta(minutes=settings.JWT_EXPIRATION_DELTA)
        self.assertAlmostEqual(payload['exp'], int(expected_expiration.timestamp()), delta=1)

    def test_user_details_in_token(self):
        token = generate_token(self.user)
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.JWT_ALGORITHM])

        # Check that correct user details are in the token
        self.assertEqual(str(payload['user_id']), str(self.user.userId))

        # Verify that we can get the user from the token
        retrieved_user = get_user_from_token(token)
        self.assertEqual(retrieved_user, self.user)


class OrganisationAccessTestCase(TestCase):
    def setUp(self):
        self.victor = User.objects.create_user(
            email='victor@gmail.com',
            password='password1234',
            firstName='Victor',
            lastName='Ibor',
            id = 10
        )
        self.daniel = User.objects.create_user(
            email='daniel@gmail.com',
            password='password1234',
            firstName='Daniel',
            lastName='Ibor',
            id = 5
        )
        self.org1 = Organisation.objects.create(name="Victor Ibor's Organisation", creator=self.victor)
        self.org2 = Organisation.objects.create(name="Daniel Ibor's Organisation", creator=self.daniel)
        self.org1.users.add(self.victor)
        self.org2.users.add(self.daniel)

    # USER SEE ONLY ORG..
    def test_user_can_only_see_own_organisations(self):
        victor_orgs = Organisation.objects.filter(users=self.victor)
        daniel_orgs = Organisation.objects.filter(users=self.daniel)

        self.assertIn(self.org1, victor_orgs)
        self.assertNotIn(self.org2, victor_orgs)
        self.assertIn(self.org2, daniel_orgs)
        self.assertNotIn(self.org1, daniel_orgs)