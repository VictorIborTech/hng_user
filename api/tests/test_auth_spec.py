from django.test import TestCase
from django.urls import reverse
from rest_framework.test import APIClient
from rest_framework import status
from ..models import User, Organisation

class AuthEndToEndTestCase(TestCase):
    def setUp(self):
        self.client = APIClient()
        self.register_url = reverse('register')
        self.login_url = reverse('login')

    def test_register_user_with_default_organisation(self):
        data = {
            "firstName": "Victor",
            "lastName": "Ibor",
            "email": "victor@gmail.com",
            "password": "password1234"
        }
        response = self.client.post(self.register_url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertIn('access', response.data['data'])
        self.assertEqual(response.data['data']['user']['firstName'], 'Victor')
        self.assertEqual(response.data['data']['user']['lastName'], 'Ibor')
        self.assertEqual(response.data['data']['user']['email'], 'victor@gmail.com')


        # Verify default organisation
        user = User.objects.get(email='victor@gmail.com')
        org = Organisation.objects.get(users=user)
        self.assertEqual(org.name, "Victor's Organisation")



    def test_user_login_success(self):
        # First register a user to login, If not it wont work
        register_data = {
            "firstName": "Victor",
            "lastName": "Ibor",
            "email": "victor@gmail.com",
            "password": "password1234"
        }
        self.client.post(self.register_url, register_data, format='json')

        # Now try to log in
        login_data = {
            "email": "victor@gmail.com",
            "password": "password1234"
        }
        response = self.client.post(self.login_url, login_data, format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('access', response.data['data'])
        self.assertEqual(response.data['data']['user']['email'], 'victor@gmail.com')

    def test_user_login_failure(self):
        login_data = {
            "email": "nonexistent@gmail.com",
            "password": "wrong12345"
        }
        response = self.client.post(self.login_url, login_data, format='json')
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_registration_missing_fields(self):
        data = {
            "firstName": "Victor",
            "lastName": "Ibor",
            # Missing email and password for testing purpose to see outcome
        }
        response = self.client.post(self.register_url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_422_UNPROCESSABLE_ENTITY)
        self.assertIn('email', response.data['errors'])
        self.assertIn('password', response.data['errors'])

    def test_registration_duplicate_email(self):
        data = {
            "firstName": "Victor",
            "lastName": "Ibor",
            "email": "victor@gmail.com",
            "password": "password1234"
        }
        # Register first user
        self.client.post(self.register_url, data, format='json')

        # Try to register second user with same email
        response = self.client.post(self.register_url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_422_UNPROCESSABLE_ENTITY)
        self.assertIn('email', response.data['errors'])