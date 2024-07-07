import jwt
from datetime import datetime, timedelta
from django.conf import settings
from rest_framework.views import exception_handler
from rest_framework.response import Response
from django.contrib.auth import get_user_model

def generate_token(user):
    payload = {
        'user_id': user.id,
        'exp': datetime.utcnow() + timedelta(minutes=settings.SIMPLE_JWT['ACCESS_TOKEN_LIFETIME'].total_seconds() // 60)
    }
    return jwt.encode(payload, settings.SECRET_KEY, algorithm='HS256')

def get_user_from_token(token):
    
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=['HS256'])
        User = get_user_model()
        return User.objects.get(id=payload['user_id'])
    except jwt.ExpiredSignatureError:
        raise ValueError('Token has expired')
    except jwt.InvalidTokenError:
        raise ValueError('Invalid token')
    except User.DoesNotExist:
        
        return None


class JWTAuthentication:
    def authenticate(self, request):
        auth_header = request.META.get('HTTP_AUTHORIZATION')
        if not auth_header:
            return None

        try:
            token = auth_header.split()[1]
            user = get_user_from_token(token)
            return (user, token)
        except (IndexError, ValueError):
            return None

def custom_exception_handler(exc, context):
    response = exception_handler(exc, context)

    if response is not None and response.status_code == 400:
        errors = []
        for field, error_list in response.data.items():
            for error in error_list:
                errors.append({
                    "field": field,
                    "message": str(error)
                })
        response.data = {"errors": errors}
        response.status_code = 422

    return response
# ... rest of the file remains the same